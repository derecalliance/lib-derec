// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Opaque [`DeRecProtocolHandle`] + FFI entry points. Each
//! `derec_protocol_*` function is the FFI counterpart of a method on
//! [`crate::protocol::DeRecProtocol`], organized into submodules by
//! domain: [`config`] for runtime-mutable settings, [`pairing`] for
//! contact / fingerprint helpers, and [`flow`] for the
//! `start` / `process` / `accept` / `reject` event-loop surface.

use std::collections::HashMap;
use std::time::Duration;

use prost::Message as _;

use crate::extensions::communication_info::CommunicationInfoExt as _;
use crate::interop::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_INVALID_ENUM, DEREC_CODE_FFI_NULL_PTR, DeRecError,
    ffi_error, success,
};
use crate::interop::ffi::protocol::stores::{
    ChannelStoreCallbacks, DotnetChannelStore, DotnetSecretStore, DotnetShareStore,
    DotnetStateStore, DotnetTransport, DotnetUserSecretStore, SecretStoreCallbacks,
    ShareStoreCallbacks, StateStoreCallbacks, TransportCallbacks, UserSecretStoreCallbacks,
};
use crate::protocol::DeRecProtocolBuilder;

mod config;
mod flow;
mod pairing;

pub(super) type Protocol = crate::protocol::DeRecProtocol<
    DotnetChannelStore,
    DotnetShareStore,
    DotnetSecretStore,
    DotnetUserSecretStore,
    DotnetStateStore,
    DotnetTransport,
>;

/// Opaque handle returned by [`derec_protocol_new`] and consumed by
/// every other entry point in this module. Holds the protocol instance + the
/// per-handle tokio runtime used to drive the async core synchronously.
///
/// The `inner` protocol is wrapped in [`std::sync::Mutex`] so concurrent
/// FFI calls from different host threads (.NET worker pool, Node.js
/// worker_threads, etc.) are safe by construction. Each entry point
/// locks the mutex for the duration of its call, serializing access to
/// the protocol state — no `&mut DeRecProtocolHandle` is ever
/// materialized, so aliased `&mut` references (which would be immediate
/// undefined behavior) cannot arise even under contention. The tokio
/// `Runtime` itself is `Sync` and accepts `&self` `block_on`, but
/// holding the protocol lock across `block_on` also serializes runtime
/// invocations on the current-thread executor.
pub struct DeRecProtocolHandle {
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) inner: std::sync::Mutex<Protocol>,
}

impl DeRecProtocolHandle {
    /// Lock the inner protocol for exclusive access. Recovers from a
    /// poisoned mutex (a panic in an earlier entry point) by extracting
    /// the inner state — panicking across the FFI boundary is itself
    /// undefined behavior, so the poison-tolerant pattern is the right
    /// default here.
    pub(super) fn lock_inner(&self) -> std::sync::MutexGuard<'_, Protocol> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Validate a `(uri, protocol)` pair at the FFI boundary using the
/// library-level [`crate::transport::validate`] rules. Errors are
/// surfaced through [`crate::interop::ffi::error::from_lib_error`] so the
/// host sees the same `DEREC_CODE_TRANSPORT_INVALID` regardless of
/// whether the validator fired from the FFI entry point or from a
/// wire-decode path inside the protocol.
pub(super) fn validate_transport(
    uri: &str,
    protocol: i32,
) -> Result<crate::transport::TransportProtocol, DeRecError> {
    let proto = derec_proto::TransportProtocol {
        uri: uri.to_owned(),
        protocol,
    };
    // `TryFrom` runs both the enum-discriminant check and the URI
    // structural validation; a single `?` covers both.
    crate::transport::TransportProtocol::try_from(&proto)
        .map_err(|e| crate::interop::ffi::error::from_lib_error(crate::Error::Transport(e)))
}

/// Result type for [`derec_protocol_new`].
#[repr(C)]
pub struct DeRecProtocolNewResult {
    pub error: DeRecError,
    /// On success, the opaque handle. On error, null.
    pub handle: *mut DeRecProtocolHandle,
}

impl From<DeRecError> for DeRecProtocolNewResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            handle: std::ptr::null_mut(),
        }
    }
}

/// Per-flow auto-accept policy as decoded from JSON by
/// [`derec_protocol_new`]. One boolean per flow (`true` = the
/// protocol auto-accepts that flow's incoming requests instead of
/// surfacing them as `ActionRequired`).
///
/// Every field is optional: an absent flow takes its value from
/// [`crate::protocol::AutoAcceptPolicy::default()`] through this struct's
/// `Default` impl, so a binding forwards only the flows its caller named.
#[derive(serde::Deserialize)]
#[serde(default)]
struct AutoAcceptConfig {
    pairing: bool,
    pre_pair: bool,
    store_share: bool,
    verify_share: bool,
    discovery: bool,
    get_share: bool,
    unpair: bool,
    update_channel_info: bool,
}

/// Mirrors [`crate::protocol::AutoAcceptPolicy::default()`] field for
/// field rather than repeating the "every flow off" literal here — the
/// policy's own `Default` impl is the single source of truth for what an
/// absent `"auto_accept"` key means.
impl Default for AutoAcceptConfig {
    fn default() -> Self {
        let p = crate::protocol::AutoAcceptPolicy::default();
        Self {
            pairing: p.pairing,
            pre_pair: p.pre_pair,
            store_share: p.store_share,
            verify_share: p.verify_share,
            discovery: p.discovery,
            get_share: p.get_share,
            unpair: p.unpair,
            update_channel_info: p.update_channel_info,
        }
    }
}

impl From<AutoAcceptConfig> for crate::protocol::AutoAcceptPolicy {
    fn from(p: AutoAcceptConfig) -> Self {
        Self {
            pairing: p.pairing,
            pre_pair: p.pre_pair,
            store_share: p.store_share,
            verify_share: p.verify_share,
            discovery: p.discovery,
            get_share: p.get_share,
            unpair: p.unpair,
            update_channel_info: p.update_channel_info,
        }
    }
}

/// Automatic expired-channel cleanup, as carried in the
/// [`derec_protocol_new`] config JSON under `"timeouts"."expired_channels"`.
///
/// Both fields are always transported. Deciding that a disabled policy
/// ignores its timeout is a protocol decision and happens in
/// [`crate::protocol::ExpiredChannelCleanup::new`], not here — this shim
/// only marshals.
#[derive(serde::Deserialize)]
struct RemoveExpiredChannelsConfig {
    enabled: bool,
    timeout_in_secs: u64,
}

/// The four waiting periods, as carried in the [`derec_protocol_new`] config
/// JSON under `"timeouts"`.
///
/// Every field is optional and **absent means "use the library default"** —
/// the defaults live in [`crate::protocol::types::Timeouts`], not here, so a
/// binding that omits a field gets whatever the protocol currently considers
/// right rather than a value frozen into the shim.
#[derive(serde::Deserialize, Default)]
struct TimeoutsConfig {
    #[serde(default)]
    inbound_message_secs: Option<u64>,
    #[serde(default)]
    sharing_round_secs: Option<u64>,
    #[serde(default)]
    unpair_ack_secs: Option<u64>,
    #[serde(default)]
    expired_channels: Option<RemoveExpiredChannelsConfig>,
}

impl TimeoutsConfig {
    fn to_timeouts(&self) -> crate::protocol::types::Timeouts {
        let d = crate::protocol::types::Timeouts::default();
        crate::protocol::types::Timeouts {
            inbound_message: self
                .inbound_message_secs
                .map_or(d.inbound_message, Duration::from_secs),
            sharing_round: self
                .sharing_round_secs
                .map_or(d.sharing_round, Duration::from_secs),
            unpair_ack: self
                .unpair_ack_secs
                .map_or(d.unpair_ack, Duration::from_secs),
            expired_channels: self
                .expired_channels
                .as_ref()
                .map_or(d.expired_channels, |e| {
                    crate::protocol::ExpiredChannelCleanup::new(e.enabled, e.timeout_in_secs)
                }),
        }
    }
}

/// The `parameter_range` object in [`ProtocolConfig`]. Mirrors
/// [`derec_proto::ParameterRange`] field for field.
///
/// Every field is optional and defaults to `0`, which is what the proto's
/// own default is: an unset bound advertises no constraint on that
/// dimension. Omitting the whole object advertises no constraints at all and
/// accepts any peer range, matching the builder's default.
///
/// Each bound is accepted either as a JSON number or as a decimal string.
/// The string form carries the full `i64` range through JSON encoders whose
/// numbers are `f64`, which round anything beyond 2^53.
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ParameterRangeConfig {
    #[serde(deserialize_with = "i64_from_number_or_decimal")]
    min_share_size: i64,
    #[serde(deserialize_with = "i64_from_number_or_decimal")]
    max_share_size: i64,
    #[serde(deserialize_with = "i64_from_number_or_decimal")]
    min_time_between_verifications: i64,
    #[serde(deserialize_with = "i64_from_number_or_decimal")]
    max_time_between_verifications: i64,
    #[serde(deserialize_with = "i64_from_number_or_decimal")]
    min_time_between_share_updates: i64,
    #[serde(deserialize_with = "i64_from_number_or_decimal")]
    max_time_between_share_updates: i64,
    #[serde(deserialize_with = "i64_from_number_or_decimal")]
    min_unresponsive_deletion_timeout: i64,
    #[serde(deserialize_with = "i64_from_number_or_decimal")]
    max_unresponsive_deletion_timeout: i64,
    #[serde(deserialize_with = "i64_from_number_or_decimal")]
    min_unresponsive_deactivation_timeout: i64,
    #[serde(deserialize_with = "i64_from_number_or_decimal")]
    max_unresponsive_deactivation_timeout: i64,
}

/// Reads an `i64` written either as a JSON number or as a decimal string.
fn i64_from_number_or_decimal<'de, D>(de: D) -> Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum NumberOrDecimal {
        Number(i64),
        Decimal(String),
    }
    match <NumberOrDecimal as serde::Deserialize>::deserialize(de)? {
        NumberOrDecimal::Number(n) => Ok(n),
        NumberOrDecimal::Decimal(s) => s
            .parse()
            .map_err(|_| serde::de::Error::custom(format!("{s:?} is not a decimal i64"))),
    }
}

impl From<&ParameterRangeConfig> for derec_proto::ParameterRange {
    fn from(c: &ParameterRangeConfig) -> Self {
        Self {
            min_share_size: c.min_share_size,
            max_share_size: c.max_share_size,
            min_time_between_verifications: c.min_time_between_verifications,
            max_time_between_verifications: c.max_time_between_verifications,
            min_time_between_share_updates: c.min_time_between_share_updates,
            max_time_between_share_updates: c.max_time_between_share_updates,
            min_unresponsive_deletion_timeout: c.min_unresponsive_deletion_timeout,
            max_unresponsive_deletion_timeout: c.max_unresponsive_deletion_timeout,
            min_unresponsive_deactivation_timeout: c.min_unresponsive_deactivation_timeout,
            max_unresponsive_deactivation_timeout: c.max_unresponsive_deactivation_timeout,
        }
    }
}

/// One entry of the `own_transports` array in [`ProtocolConfig`]:
/// `{uri, protocol}`, with `protocol` as its name (`"https"`, `"grpc"`) or
/// its `derec_proto::Protocol` discriminant.
#[derive(serde::Deserialize)]
struct OwnTransportConfig {
    uri: String,
    #[serde(
        deserialize_with = "crate::interop::protocol_names::protocol_from_name_or_discriminant"
    )]
    protocol: i32,
}

/// JSON configuration shape accepted by [`derec_protocol_new`].
///
/// `secret_id` and `replica_id` are decimal strings rather than JSON
/// numbers: `u64` values above 2^53 lose precision once round-tripped
/// through JSON's `f64`-backed number type in common encoders
/// (including Go's `encoding/json`).
#[derive(serde::Deserialize)]
struct ProtocolConfig {
    secret_id: String,
    /// Every endpoint this application serves, in preference order. Absent
    /// or empty is refused at construction.
    #[serde(default)]
    own_transports: Vec<OwnTransportConfig>,
    #[serde(default = "default_threshold")]
    threshold: u32,
    #[serde(default = "default_keep_versions_count")]
    keep_versions_count: u32,
    #[serde(default)]
    auto_respond_on_failure: bool,
    #[serde(default)]
    unpair_ack: Option<UnpairAckConfig>,
    #[serde(default)]
    auto_reply_to: bool,
    #[serde(default)]
    auto_accept: AutoAcceptConfig,
    #[serde(default)]
    timeouts: TimeoutsConfig,
    /// Accept plaintext transport endpoints — `http://` and `grpc://`.
    /// Absent means `false`.
    #[serde(default)]
    unsafe_connection: bool,
    // Absent or `null` means "no replica id".
    #[serde(default)]
    replica_id: Option<String>,
    #[serde(default)]
    parameter_range: Option<ParameterRangeConfig>,
    /// This node's `communication_info` map, as the same flat string-to-string
    /// JSON object `derec_protocol_set_communication_info` takes. Absent means
    /// "not set here". Supplying it together with a non-empty
    /// `communication_info` proto buffer argument is rejected rather than
    /// resolved by precedence.
    #[serde(default)]
    communication_info: Option<HashMap<String, String>>,
}

/// Constructs a [`crate::protocol::DeRecProtocol`] with scalar config
/// bundled as JSON, for FFI callers that cannot pass many native
/// arguments in a single call — e.g. Go via `purego` (no cgo), which
/// panics with "too many stack arguments" past a handful of
/// parameters. Scalar configuration is bundled into a single JSON
/// buffer; `communication_info` travels either in that JSON or as a
/// separate proto-encoded `CommunicationInfo` buffer; the 6 store/transport callback structs
/// are still passed as individual pointers, since purego marshals
/// pointer-sized arguments natively.
///
/// `config_json` must deserialize to [`ProtocolConfig`] — all field names
/// `snake_case`. `secret_id` is the only required field. Every other field
/// may be omitted, in which case the value matches
/// [`crate::protocol::DeRecProtocolBuilder::new`]'s own default for that
/// setting: [`ProtocolConfig`]'s field-level `#[serde(default)]` attributes
/// read the same constants the builder does. A field that is present is
/// used as given, including `0`, and validated by the builder.
///
/// ```json
/// {
///   "secret_id": "12345678901234567890",
///   "own_transports": [{ "uri": "https://example.com/derec", "protocol": "https" }],
///   "threshold": 3,
///   "keep_versions_count": 3,
///   "auto_respond_on_failure": false,
///   "unpair_ack": 0,
///   "auto_reply_to": false,
///   "auto_accept": {
///     "pairing": false,
///     "pre_pair": false,
///     "store_share": false,
///     "verify_share": false,
///     "discovery": false,
///     "get_share": false,
///     "unpair": false,
///     "update_channel_info": false
///   },
///   "timeouts": {
///     "inbound_message_secs": 300,
///     "sharing_round_secs": 60,
///     "unpair_ack_secs": 60,
///     "expired_channels": { "enabled": true, "timeout_in_secs": 300 }
///   },
///   "unsafe_connection": false,
///   "replica_id": null,
///   "parameter_range": {
///     "min_share_size": 0,
///     "max_share_size": 0,
///     "min_time_between_verifications": 0,
///     "max_time_between_verifications": 0,
///     "min_time_between_share_updates": 0,
///     "max_time_between_share_updates": 0,
///     "min_unresponsive_deletion_timeout": 0,
///     "max_unresponsive_deletion_timeout": 0,
///     "min_unresponsive_deactivation_timeout": 0,
///     "max_unresponsive_deactivation_timeout": 0
///   }
/// }
/// ```
///
/// - `secret_id`: decimal-string `u64`.
/// - `own_transports`: every endpoint this application serves, in
///   preference order — the order decides which of a peer's offered
///   endpoints is used. `protocol` is its name (`"https"`, `"grpc"`) or
///   its `derec_proto::Protocol` discriminant (`0`, `1`). Each entry is validated, and
///   two entries of the same protocol are rejected. Required: an absent or
///   empty list is refused, since a node with no endpoint cannot be reached
///   by any peer.
/// - `threshold` / `keep_versions_count`: omitted means
///   [`crate::protocol::DEFAULT_THRESHOLD`] /
///   [`crate::protocol::DEFAULT_KEEP_VERSIONS_COUNT`]. A `threshold` below
///   `2` is rejected with `DEREC_CODE_INVALID_INPUT`.
/// - `unpair_ack`: `0` / `"required"` = Required, `1` / `"not_required"` =
///   NotRequired; omitted means Required.
///   Any other value is rejected with `DEREC_CODE_FFI_INVALID_ENUM`.
/// - `auto_respond_on_failure` / `auto_reply_to`: omitted means `false`.
/// - `timeouts`: the four waiting periods, in whole seconds. Each field is
///   optional and omitted means the [`crate::protocol::types::Timeouts`]
///   default. `expired_channels` is the automatic removal of `Pending`
///   channels; both of its fields are always sent, and when `enabled` is
///   `false` the timeout is ignored by the library.
/// - `unsafe_connection`: accept plaintext `http://` and `grpc://`
///   endpoints. Development only; omitted means `false`.
/// - `replica_id`: decimal-string `u64`, or absent/`null` for "no
///   replica id".
/// - `auto_accept`: each flow is individually optional; an omitted flow
///   takes [`crate::protocol::AutoAcceptPolicy::default()`]'s value.
/// - `parameter_range`: the bounds advertised during pair negotiation,
///   mirroring [`derec_proto::ParameterRange`]. Optional object; every bound
///   is optional, omitted means `0` ("no constraint"), and each may be a JSON
///   number or a decimal string.
/// - `communication_info`: optional flat JSON object of string keys to
///   string values. Mutually exclusive with a non-empty
///   `communication_info_ptr` buffer; omitted with an empty buffer means
///   no entries.
///
/// # Safety
///
/// - `config_json_ptr` must be valid for reads of `config_json_len`
///   bytes.
/// - `communication_info_ptr` must be valid for reads of
///   `communication_info_len` bytes when the length is non-zero.
/// - All 6 callback pointers must be valid for reads of their pointee
///   struct, and must outlive the returned handle.
/// - The caller must invoke [`derec_protocol_free`] exactly once to
///   release the returned handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_new(
    config_json_ptr: *const u8,
    config_json_len: usize,
    communication_info_ptr: *const u8,
    communication_info_len: usize,
    channel_store_cb: *const ChannelStoreCallbacks,
    secret_store_cb: *const SecretStoreCallbacks,
    share_store_cb: *const ShareStoreCallbacks,
    user_secret_store_cb: *const UserSecretStoreCallbacks,
    state_store_cb: *const StateStoreCallbacks,
    transport_cb: *const TransportCallbacks,
) -> DeRecProtocolNewResult {
    if config_json_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "config_json_ptr is null").into();
    }
    let json_bytes = unsafe { std::slice::from_raw_parts(config_json_ptr, config_json_len) };
    let config: ProtocolConfig = match serde_json::from_slice(json_bytes) {
        Ok(c) => c,
        Err(e) => {
            return ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("config_json is not valid: {e}"),
            )
            .into();
        }
    };

    let secret_id: u64 = match config.secret_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return ffi_error(DEREC_CODE_FFI_BAD_PROTO, "secret_id is not a valid u64").into();
        }
    };

    let replica_id: Option<u64> = match config.replica_id {
        Some(s) => match s.parse() {
            Ok(id) => Some(id),
            Err(_) => {
                return ffi_error(DEREC_CODE_FFI_BAD_PROTO, "replica_id is not a valid u64").into();
            }
        },
        None => None,
    };

    // Every entry is validated so the protocol can't be constructed with a
    // malformed or downgraded endpoint that would then be propagated to peers
    // via pairing. An empty list reaches the builder, which refuses it: a node
    // with no endpoint cannot be reached by any peer.
    let mut own_transports = Vec::with_capacity(config.own_transports.len());
    for entry in config.own_transports {
        match validate_transport(&entry.uri, entry.protocol) {
            Ok(tp) => own_transports.push(tp),
            Err(e) => return e.into(),
        }
    }

    let info = match unsafe {
        resolve_communication_info(
            config.communication_info,
            communication_info_ptr,
            communication_info_len,
        )
    } {
        Ok(i) => i,
        Err(e) => return e.into(),
    };

    let unpair_ack_value = match config.unpair_ack.map(UnpairAckConfig::resolve) {
        None => crate::protocol::UnpairAck::default(),
        Some(Ok(ack)) => ack,
        Some(Err(e)) => return e.into(),
    };

    let unsafe_connection = config.unsafe_connection;

    unsafe {
        construct_protocol(
            secret_id,
            own_transports,
            config.threshold,
            config.keep_versions_count,
            info,
            config.timeouts.to_timeouts(),
            unsafe_connection,
            config.auto_respond_on_failure,
            unpair_ack_value,
            config.auto_reply_to,
            config.auto_accept.into(),
            replica_id,
            config.parameter_range.as_ref().map(Into::into),
            channel_store_cb,
            secret_store_cb,
            share_store_cb,
            user_secret_store_cb,
            state_store_cb,
            transport_cb,
        )
    }
}

/// Release a handle previously returned by [`derec_protocol_new`].
/// Safe to call with a null pointer.
///
/// # Safety
///
/// `handle` must satisfy ALL of:
///
/// - It is a pointer previously returned by [`derec_protocol_new`],
///   or it is null.
/// - It has not already been freed (no double-free).
/// - **No other thread is executing any `derec_protocol_*` function on
///   this handle while this call is in flight.** The interior
///   [`std::sync::Mutex`] protects against aliased `&mut` references
///   *within* the live allocation, but it cannot protect the
///   allocation itself from being dropped — a concurrent
///   `derec_protocol_process` / `accept` / `set_*` call that holds
///   the lock would be reading freed memory the moment this function
///   returns. Host bindings (.NET `Dispose`, Node.js / WASM
///   teardown) are responsible for draining or cancelling in-flight
///   calls before invoking `derec_protocol_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_free(handle: *mut DeRecProtocolHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Pick the `communication_info` map [`derec_protocol_new`] was given: the
/// `communication_info` key of its config JSON, or its proto buffer
/// argument. Both at once is an error, so neither silently wins.
///
/// # Safety
///
/// `ptr` must be valid for reads of `len` bytes when `len != 0`.
unsafe fn resolve_communication_info(
    from_config: Option<HashMap<String, String>>,
    ptr: *const u8,
    len: usize,
) -> Result<HashMap<String, String>, DeRecError> {
    match from_config {
        Some(_) if len != 0 => Err(ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            "communication_info supplied both in config_json and as a proto buffer",
        )),
        Some(map) => Ok(map),
        None => unsafe { decode_communication_info(ptr, len) },
    }
}

/// Decode a serialized [`derec_proto::CommunicationInfo`] proto buffer
/// into the `<String, String>` map the core protocol accepts. Used by
/// [`derec_protocol_new`], which takes `communication_info` as
/// a proto buffer separate from the rest of its JSON configuration.
///
/// # Safety
///
/// `ptr` must be valid for reads of `len` bytes when `len != 0`.
unsafe fn decode_communication_info(
    ptr: *const u8,
    len: usize,
) -> Result<HashMap<String, String>, DeRecError> {
    if len == 0 {
        return Ok(HashMap::new());
    }
    if ptr.is_null() {
        return Err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "communication_info_ptr is null but length is non-zero",
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    match derec_proto::CommunicationInfo::decode(bytes) {
        Ok(c) => Ok(c.to_map()),
        Err(_) => Err(ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            "communication_info is not a valid CommunicationInfo proto",
        )),
    }
}

/// Construction logic for [`derec_protocol_new`]: takes the
/// already-parsed/validated scalar configuration plus the 6
/// store/transport callback pointers,
/// reads each callback struct, builds the [`DeRecProtocolBuilder`],
/// and wraps the result in a handle bound to a fresh single-thread
/// tokio runtime.
///
/// # Safety
///
/// - All 6 callback pointers must be valid for reads of their pointee
///   struct.
/// - `channel_store_cb`/`secret_store_cb`/`share_store_cb`/`user_secret_store_cb`/
///   `state_store_cb`/`transport_cb` must outlive the returned handle.
#[allow(clippy::too_many_arguments)]
unsafe fn construct_protocol(
    secret_id: u64,
    own_transports: Vec<crate::transport::TransportProtocol>,
    threshold: u32,
    keep_versions_count: u32,
    communication_info: HashMap<String, String>,
    timeouts: crate::protocol::types::Timeouts,
    unsafe_connection: bool,
    auto_respond_on_failure: bool,
    unpair_ack: crate::protocol::UnpairAck,
    auto_reply_to: bool,
    auto_accept: crate::protocol::AutoAcceptPolicy,
    replica_id: Option<u64>,
    parameter_range: Option<derec_proto::ParameterRange>,
    channel_store_cb: *const ChannelStoreCallbacks,
    secret_store_cb: *const SecretStoreCallbacks,
    share_store_cb: *const ShareStoreCallbacks,
    user_secret_store_cb: *const UserSecretStoreCallbacks,
    state_store_cb: *const StateStoreCallbacks,
    transport_cb: *const TransportCallbacks,
) -> DeRecProtocolNewResult {
    if channel_store_cb.is_null()
        || secret_store_cb.is_null()
        || share_store_cb.is_null()
        || user_secret_store_cb.is_null()
        || state_store_cb.is_null()
        || transport_cb.is_null()
    {
        return ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "store/transport callback pointer is null",
        )
        .into();
    }

    let channel_store = DotnetChannelStore {
        cb: unsafe { std::ptr::read(channel_store_cb) },
    };
    let secret_store = DotnetSecretStore {
        cb: unsafe { std::ptr::read(secret_store_cb) },
    };
    let share_store = DotnetShareStore {
        cb: unsafe { std::ptr::read(share_store_cb) },
    };
    let user_secret_store = DotnetUserSecretStore {
        cb: unsafe { std::ptr::read(user_secret_store_cb) },
    };
    let state_store = DotnetStateStore {
        cb: unsafe { std::ptr::read(state_store_cb) },
    };
    let transport = DotnetTransport {
        cb: unsafe { std::ptr::read(transport_cb) },
    };

    let mut builder = DeRecProtocolBuilder::new(secret_id)
        .with_channel_store(channel_store)
        .with_share_store(share_store)
        .with_secret_store(secret_store)
        .with_user_secret_store(user_secret_store)
        .with_state_store(state_store)
        .with_transport(transport)
        .with_own_transports(own_transports)
        .with_threshold(threshold as usize)
        .with_keep_versions_count(keep_versions_count as usize)
        .with_communication_info(communication_info)
        .with_timeouts(timeouts)
        .with_unsafe_connection(unsafe_connection)
        .with_auto_respond_on_failure(auto_respond_on_failure)
        .with_unpair_ack(unpair_ack)
        .with_auto_reply_to(auto_reply_to)
        .with_auto_accept(auto_accept);

    if let Some(replica_id) = replica_id {
        builder = builder.with_replica_id(replica_id);
    }
    if let Some(parameter_range) = parameter_range {
        builder = builder.with_parameter_range(parameter_range);
    }

    let inner = match builder.build() {
        Ok(p) => p,
        Err(e) => return crate::interop::ffi::error::from_lib_error(e).into(),
    };

    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(e) => {
            return ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to build tokio runtime: {e}"),
            )
            .into();
        }
    };

    let handle = Box::new(DeRecProtocolHandle {
        runtime,
        inner: std::sync::Mutex::new(inner),
    });
    DeRecProtocolNewResult {
        error: success(),
        handle: Box::into_raw(handle),
    }
}

/// [`crate::protocol::DEFAULT_THRESHOLD`], narrowed to the FFI config's
/// wire type. Read by serde's `#[serde(default = "...")]` on
/// [`ProtocolConfig::threshold`] so an absent key resolves to the same
/// constant [`crate::protocol::DeRecProtocolBuilder::new`] uses.
fn default_threshold() -> u32 {
    crate::protocol::DEFAULT_THRESHOLD as u32
}

/// See [`default_threshold`]; the [`crate::protocol::DEFAULT_KEEP_VERSIONS_COUNT`]
/// counterpart for [`ProtocolConfig::keep_versions_count`].
fn default_keep_versions_count() -> u32 {
    crate::protocol::DEFAULT_KEEP_VERSIONS_COUNT as u32
}

/// The `unpair_ack` config value: either the discriminant (`0` = Required,
/// `1` = NotRequired) or the name every binding exposes (`"required"`,
/// `"not_required"`). Absent means [`crate::protocol::UnpairAck::default()`].
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum UnpairAckConfig {
    Code(i32),
    Name(String),
}

impl UnpairAckConfig {
    fn resolve(self) -> Result<crate::protocol::UnpairAck, DeRecError> {
        let resolved = match &self {
            Self::Code(0) => Some(crate::protocol::UnpairAck::Required),
            Self::Code(1) => Some(crate::protocol::UnpairAck::NotRequired),
            Self::Code(_) => None,
            Self::Name(name) => crate::interop::protocol_names::unpair_ack_from_name(name),
        };
        resolved.ok_or_else(|| {
            let shown = match self {
                Self::Code(code) => code.to_string(),
                Self::Name(name) => format!("{name:?}"),
            };
            ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid unpair_ack: {shown}"),
            )
        })
    }
}

#[cfg(test)]
mod protocol_config_defaults_tests {
    use super::*;

    /// A config JSON carrying only the required `secret_id`
    /// deserializes, and every omitted field resolves to exactly the value
    /// [`crate::protocol::DeRecProtocolBuilder::new`] would have used —
    /// proving the FFI shim invents no defaults of its own.
    #[test]
    fn minimal_config_json_matches_builder_defaults() {
        let minimal = r#"{
            "secret_id": "1"
        }"#;
        let config: ProtocolConfig =
            serde_json::from_str(minimal).expect("minimal config must deserialize");

        assert_eq!(config.threshold, crate::protocol::DEFAULT_THRESHOLD as u32);
        assert_eq!(
            config.keep_versions_count,
            crate::protocol::DEFAULT_KEEP_VERSIONS_COUNT as u32
        );
        assert!(!config.auto_respond_on_failure);
        assert!(config.unpair_ack.is_none());
        assert!(!config.auto_reply_to);
        assert_eq!(
            crate::protocol::AutoAcceptPolicy::from(config.auto_accept),
            crate::protocol::AutoAcceptPolicy::default()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `unpair_ack` takes the discriminant or the binding-facing name; any
    /// other value is refused rather than defaulted.
    #[test]
    fn unpair_ack_accepts_code_or_name_and_refuses_the_rest() {
        let resolve = |value: &str| {
            let config: ProtocolConfig =
                serde_json::from_str(&format!(r#"{{"secret_id": "1", "unpair_ack": {value}}}"#))
                    .expect("parses");
            config.unpair_ack.map(UnpairAckConfig::resolve)
        };
        use crate::protocol::UnpairAck::{NotRequired, Required};
        assert!(matches!(resolve("0"), Some(Ok(Required))));
        assert!(matches!(resolve("1"), Some(Ok(NotRequired))));
        assert!(matches!(resolve(r#""required""#), Some(Ok(Required))));
        assert!(matches!(
            resolve(r#""not_required""#),
            Some(Ok(NotRequired))
        ));
        for bad in ["2", "-1", r#""Required""#, r#""notrequired""#] {
            match resolve(bad) {
                Some(Err(e)) => assert_eq!(e.code, DEREC_CODE_FFI_INVALID_ENUM, "{bad}"),
                _ => panic!("{bad} must be refused"),
            }
        }
    }

    /// `unsafe_connection` is read when present and defaults to `false`.
    #[test]
    fn config_json_reads_the_plaintext_flag() {
        let set: ProtocolConfig = serde_json::from_str(
            r#"{
                "secret_id": "1",
                "unsafe_connection": true
            }"#,
        )
        .expect("parses");
        assert!(set.unsafe_connection);

        let absent: ProtocolConfig = serde_json::from_str(
            r#"{
                "secret_id": "1"
            }"#,
        )
        .expect("parses");
        assert!(!absent.unsafe_connection);
    }

    fn config_with(extra: &str) -> ProtocolConfig {
        let json = format!(
            r#"{{
                "secret_id": "1",
                "own_transport_uri": "",
                "own_transport_protocol": 1
                {extra}
            }}"#
        );
        serde_json::from_str(&json).expect("config parses")
    }

    /// A partial `auto_accept` object leaves every unnamed flow at the
    /// policy's own default instead of failing to deserialize.
    #[test]
    fn partial_auto_accept_defaults_each_absent_flow() {
        let config = config_with(r#", "auto_accept": { "pairing": true }"#);
        let policy = crate::protocol::AutoAcceptPolicy::from(config.auto_accept);
        let expected = crate::protocol::AutoAcceptPolicy {
            pairing: true,
            ..crate::protocol::AutoAcceptPolicy::default()
        };
        assert_eq!(policy, expected);

        let empty = config_with(r#", "auto_accept": {}"#);
        assert_eq!(
            crate::protocol::AutoAcceptPolicy::from(empty.auto_accept),
            crate::protocol::AutoAcceptPolicy::default()
        );
    }

    /// Parameter-range bounds keep full `i64` precision when written as
    /// decimal strings, still accept JSON numbers, and default to `0`.
    #[test]
    fn parameter_range_accepts_decimal_strings_and_numbers() {
        let config = config_with(
            r#", "parameter_range": {
                "min_share_size": "9007199254740993",
                "max_share_size": 4096,
                "max_unresponsive_deactivation_timeout": "-9223372036854775808"
            }"#,
        );
        let range = derec_proto::ParameterRange::from(
            config.parameter_range.as_ref().expect("range present"),
        );
        assert_eq!(range.min_share_size, 9_007_199_254_740_993);
        assert_eq!(range.max_share_size, 4096);
        assert_eq!(range.max_unresponsive_deactivation_timeout, i64::MIN);
        assert_eq!(range.min_time_between_verifications, 0);

        let bad = serde_json::from_str::<ProtocolConfig>(
            r#"{
                "secret_id": "1",
                "own_transport_uri": "",
                "own_transport_protocol": 1,
                "parameter_range": { "min_share_size": "12x" }
            }"#,
        );
        assert!(bad.is_err());
    }

    /// `communication_info` in the config JSON is used as-is, the proto
    /// buffer is still honored when the key is absent, and supplying both
    /// is rejected.
    #[test]
    fn communication_info_comes_from_exactly_one_source() {
        let config = config_with(r#", "communication_info": { "name": "alice" }"#);
        let from_json =
            unsafe { resolve_communication_info(config.communication_info, std::ptr::null(), 0) }
                .unwrap_or_else(|e| panic!("json map refused: {}", e.code));
        assert_eq!(from_json.get("name").map(String::as_str), Some("alice"));

        let mut map = HashMap::new();
        map.insert("name".to_owned(), "bob".to_owned());
        let proto = derec_proto::CommunicationInfo::from_map(&map).encode_to_vec();
        let from_proto = unsafe { resolve_communication_info(None, proto.as_ptr(), proto.len()) }
            .unwrap_or_else(|e| panic!("proto buffer refused: {}", e.code));
        assert_eq!(from_proto, map);

        let neither = unsafe { resolve_communication_info(None, std::ptr::null(), 0) }
            .unwrap_or_else(|e| panic!("absent refused: {}", e.code));
        assert!(neither.is_empty());

        let both = unsafe {
            resolve_communication_info(Some(HashMap::new()), proto.as_ptr(), proto.len())
        };
        let mut err = both.expect_err("both sources rejected");
        assert_eq!(err.code, DEREC_CODE_FFI_BAD_PROTO);
        unsafe { crate::interop::ffi::error::derec_free_error(&mut err) };
    }
}
