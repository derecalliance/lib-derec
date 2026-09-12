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
#[derive(serde::Deserialize)]
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

/// JSON configuration shape accepted by [`derec_protocol_new`].
///
/// `secret_id` and `replica_id` are decimal strings rather than JSON
/// numbers: `u64` values above 2^53 lose precision once round-tripped
/// through JSON's `f64`-backed number type in common encoders
/// (including Go's `encoding/json`).
/// Automatic expired-channel cleanup, as carried in the
/// [`derec_protocol_new`] config JSON.
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

impl Default for RemoveExpiredChannelsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_in_secs: 300,
        }
    }
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
#[derive(serde::Deserialize)]
struct ParameterRangeConfig {
    #[serde(default)]
    min_share_size: i64,
    #[serde(default)]
    max_share_size: i64,
    #[serde(default)]
    min_time_between_verifications: i64,
    #[serde(default)]
    max_time_between_verifications: i64,
    #[serde(default)]
    min_time_between_share_updates: i64,
    #[serde(default)]
    max_time_between_share_updates: i64,
    #[serde(default)]
    min_unresponsive_deletion_timeout: i64,
    #[serde(default)]
    max_unresponsive_deletion_timeout: i64,
    #[serde(default)]
    min_unresponsive_deactivation_timeout: i64,
    #[serde(default)]
    max_unresponsive_deactivation_timeout: i64,
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

/// One entry of the `own_transports` array in [`ProtocolConfig`]. Mirrors
/// the serde representation of [`derec_proto::TransportProtocol`] that
/// every binding's JSON channel marshaller already round-trips —
/// `{uri, protocol}` with `protocol` as the `i32` discriminant.
#[derive(serde::Deserialize)]
struct OwnTransportConfig {
    uri: String,
    protocol: i32,
}

#[derive(serde::Deserialize)]
struct ProtocolConfig {
    secret_id: String,
    own_transport_uri: String,
    own_transport_protocol: i32,
    /// Every endpoint this application serves, in preference order.
    ///
    /// Absent or empty falls back to the `own_transport_uri` /
    /// `own_transport_protocol` scalars above, which remain fully
    /// supported. When non-empty, this array takes precedence over the
    /// scalars entirely.
    #[serde(default)]
    own_transports: Vec<OwnTransportConfig>,
    #[serde(default = "default_threshold")]
    threshold: u32,
    #[serde(default = "default_keep_versions_count")]
    keep_versions_count: u32,
    #[serde(default)]
    auto_respond_on_failure: bool,
    // 0 = Required, 1 = NotRequired.
    #[serde(default = "default_unpair_ack")]
    unpair_ack: i32,
    #[serde(default)]
    auto_reply_to: bool,
    #[serde(default)]
    auto_accept: AutoAcceptConfig,
    #[serde(default)]
    timeouts: TimeoutsConfig,
    /// Accept plaintext transport endpoints. Absent means "not set", which
    /// is distinct from `false`: an SDK that never writes this key must not
    /// override `unsafe_connection`.
    ///
    /// Superseded by `unsafe_connection`; still honored, and wins on
    /// conflict. Removed at 0.0.5.
    #[serde(default)]
    unsafe_http: Option<bool>,
    /// Accept plaintext transport endpoints — `http://` and `grpc://`.
    /// Absent means "not set". See `unsafe_http` for the conflict rule.
    #[serde(default)]
    unsafe_connection: Option<bool>,
    // Absent or `null` means "no replica id".
    #[serde(default)]
    replica_id: Option<String>,
    #[serde(default)]
    parameter_range: Option<ParameterRangeConfig>,
}

/// Constructs a [`crate::protocol::DeRecProtocol`] with scalar config
/// bundled as JSON, for FFI callers that cannot pass many native
/// arguments in a single call — e.g. Go via `purego` (no cgo), which
/// panics with "too many stack arguments" past a handful of
/// parameters. Scalar configuration is bundled into a single JSON
/// buffer; `communication_info` stays a separate proto-encoded
/// `CommunicationInfo` buffer; the 6 store/transport callback structs
/// are still passed as individual pointers, since purego marshals
/// pointer-sized arguments natively.
///
/// `config_json` must deserialize to the following shape — all field
/// names `snake_case`. `secret_id`, `own_transport_uri` and
/// `own_transport_protocol` are the only genuinely required fields;
/// `threshold`, `keep_versions_count`, `auto_respond_on_failure`,
/// `unpair_ack`, `auto_reply_to` and `auto_accept` may each be omitted, in
/// which case the value matches
/// [`crate::protocol::DeRecProtocolBuilder::new`]'s own default for that
/// setting — see [`ProtocolConfig`]'s field-level `#[serde(default)]`
/// attributes, which read the same constants the builder does:
///
/// ```json
/// {
///   "secret_id": "12345678901234567890",
///   "own_transport_uri": "https://example.com/derec",
///   "own_transport_protocol": 1,
///   "own_transports": [{ "uri": "https://example.com/derec", "protocol": 0 }],
///   "threshold": 3,
///   "keep_versions_count": 2,
///   "timeout_in_secs": 30,
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
///   "remove_expired_channels": { "enabled": true, "timeout_in_secs": 300 },
///   "replica_id": null
/// }
/// ```
///
/// - `secret_id`: decimal-string `u64`.
/// - `own_transport_uri`: may be `""` for the deferred-config path;
///   `derec_protocol_set_own_transport` must be called before pairing
///   in that case.
/// - `own_transport_protocol`: [`derec_proto::Protocol`] discriminant.
/// - `own_transports`: every endpoint this application serves, in
///   preference order — the order decides which of a peer's offered
///   endpoints is used. Optional; when non-empty it takes precedence over
///   `own_transport_uri` / `own_transport_protocol`, which stay fully
///   supported for callers that serve a single transport.
/// - `threshold` / `keep_versions_count`: optional; omitted means
///   [`crate::protocol::DEFAULT_THRESHOLD`] /
///   [`crate::protocol::DEFAULT_KEEP_VERSIONS_COUNT`].
/// - `unpair_ack`: `0` = Required, `1` = NotRequired; optional, omitted
///   means `0`.
/// - `auto_respond_on_failure` / `auto_reply_to`: optional, omitted means
///   `false`.
/// - `auto_accept`: one boolean per flow; the whole object is optional,
///   omitted means every flow `false`.
/// - `remove_expired_channels`: automatic removal of expired `Pending`
///   channels. Optional — omitted means `{ "enabled": true,
///   "timeout_in_secs": 300 }`. Both fields are always sent; when
///   `enabled` is `false` the timeout is ignored by the library.
/// - `replica_id`: decimal-string `u64`, or absent/`null` for "no
///   replica id".
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

    // The `own_transports` array takes precedence over the scalar
    // `own_transport_uri` / `own_transport_protocol` fields when
    // non-empty. Empty scalar URI (and an empty array) is the
    // deferred-config path: the caller will call
    // `derec_protocol_set_own_transport` later, at which point
    // validation runs unconditionally. Every other combination is
    // validated here so the protocol can't be constructed with a
    // malformed or downgraded endpoint that would then be propagated
    // to peers via pairing.
    let own_transports: Vec<crate::transport::TransportProtocol> =
        if !config.own_transports.is_empty() {
            let mut validated = Vec::with_capacity(config.own_transports.len());
            for entry in config.own_transports {
                match validate_transport(&entry.uri, entry.protocol) {
                    Ok(tp) => validated.push(tp),
                    Err(e) => return e.into(),
                }
            }
            validated
        } else if config.own_transport_uri.is_empty() {
            vec![crate::transport::TransportProtocol::new(
                String::new(),
                derec_proto::Protocol::Https,
            )]
        } else {
            match validate_transport(&config.own_transport_uri, config.own_transport_protocol) {
                Ok(tp) => vec![tp],
                Err(e) => return e.into(),
            }
        };

    let info = match unsafe {
        decode_communication_info(communication_info_ptr, communication_info_len)
    } {
        Ok(i) => i,
        Err(e) => return e.into(),
    };

    let unpair_ack_value = match config.unpair_ack {
        0 => crate::protocol::UnpairAck::Required,
        1 => crate::protocol::UnpairAck::NotRequired,
        other => {
            return ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid unpair_ack: {other}"),
            )
            .into();
        }
    };

    let unsafe_connection = match crate::protocol::builder::resolve_plaintext_opt_in(
        config.unsafe_http,
        config.unsafe_connection,
    ) {
        Ok(v) => v,
        Err(e) => return crate::interop::ffi::error::from_lib_error(e).into(),
    };

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

/// [`crate::protocol::UnpairAck::default()`] (`Required`), encoded as the
/// wire discriminant. Read by serde's `#[serde(default = "...")]` on
/// [`ProtocolConfig::unpair_ack`] so an absent key resolves to the same
/// default [`crate::protocol::DeRecProtocolBuilder::new`] uses.
fn default_unpair_ack() -> i32 {
    crate::protocol::UnpairAck::default() as i32
}

#[cfg(test)]
mod protocol_config_defaults_tests {
    use super::*;

    /// A config JSON carrying only the genuinely-required fields
    /// (`secret_id`, `own_transport_uri`, `own_transport_protocol`)
    /// deserializes, and every omitted field resolves to exactly the value
    /// [`crate::protocol::DeRecProtocolBuilder::new`] would have used —
    /// proving the FFI shim invents no defaults of its own.
    #[test]
    fn minimal_config_json_matches_builder_defaults() {
        let minimal = r#"{
            "secret_id": "1",
            "own_transport_uri": "",
            "own_transport_protocol": 1
        }"#;
        let config: ProtocolConfig =
            serde_json::from_str(minimal).expect("minimal config must deserialize");

        assert_eq!(config.threshold, crate::protocol::DEFAULT_THRESHOLD as u32);
        assert_eq!(
            config.keep_versions_count,
            crate::protocol::DEFAULT_KEEP_VERSIONS_COUNT as u32
        );
        assert!(!config.auto_respond_on_failure);
        assert_eq!(
            config.unpair_ack,
            crate::protocol::UnpairAck::default() as i32
        );
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

    /// `ProtocolConfig` accepts either plaintext opt-in key independently,
    /// and leaves both `None` when neither is present — the FFI shim must
    /// preserve presence so `resolve_plaintext_opt_in` sees the same
    /// distinction the builder does.
    #[test]
    fn config_json_accepts_either_plaintext_flag() {
        let old: ProtocolConfig = serde_json::from_str(
            r#"{
                "secret_id": "1",
                "own_transport_uri": "",
                "own_transport_protocol": 1,
                "unsafe_http": true
            }"#,
        )
        .expect("parses");
        assert_eq!(old.unsafe_http, Some(true));
        assert_eq!(old.unsafe_connection, None);

        let new: ProtocolConfig = serde_json::from_str(
            r#"{
                "secret_id": "1",
                "own_transport_uri": "",
                "own_transport_protocol": 1,
                "unsafe_connection": true
            }"#,
        )
        .expect("parses");
        assert_eq!(new.unsafe_http, None);
        assert_eq!(new.unsafe_connection, Some(true));

        let neither: ProtocolConfig = serde_json::from_str(
            r#"{
                "secret_id": "1",
                "own_transport_uri": "",
                "own_transport_protocol": 1
            }"#,
        )
        .expect("parses");
        assert_eq!(neither.unsafe_http, None);
        assert_eq!(neither.unsafe_connection, None);
    }
}
