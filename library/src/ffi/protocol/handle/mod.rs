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

use crate::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_INVALID_ENUM, DEREC_CODE_FFI_NULL_PTR, DeRecError,
    ffi_error, success,
};
use crate::ffi::protocol::stores::{
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
/// surfaced through [`crate::ffi::error::from_lib_error`] so the
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
        .map_err(|e| crate::ffi::error::from_lib_error(crate::Error::Transport(e)))
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
        Ok(c) => Ok(c
            .communication_info_entries
            .into_iter()
            .filter_map(|e| {
                let s = match e.value? {
                    derec_proto::communication_info_key_value::Value::StringValue(s) => s,
                    // Binary entries have nowhere to land in the core
                    // protocol's `<String, String>` map; skip them.
                    derec_proto::communication_info_key_value::Value::BytesValue(_) => {
                        return None;
                    }
                };
                Some((e.key, s))
            })
            .collect()),
        Err(_) => Err(ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            "communication_info is not a valid CommunicationInfo proto",
        )),
    }
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
    own_transport: crate::transport::TransportProtocol,
    threshold: u32,
    keep_versions_count: u32,
    communication_info: HashMap<String, String>,
    timeouts: crate::protocol::types::Timeouts,
    auto_respond_on_failure: bool,
    unpair_ack: crate::protocol::UnpairAck,
    auto_reply_to: bool,
    auto_accept: crate::protocol::AutoAcceptPolicy,
    replica_id: Option<u64>,
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
        .with_own_transport(own_transport)
        .with_threshold(threshold as usize)
        .with_keep_versions_count(keep_versions_count as usize)
        .with_communication_info(communication_info)
        .with_timeouts(timeouts)
        .with_auto_respond_on_failure(auto_respond_on_failure)
        .with_unpair_ack(unpair_ack)
        .with_auto_reply_to(auto_reply_to)
        .with_auto_accept(auto_accept);

    if let Some(replica_id) = replica_id {
        builder = builder.with_replica_id(replica_id);
    }

    let inner = match builder.build() {
        Ok(p) => p,
        Err(e) => return crate::ffi::error::from_lib_error(e).into(),
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

#[derive(serde::Deserialize)]
struct ProtocolConfig {
    secret_id: String,
    own_transport_uri: String,
    own_transport_protocol: i32,
    threshold: u32,
    keep_versions_count: u32,
    auto_respond_on_failure: bool,
    // 0 = Required, 1 = NotRequired.
    unpair_ack: i32,
    auto_reply_to: bool,
    auto_accept: AutoAcceptConfig,
    #[serde(default)]
    timeouts: TimeoutsConfig,
    // Absent or `null` means "no replica id".
    #[serde(default)]
    replica_id: Option<String>,
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
/// names `snake_case`, all fields required unless noted:
///
/// ```json
/// {
///   "secret_id": "12345678901234567890",
///   "own_transport_uri": "https://example.com/derec",
///   "own_transport_protocol": 1,
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
/// - `unpair_ack`: `0` = Required, `1` = NotRequired.
/// - `auto_accept`: one boolean per flow.
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

    // Empty URI is the deferred-config path: the caller will call
    // `derec_protocol_set_own_transport` later, at which point
    // validation runs unconditionally. Non-empty URIs are validated
    // here so the protocol can't be constructed with a malformed or
    // downgraded endpoint that would then be propagated to peers
    // via pairing.
    let own_transport: crate::transport::TransportProtocol = if config.own_transport_uri.is_empty()
    {
        crate::transport::TransportProtocol::new(String::new(), derec_proto::Protocol::Https)
    } else {
        match validate_transport(&config.own_transport_uri, config.own_transport_protocol) {
            Ok(tp) => tp,
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

    unsafe {
        construct_protocol(
            secret_id,
            own_transport,
            config.threshold,
            config.keep_versions_count,
            info,
            config.timeouts.to_timeouts(),
            config.auto_respond_on_failure,
            unpair_ack_value,
            config.auto_reply_to,
            config.auto_accept.into(),
            replica_id,
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
