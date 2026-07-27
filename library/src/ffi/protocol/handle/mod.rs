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
    ffi_error, success, DeRecError, DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_INVALID_ENUM,
    DEREC_CODE_FFI_NULL_PTR,
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

/// Opaque handle returned by [`derec_protocol_new`] and consumed by every
/// other entry point in this module. Holds the protocol instance + the
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
/// into the `<String, String>` map the core protocol accepts. Shared
/// by [`derec_protocol_new`] and [`derec_protocol_new_packed`], which
/// both take `communication_info` as a proto buffer regardless of how
/// the rest of their configuration is packed.
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

/// Per-flow auto-accept policy passed across the C ABI.
///
/// Each field is `u32` (0 = off, anything else = on) to match the rest
/// of the FFI's bool-as-`u32` convention. Mirrors
/// [`crate::protocol::AutoAcceptPolicy`] one-to-one. Pass a struct
/// literal with the desired flows enabled; an all-zero struct means
/// "every flow off" (same as today's behaviour where every request
/// surfaces as `ActionRequired`).
#[repr(C)]
pub struct DeRecAutoAcceptPolicy {
    pub pairing: u32,
    pub pre_pair: u32,
    pub store_share: u32,
    pub verify_share: u32,
    pub discovery: u32,
    pub get_share: u32,
    pub unpair: u32,
    pub update_channel_info: u32,
}

impl From<DeRecAutoAcceptPolicy> for crate::protocol::AutoAcceptPolicy {
    fn from(p: DeRecAutoAcceptPolicy) -> Self {
        Self {
            pairing: p.pairing != 0,
            pre_pair: p.pre_pair != 0,
            store_share: p.store_share != 0,
            verify_share: p.verify_share != 0,
            discovery: p.discovery != 0,
            get_share: p.get_share != 0,
            unpair: p.unpair != 0,
            update_channel_info: p.update_channel_info != 0,
        }
    }
}

impl From<DeRecError> for DeRecProtocolNewResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            handle: std::ptr::null_mut(),
        }
    }
}

/// Shared construction logic for [`derec_protocol_new`] and
/// [`derec_protocol_new_packed`]: takes the already-parsed/validated
/// scalar configuration plus the 6 store/transport callback pointers,
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
    timeout_in_secs: u32,
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
        .with_timeout(Duration::from_secs(u64::from(timeout_in_secs.max(1))))
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

/// Construct a new [`crate::protocol::DeRecProtocol`] instance bound to
/// the caller-supplied store/transport callbacks. Buffer-passing
/// convention for the callbacks is documented on each `*Callbacks`
/// struct in [`super::super::stores`].
///
/// # Safety
///
/// - All pointers passed in must be valid for the documented direction
///   (`*const` = readable, `*mut` = writable) and length.
/// - `channel_store_cb`/`secret_store_cb`/`share_store_cb`/`transport_cb`
///   must outlive the returned handle.
/// - The caller must invoke [`derec_protocol_free`] exactly once to release
///   the handle.
///
/// # Deprecated
///
/// This 21-argument form exceeds the stack-argument limit of some FFI
/// callers (e.g. Go via `purego`, which panics with "too many stack
/// arguments" past ~9 arguments). Use [`derec_protocol_new_packed`]
/// instead, which bundles the scalar configuration into a single JSON
/// buffer. This function will be removed in a future version.
#[deprecated(
    note = "use derec_protocol_new_packed; the 21-arg form exceeds some FFI callers' argument limits (e.g. Go/purego). This form will be removed in a future version."
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_new(
    secret_id: u64,
    channel_store_cb: *const ChannelStoreCallbacks,
    secret_store_cb: *const SecretStoreCallbacks,
    share_store_cb: *const ShareStoreCallbacks,
    user_secret_store_cb: *const UserSecretStoreCallbacks,
    state_store_cb: *const StateStoreCallbacks,
    transport_cb: *const TransportCallbacks,
    own_transport_uri_ptr: *const u8,
    own_transport_uri_len: usize,
    own_transport_protocol: i32,
    threshold: u32,
    keep_versions_count: u32,
    communication_info_ptr: *const u8,
    communication_info_len: usize,
    timeout_in_secs: u32,
    auto_respond_on_failure: u32,
    // `unpair_ack`: 0 = Required, 1 = NotRequired.
    unpair_ack: i32,
    auto_reply_to: u32,
    // Per-flow auto-accept toggles. See [`DeRecAutoAcceptPolicy`].
    // Passed by value to keep the C ABI simple (no allocation, no
    // null-pointer handling); the all-zero struct is the safe default.
    auto_accept: DeRecAutoAcceptPolicy,
    // `has_replica_id`: 0 = unset, 1 = use `replica_id` value.
    has_replica_id: u32,
    replica_id: u64,
) -> DeRecProtocolNewResult {
    // The six callback pointers are null-checked in `construct_protocol`,
    // which this function delegates to; no duplicate check is needed here.
    let own_uri = if own_transport_uri_len == 0 {
        String::new()
    } else if own_transport_uri_ptr.is_null() {
        return ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "own_transport_uri_ptr is null but length is non-zero",
        )
        .into();
    } else {
        let bytes =
            unsafe { std::slice::from_raw_parts(own_transport_uri_ptr, own_transport_uri_len) };
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                return ffi_error(
                    DEREC_CODE_FFI_BAD_PROTO,
                    "own_transport_uri is not valid UTF-8",
                )
                .into();
            }
        }
    };

    // Empty URI is the deferred-config path: the caller will call
    // `derec_protocol_set_own_transport` later, at which point
    // validation runs unconditionally. Non-empty URIs are validated
    // here so the protocol can't be constructed with a malformed or
    // downgraded endpoint that would then be propagated to peers
    // via pairing.
    let own_transport: crate::transport::TransportProtocol = if own_uri.is_empty() {
        // Sentinel deferred-config value. The empty URI will be
        // rejected by the validator the next time the protocol
        // actually needs to use it (e.g. on the first pair attempt).
        crate::transport::TransportProtocol::new(
            String::new(),
            derec_proto::Protocol::Https,
        )
    } else {
        match validate_transport(&own_uri, own_transport_protocol) {
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

    let unpair_ack_value = match unpair_ack {
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

    let replica_id_opt = if has_replica_id != 0 {
        Some(replica_id)
    } else {
        None
    };

    unsafe {
        construct_protocol(
            secret_id,
            own_transport,
            threshold,
            keep_versions_count,
            info,
            timeout_in_secs,
            auto_respond_on_failure != 0,
            unpair_ack_value,
            auto_reply_to != 0,
            auto_accept.into(),
            replica_id_opt,
            channel_store_cb,
            secret_store_cb,
            share_store_cb,
            user_secret_store_cb,
            state_store_cb,
            transport_cb,
        )
    }
}

/// Per-flow auto-accept policy as decoded from JSON by
/// [`derec_protocol_new_packed`]. Field-for-field equivalent of
/// [`DeRecAutoAcceptPolicy`], using `bool` instead of `u32` since JSON
/// has a native boolean type.
#[derive(serde::Deserialize)]
struct PackedAutoAcceptPolicy {
    pairing: bool,
    pre_pair: bool,
    store_share: bool,
    verify_share: bool,
    discovery: bool,
    get_share: bool,
    unpair: bool,
    update_channel_info: bool,
}

impl From<PackedAutoAcceptPolicy> for crate::protocol::AutoAcceptPolicy {
    fn from(p: PackedAutoAcceptPolicy) -> Self {
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

/// JSON configuration shape accepted by [`derec_protocol_new_packed`].
///
/// `secret_id` and `replica_id` are decimal strings rather than JSON
/// numbers: `u64` values above 2^53 lose precision once round-tripped
/// through JSON's `f64`-backed number type in common encoders
/// (including Go's `encoding/json`).
#[derive(serde::Deserialize)]
struct PackedProtocolConfig {
    secret_id: String,
    own_transport_uri: String,
    own_transport_protocol: i32,
    threshold: u32,
    keep_versions_count: u32,
    timeout_in_secs: u32,
    auto_respond_on_failure: bool,
    // 0 = Required, 1 = NotRequired.
    unpair_ack: i32,
    auto_reply_to: bool,
    auto_accept: PackedAutoAcceptPolicy,
    // Absent or `null` means "no replica id".
    #[serde(default)]
    replica_id: Option<String>,
}

/// Packed variant of [`derec_protocol_new`] for FFI callers that
/// cannot pass its 21 arguments in a single native call — e.g. Go via
/// `purego` (no cgo), which panics with "too many stack arguments"
/// past a handful of parameters. Scalar configuration is bundled into
/// a single JSON buffer; `communication_info` stays a separate proto
/// buffer (same wire format as [`derec_protocol_new`]); the 6
/// store/transport callback structs are still passed as individual
/// pointers, since purego marshals pointer-sized arguments natively.
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
///   "replica_id": null
/// }
/// ```
///
/// - `secret_id`: decimal-string `u64`.
/// - `own_transport_uri`: may be `""` for the deferred-config path
///   (same as [`derec_protocol_new`]); `derec_protocol_set_own_transport`
///   must be called before pairing in that case.
/// - `own_transport_protocol`: [`derec_proto::Protocol`] discriminant.
/// - `unpair_ack`: `0` = Required, `1` = NotRequired.
/// - `auto_accept`: field-for-field equivalent of
///   [`DeRecAutoAcceptPolicy`], booleans instead of `u32`.
/// - `replica_id`: decimal-string `u64`, or absent/`null` for "no
///   replica id".
///
/// # Safety
///
/// - `config_json_ptr` must be valid for reads of `config_json_len`
///   bytes.
/// - `communication_info_ptr` must be valid for reads of
///   `communication_info_len` bytes when the length is non-zero.
/// - The 6 callback pointers must satisfy the same requirements as
///   documented on [`derec_protocol_new`].
/// - The caller must invoke [`derec_protocol_free`] exactly once to
///   release the returned handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_new_packed(
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
    let config: PackedProtocolConfig = match serde_json::from_slice(json_bytes) {
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
                return ffi_error(DEREC_CODE_FFI_BAD_PROTO, "replica_id is not a valid u64")
                    .into();
            }
        },
        None => None,
    };

    // Empty URI is the deferred-config path; see
    // [`derec_protocol_new`] for the rationale.
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
            config.timeout_in_secs,
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

/// Release a handle previously returned by [`derec_protocol_new`]. Safe
/// to call with a null pointer.
///
/// # Safety
///
/// `handle` must satisfy ALL of:
///
/// - It is a pointer previously returned by [`derec_protocol_new`], or
///   it is null.
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
