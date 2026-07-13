// SPDX-License-Identifier: Apache-2.0

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

    let info: HashMap<String, String> = if communication_info_len == 0 {
        HashMap::new()
    } else {
        if communication_info_ptr.is_null() {
            return ffi_error(
                DEREC_CODE_FFI_NULL_PTR,
                "communication_info_ptr is null but length is non-zero",
            )
            .into();
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(communication_info_ptr, communication_info_len) };
        match derec_proto::CommunicationInfo::decode(bytes) {
            Ok(c) => c
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
                .collect(),
            Err(_) => {
                return ffi_error(
                    DEREC_CODE_FFI_BAD_PROTO,
                    "communication_info is not a valid CommunicationInfo proto",
                )
                .into();
            }
        }
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
        .with_communication_info(info)
        .with_timeout(Duration::from_secs(u64::from(timeout_in_secs.max(1))))
        .with_auto_respond_on_failure(auto_respond_on_failure != 0)
        .with_unpair_ack(unpair_ack_value)
        .with_auto_reply_to(auto_reply_to != 0)
        .with_auto_accept(auto_accept.into());

    if has_replica_id != 0 {
        builder = builder.with_replica_id(replica_id);
    }

    let inner = match builder.build() {
        Ok(p) => p,
        Err(e) => return crate::ffi::error::from_lib_error(e).into(),
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .build() {
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
