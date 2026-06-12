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
    DotnetTransport, DotnetUserSecretStore, SecretStoreCallbacks, ShareStoreCallbacks,
    TransportCallbacks, UserSecretStoreCallbacks,
};
use crate::protocol::DeRecProtocolBuilder;
use derec_proto::TransportProtocol;

mod config;
mod flow;
mod pairing;

pub(super) type Protocol = crate::protocol::DeRecProtocol<
    DotnetChannelStore,
    DotnetShareStore,
    DotnetSecretStore,
    DotnetUserSecretStore,
    DotnetTransport,
>;

/// Opaque handle returned by [`derec_protocol_new`] and consumed by every
/// other entry point in this module. Holds the protocol instance + the
/// per-handle tokio runtime used to drive the async core synchronously.
pub struct DeRecProtocolHandle {
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) inner: Protocol,
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
    // `has_replica_id`: 0 = unset, 1 = use `replica_id` value.
    has_replica_id: u32,
    replica_id: u64,
) -> DeRecProtocolNewResult {
    if channel_store_cb.is_null()
        || secret_store_cb.is_null()
        || share_store_cb.is_null()
        || user_secret_store_cb.is_null()
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

    let own_transport = TransportProtocol {
        uri: own_uri,
        protocol: own_transport_protocol,
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
    let transport = DotnetTransport {
        cb: unsafe { std::ptr::read(transport_cb) },
    };

    let mut builder = DeRecProtocolBuilder::new(secret_id)
        .with_channel_store(channel_store)
        .with_share_store(share_store)
        .with_secret_store(secret_store)
        .with_user_secret_store(user_secret_store)
        .with_transport(transport)
        .with_own_transport(own_transport)
        .with_threshold(threshold as usize)
        .with_keep_versions_count(keep_versions_count as usize)
        .with_communication_info(info)
        .with_timeout(Duration::from_secs(u64::from(timeout_in_secs.max(1))))
        .with_auto_respond_on_failure(auto_respond_on_failure != 0)
        .with_unpair_ack(unpair_ack_value)
        .with_auto_reply_to(auto_reply_to != 0);

    if has_replica_id != 0 {
        builder = builder.with_replica_id(replica_id);
    }

    let inner = builder.build();

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

    let handle = Box::new(DeRecProtocolHandle { runtime, inner });
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
/// `handle` must be a pointer previously returned by [`derec_protocol_new`]
/// and must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_free(handle: *mut DeRecProtocolHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}
