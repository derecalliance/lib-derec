// SPDX-License-Identifier: Apache-2.0

//! Opaque [`DeRecProtocolHandle`] + entry points exposed across the C
//! FFI. Each `derec_protocol_*` function in this module is the FFI
//! counterpart of a method on [`crate::protocol::DeRecProtocol`].

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::Duration;

use prost::Message as _;

use crate::ffi::common::{empty_buffer, vec_into_buffer, DeRecBuffer};
use crate::ffi::error::{
    ffi_error, from_lib_error, success, DeRecError, DEREC_CODE_FFI_BAD_PROTO,
    DEREC_CODE_FFI_INVALID_ENUM, DEREC_CODE_FFI_NULL_PTR,
};
use crate::ffi::protocol::events::encode_events;
use crate::ffi::protocol::flow;
use crate::ffi::protocol::stores::{
    ChannelStoreCallbacks, DotnetChannelStore, DotnetSecretStore, DotnetShareStore,
    DotnetTransport, SecretStoreCallbacks, ShareStoreCallbacks, TransportCallbacks,
};
use crate::protocol::DeRecProtocolBuilder;
use crate::types::ChannelId;
use derec_proto::TransportProtocol;

type Protocol = crate::protocol::DeRecProtocol<
    DotnetChannelStore,
    DotnetShareStore,
    DotnetSecretStore,
    DotnetTransport,
>;

/// Opaque handle returned by [`derec_protocol_new`] and consumed by every
/// other entry point in this module. Holds the protocol instance + the
/// per-handle tokio runtime used to drive the async core synchronously.
pub struct DeRecProtocolHandle {
    runtime: tokio::runtime::Runtime,
    inner: Protocol,
}

/// Result type for [`derec_protocol_new`].
#[repr(C)]
pub struct DeRecProtocolNewResult {
    pub error: DeRecError,
    /// On success, the opaque handle. On error, null.
    pub handle: *mut DeRecProtocolHandle,
}

fn new_result_err(error: DeRecError) -> DeRecProtocolNewResult {
    DeRecProtocolNewResult {
        error,
        handle: std::ptr::null_mut(),
    }
}

/// Construct a new [`DeRecProtocol`] instance bound to the caller-supplied
/// store/transport callbacks.
///
/// Buffer-passing convention for the callbacks is documented on each
/// `*Callbacks` struct in [`super::stores`].
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
    channel_store_cb: *const ChannelStoreCallbacks,
    secret_store_cb: *const SecretStoreCallbacks,
    share_store_cb: *const ShareStoreCallbacks,
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
        || transport_cb.is_null()
    {
        return new_result_err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "store/transport callback pointer is null",
        ));
    }

    let own_uri = if own_transport_uri_len == 0 {
        String::new()
    } else if own_transport_uri_ptr.is_null() {
        return new_result_err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "own_transport_uri_ptr is null but length is non-zero",
        ));
    } else {
        let bytes =
            unsafe { std::slice::from_raw_parts(own_transport_uri_ptr, own_transport_uri_len) };
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                return new_result_err(ffi_error(
                    DEREC_CODE_FFI_BAD_PROTO,
                    "own_transport_uri is not valid UTF-8",
                ));
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
            return new_result_err(ffi_error(
                DEREC_CODE_FFI_NULL_PTR,
                "communication_info_ptr is null but length is non-zero",
            ));
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(communication_info_ptr, communication_info_len)
        };
        match derec_proto::CommunicationInfo::decode(bytes) {
            Ok(c) => c
                .communication_info_entries
                .into_iter()
                .filter_map(|e| {
                    let s = match e.value? {
                        derec_proto::communication_info_key_value::Value::StringValue(s) => s,
                        // Skip binary entries — the core protocol's
                        // `communication_info` map is `<String, String>`,
                        // so bytes-only entries have nowhere to land.
                        derec_proto::communication_info_key_value::Value::BytesValue(_) => {
                            return None;
                        }
                    };
                    Some((e.key, s))
                })
                .collect(),
            Err(_) => {
                return new_result_err(ffi_error(
                    DEREC_CODE_FFI_BAD_PROTO,
                    "communication_info is not a valid CommunicationInfo proto",
                ));
            }
        }
    };

    let unpair_ack_value = match unpair_ack {
        0 => crate::protocol::UnpairAck::Required,
        1 => crate::protocol::UnpairAck::NotRequired,
        other => {
            return new_result_err(ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid unpair_ack: {other}"),
            ));
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
    let transport = DotnetTransport {
        cb: unsafe { std::ptr::read(transport_cb) },
    };

    let mut builder = DeRecProtocolBuilder::new()
        .with_channel_store(channel_store)
        .with_share_store(share_store)
        .with_secret_store(secret_store)
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
            return new_result_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to build tokio runtime: {e}"),
            ));
        }
    };

    let handle = Box::new(DeRecProtocolHandle { runtime, inner });
    DeRecProtocolNewResult {
        error: success(),
        handle: Box::into_raw(handle),
    }
}

/// Release a handle previously returned by [`derec_protocol_new`].
///
/// Safe to call with a null pointer.
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

/// Result type for fingerprint accessors.
#[repr(C)]
pub struct DeRecProtocolFingerprintResult {
    pub error: DeRecError,
    /// On success, owned C string (heap-allocated). Caller releases via
    /// [`crate::ffi::common::derec_free_string`].
    pub fingerprint: *mut c_char,
}

fn fingerprint_err(error: DeRecError) -> DeRecProtocolFingerprintResult {
    DeRecProtocolFingerprintResult {
        error,
        fingerprint: std::ptr::null_mut(),
    }
}

/// Derive the human-readable fingerprint for a paired channel. See
/// [`crate::protocol::DeRecProtocol::get_fingerprint`].
///
/// # Safety
///
/// `handle` must be a valid pointer returned by [`derec_protocol_new`]
/// and must not be used concurrently from other threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_get_fingerprint(
    handle: *mut DeRecProtocolHandle,
    channel_id: u64,
) -> DeRecProtocolFingerprintResult {
    if handle.is_null() {
        return fingerprint_err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "handle is null",
        ));
    }
    let h = unsafe { &mut *handle };
    let result = h
        .runtime
        .block_on(h.inner.get_fingerprint(ChannelId(channel_id)));
    match result {
        Ok(s) => match CString::new(s) {
            Ok(c) => DeRecProtocolFingerprintResult {
                error: success(),
                fingerprint: c.into_raw(),
            },
            Err(_) => fingerprint_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                "fingerprint contains NUL byte",
            )),
        },
        Err(e) => fingerprint_err(from_lib_error(e)),
    }
}

/// Verify a fingerprint against the channel's locally-derived one. See
/// [`crate::protocol::DeRecProtocol::verify_fingerprint`]. Writes
/// `*out_matched = 1` on match, `0` on mismatch. Returns a non-OK error
/// envelope on backend failure.
///
/// # Safety
///
/// `handle` and `out_matched` must be valid pointers. `fingerprint_ptr`
/// must be a valid pointer to a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_verify_fingerprint(
    handle: *mut DeRecProtocolHandle,
    channel_id: u64,
    fingerprint_ptr: *const c_char,
    out_matched: *mut u32,
) -> DeRecError {
    if handle.is_null() || fingerprint_ptr.is_null() || out_matched.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "null pointer in verify_fingerprint");
    }
    let fingerprint = match unsafe { CStr::from_ptr(fingerprint_ptr) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => {
            return ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                "fingerprint is not valid UTF-8",
            );
        }
    };
    let h = unsafe { &mut *handle };
    match h
        .runtime
        .block_on(h.inner.verify_fingerprint(ChannelId(channel_id), &fingerprint))
    {
        Ok(matched) => {
            unsafe {
                *out_matched = if matched { 1 } else { 0 };
            }
            success()
        }
        Err(e) => from_lib_error(e),
    }
}

/// Replace this node's local `communication_info` map. Does not contact
/// peers — follow up with `start(FlowKind::UpdateChannelInfo)` to
/// propagate. The body is the same JSON wire shape used elsewhere on
/// the FFI: a UTF-8 JSON object with string keys + string values.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by [`derec_protocol_new`].
/// `info_json_ptr`/`info_json_len` must describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_set_communication_info(
    handle: *mut DeRecProtocolHandle,
    info_json_ptr: *const u8,
    info_json_len: usize,
) -> DeRecError {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null");
    }
    let info: HashMap<String, String> = if info_json_len == 0 {
        HashMap::new()
    } else if info_json_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "info_json_ptr null with len > 0");
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(info_json_ptr, info_json_len) };
        match serde_json::from_slice(bytes) {
            Ok(m) => m,
            Err(e) => {
                return ffi_error(
                    DEREC_CODE_FFI_BAD_PROTO,
                    format!("invalid communication_info JSON: {e}"),
                );
            }
        }
    };
    let h = unsafe { &mut *handle };
    h.inner.set_communication_info(info);
    success()
}

/// Replace this node's local transport endpoint. See
/// [`crate::protocol::DeRecProtocol::set_own_transport`] for the
/// changeover discipline (keep the old endpoint up during the
/// transition).
///
/// # Safety
///
/// `handle` must be a valid pointer returned by [`derec_protocol_new`].
/// `uri_ptr`/`uri_len` must describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_set_own_transport(
    handle: *mut DeRecProtocolHandle,
    uri_ptr: *const u8,
    uri_len: usize,
    protocol: i32,
) -> DeRecError {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null");
    }
    if uri_len == 0 || uri_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "uri_ptr null or len == 0");
    }
    let uri = {
        let bytes = unsafe { std::slice::from_raw_parts(uri_ptr, uri_len) };
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => return ffi_error(DEREC_CODE_FFI_BAD_PROTO, "uri is not valid UTF-8"),
        }
    };
    let h = unsafe { &mut *handle };
    h.inner.set_own_transport(TransportProtocol { uri, protocol });
    success()
}

/// Result type for [`derec_protocol_create_contact`].
#[repr(C)]
pub struct DeRecProtocolCreateContactResult {
    pub error: DeRecError,
    /// prost-encoded [`derec_proto::ContactMessage`] on success.
    /// Caller releases via [`crate::ffi::derec_free_buffer`].
    pub contact_wire_bytes: DeRecBuffer,
}

fn create_contact_err(error: DeRecError) -> DeRecProtocolCreateContactResult {
    DeRecProtocolCreateContactResult {
        error,
        contact_wire_bytes: empty_buffer(),
    }
}

/// Generate an out-of-band contact message used to bootstrap pairing.
/// See [`crate::protocol::DeRecProtocol::create_contact`].
///
/// `has_channel_id == 0` lets the library mint the channel id; `1`
/// supplies it via `channel_id`.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by [`derec_protocol_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_create_contact(
    handle: *mut DeRecProtocolHandle,
    has_channel_id: u32,
    channel_id: u64,
    contact_mode: i32,
) -> DeRecProtocolCreateContactResult {
    if handle.is_null() {
        return create_contact_err(ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null"));
    }
    let mode = match derec_proto::ContactMode::try_from(contact_mode) {
        Ok(m) => m,
        Err(_) => {
            return create_contact_err(ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid ContactMode: {contact_mode}"),
            ));
        }
    };
    let id_arg: Option<ChannelId> = if has_channel_id != 0 {
        Some(ChannelId(channel_id))
    } else {
        None
    };
    let h = unsafe { &mut *handle };
    match h.runtime.block_on(h.inner.create_contact(id_arg, mode)) {
        Ok(contact) => DeRecProtocolCreateContactResult {
            error: success(),
            contact_wire_bytes: vec_into_buffer(contact.encode_to_vec()),
        },
        Err(e) => create_contact_err(from_lib_error(e)),
    }
}

/// Result type for [`derec_protocol_start`].
///
/// `has_channel_id` is `1` only for the Pairing flow (which mints a new
/// channel id); other flows return `0` and the field is undefined.
#[repr(C)]
pub struct DeRecProtocolStartResult {
    pub error: DeRecError,
    pub has_channel_id: u32,
    pub channel_id: u64,
}

fn start_err(error: DeRecError) -> DeRecProtocolStartResult {
    DeRecProtocolStartResult {
        error,
        has_channel_id: 0,
        channel_id: 0,
    }
}

/// Start a new flow. `flow_kind` matches the constants in
/// [`crate::ffi::protocol::flow`]. `params_json_*` is a UTF-8 JSON
/// blob shaped to the matching `*ParamsJson` struct in that module —
/// for chunk 7b only `Pairing` (flow_kind = 0) is supported.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by [`derec_protocol_new`].
/// `params_json_ptr`/`params_json_len` must describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_start(
    handle: *mut DeRecProtocolHandle,
    flow_kind: u32,
    params_json_ptr: *const u8,
    params_json_len: usize,
) -> DeRecProtocolStartResult {
    if handle.is_null() {
        return start_err(ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null"));
    }
    if params_json_len > 0 && params_json_ptr.is_null() {
        return start_err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "params_json_ptr is null but len > 0",
        ));
    }
    let params_bytes = if params_json_len == 0 {
        b""[..].to_vec()
    } else {
        unsafe { std::slice::from_raw_parts(params_json_ptr, params_json_len) }.to_vec()
    };

    let flow = match flow::parse_flow(flow_kind, &params_bytes) {
        Ok(f) => f,
        Err(e) => return start_err(ffi_error(DEREC_CODE_FFI_BAD_PROTO, e)),
    };

    let h = unsafe { &mut *handle };
    match h.runtime.block_on(h.inner.start(flow)) {
        Ok(Some(id)) => DeRecProtocolStartResult {
            error: success(),
            has_channel_id: 1,
            channel_id: id,
        },
        Ok(None) => DeRecProtocolStartResult {
            error: success(),
            has_channel_id: 0,
            channel_id: 0,
        },
        Err(e) => start_err(from_lib_error(e)),
    }
}

/// Result type for entry points that return a `Vec<DeRecEvent>`.
#[repr(C)]
pub struct DeRecProtocolEventsResult {
    pub error: DeRecError,
    /// UTF-8 JSON array of events. See
    /// [`crate::ffi::protocol::events`] for the per-variant shape.
    /// Caller releases via [`crate::ffi::derec_free_buffer`].
    pub events_json: DeRecBuffer,
}

fn events_err(error: DeRecError) -> DeRecProtocolEventsResult {
    DeRecProtocolEventsResult {
        error,
        events_json: empty_buffer(),
    }
}

/// Process an inbound `DeRecMessage` envelope. See
/// [`crate::protocol::DeRecProtocol::process`].
///
/// # Safety
///
/// `handle` must be a valid pointer returned by [`derec_protocol_new`].
/// `message_ptr`/`message_len` must describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_process(
    handle: *mut DeRecProtocolHandle,
    message_ptr: *const u8,
    message_len: usize,
) -> DeRecProtocolEventsResult {
    if handle.is_null() {
        return events_err(ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null"));
    }
    if message_len > 0 && message_ptr.is_null() {
        return events_err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "message_ptr is null but len > 0",
        ));
    }
    let bytes = if message_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(message_ptr, message_len) }.to_vec()
    };

    let h = unsafe { &mut *handle };
    match h.runtime.block_on(h.inner.process(&bytes)) {
        Ok(events) => {
            let json = encode_events(events);
            DeRecProtocolEventsResult {
                error: success(),
                events_json: vec_into_buffer(json),
            }
        }
        Err(e) => events_err(from_lib_error(e.source)),
    }
}

/// Accept a pending action from an `ActionRequired` event. See
/// [`crate::protocol::DeRecProtocol::accept`]. The `action_bytes` blob
/// is the exact payload the caller received in the event — the FFI
/// wire format is the encoding produced by
/// [`crate::protocol::pending_action_wire::serialize`].
///
/// # Safety
///
/// `handle` must be a valid pointer returned by [`derec_protocol_new`].
/// `action_ptr`/`action_len` must describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_accept(
    handle: *mut DeRecProtocolHandle,
    action_ptr: *const u8,
    action_len: usize,
) -> DeRecProtocolEventsResult {
    if handle.is_null() {
        return events_err(ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null"));
    }
    if action_len == 0 || action_ptr.is_null() {
        return events_err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "action_ptr is null or len == 0",
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(action_ptr, action_len) };
    let action = match crate::protocol::pending_action_wire::deserialize(bytes) {
        Ok(a) => a,
        Err(e) => {
            return events_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("PendingAction decode: {e}"),
            ));
        }
    };
    let h = unsafe { &mut *handle };
    match h.runtime.block_on(h.inner.accept(action)) {
        Ok(events) => {
            let json = encode_events(events);
            DeRecProtocolEventsResult {
                error: success(),
                events_json: vec_into_buffer(json),
            }
        }
        Err(e) => events_err(from_lib_error(e)),
    }
}

/// Reject a pending action from an `ActionRequired` event. See
/// [`crate::protocol::DeRecProtocol::reject`]. `status` matches
/// `derec_proto::StatusEnum` and `memo_ptr`/`memo_len` is an optional
/// UTF-8 string body (`memo_len == 0` for absent).
///
/// # Safety
///
/// `handle` must be a valid pointer returned by [`derec_protocol_new`].
/// `action_ptr`/`action_len` must describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_reject(
    handle: *mut DeRecProtocolHandle,
    action_ptr: *const u8,
    action_len: usize,
    status: i32,
    memo_ptr: *const u8,
    memo_len: usize,
) -> DeRecError {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null");
    }
    if action_len == 0 || action_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "action_ptr is null or len == 0");
    }
    let bytes = unsafe { std::slice::from_raw_parts(action_ptr, action_len) };
    let action = match crate::protocol::pending_action_wire::deserialize(bytes) {
        Ok(a) => a,
        Err(e) => {
            return ffi_error(DEREC_CODE_FFI_BAD_PROTO, format!("PendingAction decode: {e}"));
        }
    };
    let memo = if memo_len == 0 {
        String::new()
    } else if memo_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "memo_ptr is null but len > 0");
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(memo_ptr, memo_len) };
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => return ffi_error(DEREC_CODE_FFI_BAD_PROTO, "memo is not valid UTF-8"),
        }
    };

    let status_enum = match derec_proto::StatusEnum::try_from(status) {
        Ok(s) => s,
        Err(_) => {
            return ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid StatusEnum: {status}"),
            );
        }
    };

    let h = unsafe { &mut *handle };
    match h.runtime.block_on(h.inner.reject(action, status_enum, &memo)) {
        Ok(()) => success(),
        Err(e) => from_lib_error(e),
    }
}

