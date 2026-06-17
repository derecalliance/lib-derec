// SPDX-License-Identifier: Apache-2.0

//! Event-loop entry points: `start` / `process` / `accept` / `reject`.
//! Each one drives the protocol's async core via the per-handle tokio
//! runtime and returns either a typed result or a JSON event array.

use super::DeRecProtocolHandle;
use crate::ffi::common::{empty_buffer, vec_into_buffer, DeRecBuffer};
use crate::ffi::error::{
    ffi_error, from_lib_error, success, DeRecError, DEREC_CODE_FFI_BAD_PROTO,
    DEREC_CODE_FFI_INVALID_ENUM, DEREC_CODE_FFI_NULL_PTR,
};
use crate::ffi::protocol::events::encode_events;
use crate::ffi::protocol::flow as flow_params;

/// Result type for [`derec_protocol_start`]. `has_channel_id` is `1`
/// only for the Pairing flow (which mints a new channel id); other
/// flows return `0` and the field is undefined.
#[repr(C)]
pub struct DeRecProtocolStartResult {
    pub error: DeRecError,
    pub has_channel_id: u32,
    pub channel_id: u64,
}

impl From<DeRecError> for DeRecProtocolStartResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            has_channel_id: 0,
            channel_id: 0,
        }
    }
}

/// Start a new flow. `flow_kind` matches the constants in
/// [`crate::ffi::protocol::flow`]. `params_json_*` is a UTF-8 JSON blob
/// shaped to the matching `*ParamsJson` struct in that module.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `params_json_ptr`/`params_json_len`
/// must describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_start(
    handle: *mut DeRecProtocolHandle,
    flow_kind: u32,
    params_json_ptr: *const u8,
    params_json_len: usize,
) -> DeRecProtocolStartResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }
    if params_json_len > 0 && params_json_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "params_json_ptr is null but len > 0").into();
    }
    let params_bytes = if params_json_len == 0 {
        b""[..].to_vec()
    } else {
        unsafe { std::slice::from_raw_parts(params_json_ptr, params_json_len) }.to_vec()
    };

    let flow = match flow_params::parse_flow(flow_kind, &params_bytes) {
        Ok(f) => f,
        Err(e) => return ffi_error(DEREC_CODE_FFI_BAD_PROTO, e).into(),
    };

    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h.runtime.block_on(inner.start(flow)) {
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
        Err(e) => from_lib_error(e).into(),
    }
}

/// Result type for entry points that return a `Vec<DeRecEvent>`.
#[repr(C)]
pub struct DeRecProtocolEventsResult {
    pub error: DeRecError,
    /// UTF-8 JSON array of events. See [`crate::ffi::protocol::events`]
    /// for the per-variant shape. Caller releases via
    /// [`crate::ffi::derec_free_buffer`].
    pub events_json: DeRecBuffer,
}

impl From<DeRecError> for DeRecProtocolEventsResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            events_json: empty_buffer(),
        }
    }
}

/// Process an inbound `DeRecMessage` envelope. See
/// [`crate::protocol::DeRecProtocol::process`].
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `message_ptr`/`message_len` must
/// describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_process(
    handle: *mut DeRecProtocolHandle,
    message_ptr: *const u8,
    message_len: usize,
) -> DeRecProtocolEventsResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }
    if message_len > 0 && message_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "message_ptr is null but len > 0").into();
    }
    let bytes = if message_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(message_ptr, message_len) }.to_vec()
    };

    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h.runtime.block_on(inner.process(&bytes)) {
        Ok(events) => {
            let json = encode_events(events);
            DeRecProtocolEventsResult {
                error: success(),
                events_json: vec_into_buffer(json),
            }
        }
        Err(e) => from_lib_error(e.source).into(),
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
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `action_ptr`/`action_len` must
/// describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_accept(
    handle: *mut DeRecProtocolHandle,
    action_ptr: *const u8,
    action_len: usize,
) -> DeRecProtocolEventsResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }
    if action_len == 0 || action_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "action_ptr is null or len == 0").into();
    }
    let bytes = unsafe { std::slice::from_raw_parts(action_ptr, action_len) };
    let action = match crate::protocol::pending_action_wire::deserialize(bytes) {
        Ok(a) => a,
        Err(e) => {
            return ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("PendingAction decode: {e}"),
            )
            .into();
        }
    };
    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h.runtime.block_on(inner.accept(action)) {
        Ok(events) => {
            let json = encode_events(events);
            DeRecProtocolEventsResult {
                error: success(),
                events_json: vec_into_buffer(json),
            }
        }
        Err(e) => from_lib_error(e).into(),
    }
}

/// Reject a pending action from an `ActionRequired` event. See
/// [`crate::protocol::DeRecProtocol::reject`]. `status` matches
/// `derec_proto::StatusEnum` and `memo_ptr`/`memo_len` is an optional
/// UTF-8 string body (`memo_len == 0` for absent).
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `action_ptr`/`action_len` must
/// describe a readable byte range.
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

    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h.runtime.block_on(inner.reject(action, status_enum, &memo)) {
        Ok(()) => success(),
        Err(e) => from_lib_error(e),
    }
}
