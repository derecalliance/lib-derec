// SPDX-License-Identifier: Apache-2.0

//! Runtime-mutable configuration entry points — counterpart to the
//! `DeRecProtocol::set_*` methods.

use std::collections::HashMap;

use super::DeRecProtocolHandle;
use crate::ffi::error::{
    ffi_error, success, DeRecError, DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_NULL_PTR,
};

/// Replace this node's local `communication_info` map. Does not contact
/// peers — follow up with `start(FlowKind::UpdateChannelInfo)` to
/// propagate. The body is the same JSON wire shape used elsewhere on
/// the FFI: a UTF-8 JSON object with string keys + string values.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `info_json_ptr`/`info_json_len` must
/// describe a readable byte range. Concurrent calls on the same
/// handle from different threads are safe: the handle's internal
/// mutex serializes them.
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
    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    inner.set_communication_info(info);
    success()
}

/// Replace this node's local transport endpoint. See
/// [`crate::protocol::DeRecProtocol::set_own_transport`] for the
/// changeover discipline (keep the old endpoint up during the
/// transition).
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `uri_ptr`/`uri_len` must describe a
/// readable byte range. The `(uri, protocol)` pair is validated via
/// [`super::validate_transport`] before it is stored — see that
/// function's docs for the structural rules (length cap, scheme
/// match, enum discriminant). Concurrent calls on the same handle
/// from different threads are safe: the handle's internal mutex
/// serializes them.
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
    // Validate before storing — `validate_transport` runs both the
    // protocol-enum check and the URI rules, so a downgraded scheme
    // (e.g. `http://` carried with `Protocol::Https`) is rejected
    // here rather than silently propagated to peers.
    if let Err(e) = super::validate_transport(&uri, protocol) {
        return e;
    }
    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    inner.set_own_transport(uri);
    success()
}
