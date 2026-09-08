// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Runtime-mutable configuration entry points — counterpart to the
//! `DeRecProtocol::set_*` methods.

use std::collections::HashMap;

use super::DeRecProtocolHandle;
use crate::interop::ffi::common::{DeRecBuffer, empty_buffer, vec_into_buffer};
use crate::interop::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_NULL_PTR, DeRecError, ffi_error, from_lib_error,
    success,
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

/// Replace this node's endpoint **for one protocol**, leaving the others
/// alone. A node serves at most one endpoint per protocol, so the `(uri,
/// protocol)` pair identifies the entry it replaces; an entry for a protocol
/// not yet served is appended, and a replaced one keeps its position in the
/// preference order. See
/// [`crate::protocol::DeRecProtocol::set_own_transport`] for the changeover
/// discipline (keep the old endpoint up during the transition).
///
/// Superseded by [`derec_protocol_set_own_transports`], which takes the
/// whole preference list and is the only way to change *which* protocols
/// this node serves, or their order.
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
#[deprecated(
    since = "0.0.3",
    note = "use derec_protocol_set_own_transports, which takes the whole \
            preference list; removed at 0.0.5"
)]
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
    let validated_tp = match super::validate_transport(&uri, protocol) {
        Ok(tp) => tp,
        Err(e) => return e,
    };
    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match inner.set_own_transports([validated_tp]) {
        Ok(()) => success(),
        Err(e) => crate::interop::ffi::error::from_lib_error(e),
    }
}

/// Replace every endpoint this node advertises, in preference order.
///
/// The runtime counterpart to the `own_transports` array accepted by
/// [`super::derec_protocol_new`], and the way to change the whole set:
/// `derec_protocol_set_own_transport` replaces only the entry for the
/// protocol its URI names. A device serves at most one endpoint per
/// protocol, so this list is a preference order over distinct protocols and
/// two entries of the same protocol are rejected. Body is the same JSON
/// shape that config array uses — `[{"uri": "...", "protocol": 0}, ...]`.
///
/// Every entry is validated before any is stored, so a malformed URI
/// leaves the previous set intact rather than half-applied.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `json_ptr`/`json_len` must describe a
/// readable byte range. Concurrent calls on the same handle from
/// different threads are safe: the handle's internal mutex serializes
/// them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_set_own_transports(
    handle: *mut DeRecProtocolHandle,
    json_ptr: *const u8,
    json_len: usize,
) -> DeRecError {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null");
    }
    if json_len == 0 || json_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "json_ptr null or len == 0");
    }
    let bytes = unsafe { std::slice::from_raw_parts(json_ptr, json_len) };
    let entries: Vec<OwnTransportEntry> = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            return ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("invalid own_transports JSON: {e}"),
            );
        }
    };
    let mut validated = Vec::with_capacity(entries.len());
    for entry in entries {
        match super::validate_transport(&entry.uri, entry.protocol) {
            Ok(tp) => validated.push(tp),
            Err(e) => return e,
        }
    }
    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match inner.set_own_transports(validated) {
        Ok(()) => success(),
        Err(e) => from_lib_error(e),
    }
}

/// One entry of the array [`derec_protocol_set_own_transports`] accepts.
/// Same `{uri, protocol}` shape as the `own_transports` config array.
#[derive(serde::Deserialize)]
struct OwnTransportEntry {
    uri: String,
    protocol: i32,
}

/// Result type for [`derec_protocol_remove_expired_channels`].
#[repr(C)]
pub struct DeRecRemovedChannelsResult {
    pub error: DeRecError,
    /// On success, a heap-owned UTF-8 JSON array of removed channel ids as
    /// decimal strings — e.g. `["12","4096"]`. Decimal strings rather than
    /// JSON numbers because `u64` ids exceed `Number.MAX_SAFE_INTEGER`;
    /// this matches every other id crossing this boundary. Caller releases
    /// via [`crate::interop::ffi::common::derec_free_buffer`].
    pub channels: DeRecBuffer,
}

impl From<DeRecError> for DeRecRemovedChannelsResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            channels: empty_buffer(),
        }
    }
}

/// Remove `Pending` channels older than `older_than_secs`. See
/// [`crate::protocol::DeRecProtocol::remove_expired_channels`] for the
/// semantics, including the strict `>` age boundary.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. Concurrent calls on the same handle
/// from different threads are safe: the handle's internal mutex
/// serializes them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_remove_expired_channels(
    handle: *mut DeRecProtocolHandle,
    older_than_secs: u64,
) -> DeRecRemovedChannelsResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }
    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h
        .runtime
        .block_on(inner.remove_expired_channels(older_than_secs))
    {
        Ok(ids) => {
            let decimal: Vec<String> = ids.iter().map(|c| c.0.to_string()).collect();
            match serde_json::to_vec(&decimal) {
                Ok(bytes) => DeRecRemovedChannelsResult {
                    error: success(),
                    channels: vec_into_buffer(bytes),
                },
                Err(e) => ffi_error(
                    DEREC_CODE_FFI_BAD_PROTO,
                    format!("failed to encode removed channel ids: {e}"),
                )
                .into(),
            }
        }
        Err(e) => from_lib_error(e).into(),
    }
}
