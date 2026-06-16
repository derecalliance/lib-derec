// SPDX-License-Identifier: Apache-2.0

//! Pairing-flow entry points: contact creation and the
//! fingerprint accessors that gate replica channel transitions.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use prost::Message as _;

use super::DeRecProtocolHandle;
use crate::ffi::common::{empty_buffer, vec_into_buffer, DeRecBuffer};
use crate::ffi::error::{
    ffi_error, from_lib_error, success, DeRecError, DEREC_CODE_FFI_BAD_PROTO,
    DEREC_CODE_FFI_INVALID_ENUM, DEREC_CODE_FFI_NULL_PTR,
};
use crate::types::ChannelId;

/// Result type for fingerprint accessors.
#[repr(C)]
pub struct DeRecProtocolFingerprintResult {
    pub error: DeRecError,
    /// On success, owned C string (heap-allocated). Caller releases via
    /// [`crate::ffi::common::derec_free_string`].
    pub fingerprint: *mut c_char,
}

impl From<DeRecError> for DeRecProtocolFingerprintResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            fingerprint: std::ptr::null_mut(),
        }
    }
}

/// Derive the human-readable fingerprint for a paired channel. See
/// [`crate::protocol::DeRecProtocol::get_fingerprint`].
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`] and must not be used concurrently from
/// other threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_get_fingerprint(
    handle: *mut DeRecProtocolHandle,
    channel_id: u64,
) -> DeRecProtocolFingerprintResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }
    let h = unsafe { &*handle };
    let inner = h.lock_inner();
    let result = h
        .runtime
        .block_on(inner.get_fingerprint(ChannelId(channel_id)));
    match result {
        Ok(s) => match CString::new(s) {
            Ok(c) => DeRecProtocolFingerprintResult {
                error: success(),
                fingerprint: c.into_raw(),
            },
            Err(_) => ffi_error(DEREC_CODE_FFI_BAD_PROTO, "fingerprint contains NUL byte").into(),
        },
        Err(e) => from_lib_error(e).into(),
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
            return ffi_error(DEREC_CODE_FFI_BAD_PROTO, "fingerprint is not valid UTF-8");
        }
    };
    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h
        .runtime
        .block_on(inner.verify_fingerprint(ChannelId(channel_id), &fingerprint))
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

/// Result type for [`derec_protocol_create_contact`].
#[repr(C)]
pub struct DeRecProtocolCreateContactResult {
    pub error: DeRecError,
    /// prost-encoded [`derec_proto::ContactMessage`] on success.
    /// Caller releases via [`crate::ffi::derec_free_buffer`].
    pub contact_wire_bytes: DeRecBuffer,
}

impl From<DeRecError> for DeRecProtocolCreateContactResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            contact_wire_bytes: empty_buffer(),
        }
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
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_create_contact(
    handle: *mut DeRecProtocolHandle,
    has_channel_id: u32,
    channel_id: u64,
    contact_mode: i32,
) -> DeRecProtocolCreateContactResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }
    let mode = match derec_proto::ContactMode::try_from(contact_mode) {
        Ok(m) => m,
        Err(_) => {
            return ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid ContactMode: {contact_mode}"),
            )
            .into();
        }
    };
    let id_arg: Option<ChannelId> = if has_channel_id != 0 {
        Some(ChannelId(channel_id))
    } else {
        None
    };
    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h.runtime.block_on(inner.create_contact(id_arg, mode)) {
        Ok(contact) => DeRecProtocolCreateContactResult {
            error: success(),
            contact_wire_bytes: vec_into_buffer(contact.encode_to_vec()),
        },
        Err(e) => from_lib_error(e).into(),
    }
}
