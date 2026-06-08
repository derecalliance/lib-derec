// SPDX-License-Identifier: Apache-2.0

//! Core C ABI primitives shared by all DeRec FFI flows.
//!
//! Foreign callers interact with the SDK through three concerns documented
//! here:
//!
//! - [`DeRecBuffer`] for heap-owned byte buffers
//! - [`derec_free_buffer`] / [`derec_free_string`] for releasing them
//! - the typed-error envelope in [`crate::ffi::error`]
//!
//! Protocol semantics live in `library/src/primitives/*` and are not repeated
//! here. Per-flow module docs cover only FFI-specific concerns (custom binary
//! formats, chained-bytes contracts, etc.).

use std::ffi::{CString, c_char};

#[repr(C)]
pub struct DeRecBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

/// Releases a [`DeRecBuffer`] previously returned by the SDK.
///
/// Safe to call with a null pointer.
///
/// # Safety
///
/// `ptr` must have been allocated by the DeRec SDK and `len` must match the
/// original allocation length.
#[unsafe(no_mangle)]
pub extern "C" fn derec_free_buffer(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

/// Releases a standalone C string previously returned by the SDK.
///
/// For strings owned by a [`crate::ffi::error::DeRecError`], use
/// [`crate::ffi::error::derec_free_error`] which releases both owned strings
/// in one call. Safe to call with a null pointer.
///
/// # Safety
///
/// `ptr` must have been allocated by the DeRec SDK.
#[unsafe(no_mangle)]
pub extern "C" fn derec_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(ptr));
    }
}

pub(crate) fn empty_buffer() -> DeRecBuffer {
    DeRecBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
    }
}

pub(crate) fn vec_into_buffer(mut data: Vec<u8>) -> DeRecBuffer {
    let ptr = data.as_mut_ptr();
    let len = data.len();
    std::mem::forget(data);
    DeRecBuffer { ptr, len }
}

pub(crate) fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("length exceeds u32::MAX");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn read_exact<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], String> {
    if input.len() < len {
        return Err("unexpected end of input".to_string());
    }
    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

pub(crate) fn read_u32_le(input: &mut &[u8]) -> Result<u32, String> {
    let bytes = read_exact(input, 4)?;
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| "failed to read u32".to_string())?;
    Ok(u32::from_le_bytes(array))
}

pub(crate) fn read_len_prefixed_vec(input: &mut &[u8]) -> Result<Vec<u8>, String> {
    let len = read_u32_le(input)? as usize;
    let bytes = read_exact(input, len)?;
    Ok(bytes.to_vec())
}

/// Decode an optional `TransportProtocol` (proto-encoded) from raw FFI bytes.
///
/// `len == 0` (or a null pointer with zero length) signals "absent", which
/// is how request bodies express `reply_to: None`. A non-zero length plus
/// null pointer is treated as an error. Used by the FFI `produce_*_request`
/// surfaces to thread `reply_to` into the corresponding primitive.
pub(crate) fn parse_optional_transport_protocol(
    ptr: *const u8,
    len: usize,
) -> Result<Option<derec_proto::TransportProtocol>, crate::ffi::error::DeRecError> {
    use crate::ffi::error::{DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_NULL_PTR, ffi_error};
    use prost::Message as _;

    if len == 0 {
        return Ok(None);
    }
    if ptr.is_null() {
        return Err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "reply_to_ptr is null but reply_to_len is non-zero",
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    derec_proto::TransportProtocol::decode(bytes)
        .map(Some)
        .map_err(|e| {
            ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode reply_to TransportProtocol: {e}"),
            )
        })
}
