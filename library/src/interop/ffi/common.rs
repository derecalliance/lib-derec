// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Core C ABI primitives shared by all DeRec FFI flows.
//!
//! Foreign callers interact with the SDK through three concerns documented
//! here:
//!
//! - [`DeRecBuffer`] for heap-owned byte buffers
//! - [`derec_free_buffer`] / [`derec_free_string`] for releasing them
//! - the typed-error envelope in [`crate::interop::ffi::error`]
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
/// For strings owned by a [`crate::interop::ffi::error::DeRecError`], use
/// [`crate::interop::ffi::error::derec_free_error`] which releases both owned strings
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

/// Decode a length-delimited `TransportProtocol` sequence from raw FFI bytes:
/// each entry preceded by its protobuf varint byte length, the same framing
/// protobuf uses for a repeated embedded message field.
///
/// `len == 0` (or a null pointer with zero length) yields an empty list. That
/// is how request bodies express "no reply-to override", which is legitimate
/// rather than an error: absence means "route to the endpoints already on
/// file for this channel". A non-zero length plus null pointer is an error.
/// Used by the FFI `produce_*_request` surfaces to thread `reply_to` into the
/// corresponding primitive.
///
/// Every entry is validated with
/// [`crate::extensions::transport_protocol::TransportProtocolExt::validate`], so callers that
/// reach the library through FFI cannot smuggle a mismatched-scheme or
/// otherwise malformed endpoint past the seam. Mirrors the validation
/// applied at every primitive `extract` site, keeping the rejection
/// semantics uniform across SDKs.
pub(crate) fn parse_transport_protocol_list(
    ptr: *const u8,
    len: usize,
    field: &str,
) -> Result<Vec<derec_proto::TransportProtocol>, crate::interop::ffi::error::DeRecError> {
    use crate::extensions::transport_protocol::TransportProtocolExt as _;
    use crate::interop::ffi::error::{
        DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_NULL_PTR, ffi_error, from_lib_error,
    };
    use prost::Message as _;

    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            format!("{field} is null but its length is non-zero"),
        ));
    }

    let mut bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let entry_len = prost::encoding::decode_varint(&mut bytes).map_err(|_| {
            ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("{field} has a malformed length prefix"),
            )
        })? as usize;
        if entry_len > bytes.len() {
            return Err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("{field} length prefix overruns the buffer"),
            ));
        }
        let (entry, rest) = bytes.split_at(entry_len);
        bytes = rest;

        let tp = derec_proto::TransportProtocol::decode(entry).map_err(|_| {
            ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("{field} contains an invalid TransportProtocol"),
            )
        })?;
        tp.validate()
            .map_err(|e| from_lib_error(crate::Error::Transport(e)))?;
        out.push(tp);
    }
    Ok(out)
}
