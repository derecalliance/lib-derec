//! Common C FFI types and utilities used across the DeRec SDK.
//!
//! This module defines the core ABI primitives and helper functions that all
//! FFI-exposed flows (pairing, sharing, recovery, verification) rely on.
//!
//! It is responsible for:
//!
//! - Representing buffers and status values in a C-compatible way
//! - Managing memory ownership across the FFI boundary
//! - Providing serialization helpers for custom FFI byte formats
//! - Providing deserialization helpers for internal decoding
//!
//! # Core Concepts
//!
//! ## Buffers
//!
//! Binary data is passed across the FFI boundary using [`DeRecBuffer`]:
//!
//! - `ptr`: pointer to heap-allocated memory
//! - `len`: length of the buffer in bytes
//!
//! Ownership rules:
//!
//! - Buffers returned by the Rust SDK are owned by the caller
//! - The caller **must** free them using [`derec_free_buffer`]
//!
//! ## Status Handling
//!
//! All fallible FFI functions return a [`DeRecStatus`] alongside their outputs:
//!
//! - `code == 0` → success
//! - `code != 0` → error
//! - `message` → optional null-terminated error string
//!
//! Ownership rules:
//!
//! - Error messages are heap-allocated C strings
//! - The caller **must** free them using [`derec_free_string`]
//!
//! ## Serialization Helpers
//!
//! This module provides internal helpers to encode/decode simple binary formats
//! used by the FFI layer:
//!
//! - Little-endian integer encoding (`u32`, `u64`)
//! - Length-prefixed byte sequences
//! - Optional fields with presence tags
//!
//! These formats are **not part of the DeRec protocol itself**, but rather an
//! implementation detail of the FFI boundary.
//!
//! # Safety Model
//!
//! - All exported functions validate null pointers before dereferencing
//! - Internal helpers assume valid input once inside Rust
//! - Callers must respect pointer/length invariants when invoking FFI functions
//!
//! # Notes
//!
//! - This module is shared by all FFI submodules
//! - Most helper functions are `pub(crate)` and not exposed directly over FFI
//! - Memory management correctness is critical when integrating with C or other languages

use std::ffi::{CString, c_char};

/// C-compatible buffer used to transfer binary data across the FFI boundary.
///
/// This struct represents a heap-allocated byte slice.
///
/// # Fields
///
/// - `ptr`: Pointer to the start of the buffer
/// - `len`: Length of the buffer in bytes
///
/// # Ownership
///
/// - Buffers returned from Rust are owned by the caller
/// - The caller must free them using [`derec_free_buffer`]
///
/// # Safety
///
/// - `ptr` must either be null or point to `len` valid bytes
/// - After calling [`derec_free_buffer`], the pointer must not be reused
#[repr(C)]
pub struct DeRecBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

/// C-compatible status returned by all fallible FFI functions.
///
/// # Fields
///
/// - `code`: Status code (`0` = success, non-zero = error)
/// - `message`: Optional null-terminated error string
///
/// # Ownership
///
/// - On error, `message` is heap-allocated
/// - The caller must free it using [`derec_free_string`]
///
/// # Notes
///
/// - On success, `message` is typically null
#[repr(C)]
pub struct DeRecStatus {
    pub code: i32,
    pub message: *mut c_char,
}

/// Frees a buffer previously returned by the DeRec FFI.
///
/// This function must be called by foreign code to release memory returned
/// in a [`DeRecBuffer`].
///
/// # Arguments
///
/// * `ptr` - Pointer to the buffer
/// * `len` - Length of the buffer
///
/// # Safety
///
/// - `ptr` must have been allocated by the DeRec SDK
/// - `len` must match the original allocation length
/// - Passing an invalid pointer or length results in undefined behavior
///
/// # Notes
///
/// - It is safe to call this function with a null pointer
#[unsafe(no_mangle)]
pub extern "C" fn derec_free_buffer(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

/// Frees a C string previously returned by the DeRec FFI.
///
/// This function must be called by foreign code to release error messages
/// returned in [`DeRecStatus`].
///
/// # Arguments
///
/// * `ptr` - Pointer to a null-terminated C string
///
/// # Safety
///
/// - `ptr` must have been allocated by the DeRec SDK
/// - Passing an invalid pointer results in undefined behavior
///
/// # Notes
///
/// - It is safe to call this function with a null pointer
#[unsafe(no_mangle)]
pub extern "C" fn derec_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(ptr));
    }
}

/// Returns a success [`DeRecStatus`] with no error message.
///
/// This is used internally by FFI functions to indicate successful execution.
pub(crate) fn ok_status() -> DeRecStatus {
    DeRecStatus {
        code: 0,
        message: std::ptr::null_mut(),
    }
}

/// Creates an error [`DeRecStatus`] with a heap-allocated message.
///
/// This function is used internally by FFI functions to report failures.
///
/// If the provided message cannot be converted to a valid C string,
/// a fallback `"internal error"` message is used.
pub(crate) fn err_status(msg: impl AsRef<str>) -> DeRecStatus {
    let cstring =
        CString::new(msg.as_ref()).unwrap_or_else(|_| CString::new("internal error").unwrap());

    DeRecStatus {
        code: 1,
        message: cstring.into_raw(),
    }
}

/// Returns an empty [`DeRecBuffer`] with null pointer and zero length.
///
/// This is used in error paths where no valid buffer can be returned.
pub(crate) fn empty_buffer() -> DeRecBuffer {
    DeRecBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
    }
}

/// Converts a `Vec<u8>` into a [`DeRecBuffer`] without copying.
///
/// Ownership of the vector is transferred to the caller, and the memory is
/// intentionally leaked from Rust's perspective. The caller is responsible
/// for freeing it using [`derec_free_buffer`].
///
/// # Safety
///
/// - The returned pointer must eventually be freed using [`derec_free_buffer`]
pub(crate) fn vec_into_buffer(mut data: Vec<u8>) -> DeRecBuffer {
    let ptr = data.as_mut_ptr();
    let len = data.len();
    std::mem::forget(data);

    DeRecBuffer { ptr, len }
}

/// Writes a length-prefixed byte slice into the output buffer.
///
/// Format:
///
/// - 4 bytes (little-endian length)
/// - raw bytes
pub(crate) fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("pairing secret key component too large");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Writes an optional length-prefixed byte slice.
///
/// Format:
///
/// - 1 byte tag:
///   - `0` → None
///   - `1` → Some
/// - if `Some`: length-prefixed bytes
pub(crate) fn write_optional_len_prefixed(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            out.push(1);
            write_len_prefixed(out, bytes);
        }
        None => out.push(0),
    }
}

/// Writes a `u32` in little-endian format.
pub(crate) fn write_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Writes a `u64` in little-endian format.
pub(crate) fn write_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Reads exactly `len` bytes from the input slice.
///
/// Advances the input slice on success.
///
/// # Errors
///
/// Returns an error if there are not enough bytes remaining.
pub(crate) fn read_exact<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], String> {
    if input.len() < len {
        return Err("unexpected end of input".to_string());
    }

    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

/// Reads a single byte from the input.
pub(crate) fn read_u8(input: &mut &[u8]) -> Result<u8, String> {
    Ok(read_exact(input, 1)?[0])
}

/// Reads a `u32` in little-endian format.
pub(crate) fn read_u32_le(input: &mut &[u8]) -> Result<u32, String> {
    let bytes = read_exact(input, 4)?;
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| "failed to read u32".to_string())?;
    Ok(u32::from_le_bytes(array))
}

/// Reads a length-prefixed byte vector.
///
/// Format:
///
/// - 4 bytes (little-endian length)
/// - raw bytes
pub(crate) fn read_len_prefixed_vec(input: &mut &[u8]) -> Result<Vec<u8>, String> {
    let len = read_u32_le(input)? as usize;
    let bytes = read_exact(input, len)?;
    Ok(bytes.to_vec())
}

/// Reads an optional length-prefixed byte vector.
///
/// Format:
///
/// - 1 byte tag:
///   - `0` → None
///   - `1` → Some
///
/// # Errors
///
/// Returns an error if the tag is invalid.
pub(crate) fn read_optional_len_prefixed_vec(input: &mut &[u8]) -> Result<Option<Vec<u8>>, String> {
    match read_u8(input)? {
        0 => Ok(None),
        1 => Ok(Some(read_len_prefixed_vec(input)?)),
        _ => Err("invalid optional field tag".to_string()),
    }
}
