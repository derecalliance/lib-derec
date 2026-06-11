// SPDX-License-Identifier: Apache-2.0

//! C FFI for the DeRec unpairing flow.
//!
//! Protocol semantics live in `library/src/primitives/unpairing/`. Items
//! below describe only the FFI surface.

use std::ffi::CString;
use std::os::raw::c_char;

use crate::ffi::common::{
    DeRecBuffer, empty_buffer, parse_optional_transport_protocol, vec_into_buffer,
};
use crate::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_BAD_SHARED_KEY, DEREC_CODE_FFI_BAD_UTF8,
    DEREC_CODE_FFI_NULL_PTR, DEREC_CODE_FFI_NUL_IN_STRING, DeRecError, ffi_error, from_lib_error,
    success,
};
use derec_proto::{DeRecMessage, UnpairResponseMessage};
use prost::Message as _;

#[repr(C)]
pub struct ProduceUnpairRequestMessageResult {
    pub error: DeRecError,
    pub request_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractUnpairRequestResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Decrypted memo. Release with `derec_free_string`.
    pub memo: *mut c_char,
    /// prost-encoded inner `UnpairRequestMessage` bytes. SDK consumers
    /// decode this to inspect optional fields such as `reply_to`.
    pub request_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ProduceUnpairResponseMessageResult {
    pub error: DeRecError,
    pub response_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractUnpairResponseResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Inner `UnpairResponseMessage` proto bytes for chaining into
    /// [`process_unpair_response_message`].
    pub response_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ProcessUnpairResponseResult {
    pub error: DeRecError,
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_unpair_request_message(
    channel_id: u64,
    memo_ptr: *const u8,
    memo_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    // See `produce_store_share_request_message` in `sharing.rs` for the
    // `reply_to` semantics — `reply_to_len == 0` means "no override".
    reply_to_ptr: *const u8,
    reply_to_len: usize,
) -> ProduceUnpairRequestMessageResult {
    let with_err = |error| ProduceUnpairRequestMessageResult {
        error,
        request_wire_bytes: empty_buffer(),
    };

    let memo_bytes = match parse_buffer(memo_ptr, memo_len, "memo_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let memo = match std::str::from_utf8(memo_bytes) {
        Ok(s) => s,
        Err(_) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_UTF8,
                "memo is not valid UTF-8",
            ));
        }
    };
    let shared_key = match parse_shared_key(shared_key_ptr, shared_key_len) {
        Ok(k) => k,
        Err(e) => return with_err(e),
    };

    let reply_to = match parse_optional_transport_protocol(reply_to_ptr, reply_to_len) {
        Ok(rt) => rt,
        Err(e) => return with_err(e),
    };

    match crate::primitives::unpairing::request::produce(
        channel_id.into(),
        memo,
        &shared_key,
        reply_to,
    ) {
        Ok(r) => ProduceUnpairRequestMessageResult {
            error: success(),
            request_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_unpair_request(
    request_ptr: *const u8,
    request_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractUnpairRequestResult {
    let with_err = |error| ExtractUnpairRequestResult {
        error,
        channel_id: 0,
        memo: std::ptr::null_mut(),
        request_proto_bytes: empty_buffer(),
    };

    let request_bytes = match parse_buffer(request_ptr, request_len, "request_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let shared_key = match parse_shared_key(shared_key_ptr, shared_key_len) {
        Ok(k) => k,
        Err(e) => return with_err(e),
    };

    let channel_id = match DeRecMessage::decode(request_bytes) {
        Ok(e) => e.channel_id,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode envelope: {e}"),
            ));
        }
    };

    match crate::primitives::unpairing::request::extract(request_bytes, &shared_key) {
        Ok(r) => {
            let request_proto_bytes = vec_into_buffer(r.request.encode_to_vec());
            let memo_c = match CString::new(r.request.memo) {
                Ok(s) => s.into_raw(),
                Err(_) => {
                    return with_err(ffi_error(
                        DEREC_CODE_FFI_NUL_IN_STRING,
                        "memo contains an interior NUL byte",
                    ));
                }
            };
            ExtractUnpairRequestResult {
                error: success(),
                channel_id,
                memo: memo_c,
                request_proto_bytes,
            }
        }
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_unpair_response_message(
    channel_id: u64,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ProduceUnpairResponseMessageResult {
    let with_err = |error| ProduceUnpairResponseMessageResult {
        error,
        response_wire_bytes: empty_buffer(),
    };

    let shared_key = match parse_shared_key(shared_key_ptr, shared_key_len) {
        Ok(k) => k,
        Err(e) => return with_err(e),
    };

    match crate::primitives::unpairing::response::produce(channel_id.into(), &shared_key) {
        Ok(r) => ProduceUnpairResponseMessageResult {
            error: success(),
            response_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_unpair_response(
    response_ptr: *const u8,
    response_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractUnpairResponseResult {
    let with_err = |error| ExtractUnpairResponseResult {
        error,
        channel_id: 0,
        response_proto_bytes: empty_buffer(),
    };

    let response_bytes = match parse_buffer(response_ptr, response_len, "response_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let shared_key = match parse_shared_key(shared_key_ptr, shared_key_len) {
        Ok(k) => k,
        Err(e) => return with_err(e),
    };

    let channel_id = match DeRecMessage::decode(response_bytes) {
        Ok(e) => e.channel_id,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode envelope: {e}"),
            ));
        }
    };

    match crate::primitives::unpairing::response::extract(response_bytes, &shared_key) {
        Ok(r) => ExtractUnpairResponseResult {
            error: success(),
            channel_id,
            response_proto_bytes: vec_into_buffer(r.response.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `response_proto_ptr` / `response_proto_len` must be the
/// `response_proto_bytes` returned by [`extract_unpair_response`].
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_unpair_response_message(
    response_proto_ptr: *const u8,
    response_proto_len: usize,
) -> ProcessUnpairResponseResult {
    let with_err = |error| ProcessUnpairResponseResult { error };

    let response_bytes =
        match parse_buffer(response_proto_ptr, response_proto_len, "response_proto_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };

    let response = match UnpairResponseMessage::decode(response_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode response: {e}"),
            ));
        }
    };

    match crate::primitives::unpairing::response::process(&response) {
        Ok(_) => ProcessUnpairResponseResult { error: success() },
        Err(e) => with_err(from_lib_error(e)),
    }
}

fn parse_buffer<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], DeRecError> {
    if ptr.is_null() && len > 0 {
        return Err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            format!("{name} is null"),
        ));
    }
    if len == 0 {
        Ok(&[])
    } else {
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}

fn parse_shared_key(ptr: *const u8, len: usize) -> Result<[u8; 32], DeRecError> {
    let bytes = parse_buffer(ptr, len, "shared_key_ptr")?;
    bytes.try_into().map_err(|_| {
        ffi_error(
            DEREC_CODE_FFI_BAD_SHARED_KEY,
            "shared_key must be exactly 32 bytes",
        )
    })
}
