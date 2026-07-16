// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! C FFI for the DeRec verification flow.
//!
//! Protocol semantics live in `library/src/primitives/verification/`. Items
//! below describe only the FFI surface.

use crate::ffi::common::{
    DeRecBuffer, empty_buffer, parse_optional_transport_protocol, vec_into_buffer,
};
use crate::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_BAD_SHARED_KEY, DEREC_CODE_FFI_NULL_PTR, DeRecError,
    ffi_error, from_lib_error, success,
};
use derec_proto::{DeRecMessage, VerifyShareRequestMessage, VerifyShareResponseMessage};
use prost::Message as _;

#[repr(C)]
pub struct ProduceVerifyShareRequestMessageResult {
    pub error: DeRecError,
    pub request_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractVerifyShareRequestResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Inner `VerifyShareRequestMessage` proto bytes for chaining into
    /// [`produce_verify_share_response_message`].
    pub request_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ProduceVerifyShareResponseMessageResult {
    pub error: DeRecError,
    pub response_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractVerifyShareResponseResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Inner `VerifyShareResponseMessage` proto bytes for chaining into
    /// [`process_verify_share_response_message`].
    pub response_proto_bytes: DeRecBuffer,
}

/// `is_valid` is meaningful only on success. Peer rejection surfaces on
/// `error` (see [`crate::ffi::error`]).
#[repr(C)]
pub struct VerifyShareResponseResult {
    pub error: DeRecError,
    pub is_valid: bool,
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_verify_share_request_message(
    channel_id: u64,
    secret_id: u64,
    version: u32,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    // See `produce_store_share_request_message` for the `reply_to`
    // semantics — `reply_to_len == 0` means "no override".
    reply_to_ptr: *const u8,
    reply_to_len: usize,
) -> ProduceVerifyShareRequestMessageResult {
    let with_err = |error| ProduceVerifyShareRequestMessageResult {
        error,
        request_wire_bytes: empty_buffer(),
    };

    let shared_key = match parse_shared_key(shared_key_ptr, shared_key_len) {
        Ok(k) => k,
        Err(e) => return with_err(e),
    };

    let reply_to = match parse_optional_transport_protocol(reply_to_ptr, reply_to_len) {
        Ok(rt) => rt,
        Err(e) => return with_err(e),
    };

    match crate::primitives::verification::request::produce(
        channel_id.into(),
        secret_id,
        version,
        &shared_key,
        reply_to,
    ) {
        Ok(r) => ProduceVerifyShareRequestMessageResult {
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
pub extern "C" fn extract_verify_share_request(
    request_ptr: *const u8,
    request_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractVerifyShareRequestResult {
    let with_err = |error| ExtractVerifyShareRequestResult {
        error,
        channel_id: 0,
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

    match crate::primitives::verification::request::extract(request_bytes, &shared_key) {
        Ok(r) => ExtractVerifyShareRequestResult {
            error: success(),
            channel_id,
            request_proto_bytes: vec_into_buffer(r.request.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
/// returned by [`extract_verify_share_request`].
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_verify_share_response_message(
    channel_id: u64,
    request_proto_ptr: *const u8,
    request_proto_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    share_content_ptr: *const u8,
    share_content_len: usize,
) -> ProduceVerifyShareResponseMessageResult {
    let with_err = |error| ProduceVerifyShareResponseMessageResult {
        error,
        response_wire_bytes: empty_buffer(),
    };

    let request_bytes =
        match parse_buffer(request_proto_ptr, request_proto_len, "request_proto_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    let shared_key = match parse_shared_key(shared_key_ptr, shared_key_len) {
        Ok(k) => k,
        Err(e) => return with_err(e),
    };
    let share_content =
        match parse_buffer(share_content_ptr, share_content_len, "share_content_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };

    let request = match VerifyShareRequestMessage::decode(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode request: {e}"),
            ));
        }
    };

    match crate::primitives::verification::response::produce(
        channel_id.into(),
        &request,
        &shared_key,
        share_content,
    ) {
        Ok(r) => ProduceVerifyShareResponseMessageResult {
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
pub extern "C" fn extract_verify_share_response(
    response_ptr: *const u8,
    response_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractVerifyShareResponseResult {
    let with_err = |error| ExtractVerifyShareResponseResult {
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

    match crate::primitives::verification::response::extract(response_bytes, &shared_key) {
        Ok(r) => ExtractVerifyShareResponseResult {
            error: success(),
            channel_id,
            response_proto_bytes: vec_into_buffer(r.response.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// Verify a `VerifyShareResponseMessage` against the originating
/// `VerifyShareRequestMessage` and the expected share content.
///
/// `request_proto_ptr` / `request_proto_len` must carry the proto-
/// encoded [`derec_proto::VerifyShareRequestMessage`] the **owner**
/// previously produced for this challenge (kept by the caller in a
/// per-`channel_id` pending-verification map). The primitive
/// rejects any response whose `(nonce, secret_id, version)` triple
/// doesn't match — that's the anti-replay gate.
///
/// `response_proto_ptr` / `response_proto_len` must be the
/// `response_proto_bytes` returned by [`extract_verify_share_response`].
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_verify_share_response_message(
    request_proto_ptr: *const u8,
    request_proto_len: usize,
    response_proto_ptr: *const u8,
    response_proto_len: usize,
    share_content_ptr: *const u8,
    share_content_len: usize,
) -> VerifyShareResponseResult {
    let with_err = |error| VerifyShareResponseResult {
        error,
        is_valid: false,
    };

    let request_bytes = match parse_buffer(request_proto_ptr, request_proto_len, "request_proto_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let response_bytes =
        match parse_buffer(response_proto_ptr, response_proto_len, "response_proto_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    let share_content =
        match parse_buffer(share_content_ptr, share_content_len, "share_content_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };

    let request = match derec_proto::VerifyShareRequestMessage::decode(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode request: {e}"),
            ));
        }
    };
    let response = match VerifyShareResponseMessage::decode(response_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode response: {e}"),
            ));
        }
    };

    match crate::primitives::verification::response::process(&request, &response, share_content) {
        Ok(is_valid) => VerifyShareResponseResult {
            error: success(),
            is_valid,
        },
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
