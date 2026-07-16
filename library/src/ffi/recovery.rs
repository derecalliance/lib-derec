// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! C FFI for the DeRec recovery flow.
//!
//! Protocol semantics live in `library/src/primitives/recovery/`. Items below
//! describe only the FFI surface and the custom binary format used to ferry
//! the response set to [`recover_from_share_responses`].
//!
//! # Responses binary format
//!
//! [`recover_from_share_responses`] takes a single buffer with:
//!
//! ```text
//! [count: u32 LE]
//! for each entry:
//!   [response_len: u32 LE]
//!   [serialized GetShareResponseMessage]
//! ```
//!
//! Build it by accumulating the `response_proto_bytes` returned by repeated
//! calls to [`extract_get_share_response`].

use crate::ffi::common::{
    DeRecBuffer, empty_buffer, parse_optional_transport_protocol, read_len_prefixed_vec,
    read_u32_le, vec_into_buffer,
};
use crate::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_BAD_SHARED_KEY, DEREC_CODE_FFI_NULL_PTR, DeRecError,
    ffi_error, from_lib_error, success,
};
use derec_proto::{
    DeRecMessage, GetShareRequestMessage, GetShareResponseMessage, StoreShareRequestMessage,
};
use prost::Message as _;

#[repr(C)]
pub struct ProduceGetShareRequestMessageResult {
    pub error: DeRecError,
    pub request_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractGetShareRequestResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Inner `GetShareRequestMessage` proto bytes for chaining into
    /// [`produce_get_share_response_message`].
    pub request_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ProduceGetShareResponseMessageResult {
    pub error: DeRecError,
    pub response_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractGetShareResponseResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Inner `GetShareResponseMessage` proto bytes. Accumulate across helpers
    /// and pass to [`recover_from_share_responses`].
    pub response_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct RecoverFromShareResponsesResult {
    pub error: DeRecError,
    pub secret_data: DeRecBuffer,
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_get_share_request_message(
    channel_id: u64,
    secret_id: u64,
    version: u32,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    // See `produce_store_share_request_message` for the `reply_to`
    // semantics — `reply_to_len == 0` means "no override".
    reply_to_ptr: *const u8,
    reply_to_len: usize,
) -> ProduceGetShareRequestMessageResult {
    let with_err = |error| ProduceGetShareRequestMessageResult {
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

    match crate::primitives::recovery::request::produce(
        channel_id.into(),
        secret_id,
        version,
        &shared_key,
        reply_to,
    ) {
        Ok(r) => ProduceGetShareRequestMessageResult {
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
pub extern "C" fn extract_get_share_request(
    request_ptr: *const u8,
    request_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractGetShareRequestResult {
    let with_err = |error| ExtractGetShareRequestResult {
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

    match crate::primitives::recovery::request::extract(request_bytes, &shared_key) {
        Ok(r) => ExtractGetShareRequestResult {
            error: success(),
            channel_id,
            request_proto_bytes: vec_into_buffer(r.request.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
/// returned by [`extract_get_share_request`].
///
/// `stored_share_proto_ptr` / `stored_share_proto_len` must be the serialized
/// inner `StoreShareRequestMessage` the helper persisted at sharing time —
/// typically the `request_proto_bytes` returned by `extract_store_share_request`.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_get_share_response_message(
    channel_id: u64,
    request_proto_ptr: *const u8,
    request_proto_len: usize,
    stored_share_proto_ptr: *const u8,
    stored_share_proto_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ProduceGetShareResponseMessageResult {
    let with_err = |error| ProduceGetShareResponseMessageResult {
        error,
        response_wire_bytes: empty_buffer(),
    };

    let request_bytes =
        match parse_buffer(request_proto_ptr, request_proto_len, "request_proto_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    let stored_share_bytes = match parse_buffer(
        stored_share_proto_ptr,
        stored_share_proto_len,
        "stored_share_proto_ptr",
    ) {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let shared_key = match parse_shared_key(shared_key_ptr, shared_key_len) {
        Ok(k) => k,
        Err(e) => return with_err(e),
    };

    let request = match GetShareRequestMessage::decode(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode request: {e}"),
            ));
        }
    };
    let stored_share = match StoreShareRequestMessage::decode(stored_share_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode stored share: {e}"),
            ));
        }
    };

    match crate::primitives::recovery::response::produce(
        channel_id.into(),
        &request,
        &stored_share,
        &shared_key,
    ) {
        Ok(r) => ProduceGetShareResponseMessageResult {
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
pub extern "C" fn extract_get_share_response(
    response_ptr: *const u8,
    response_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractGetShareResponseResult {
    let with_err = |error| ExtractGetShareResponseResult {
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

    match crate::primitives::recovery::response::extract(response_bytes, &shared_key) {
        Ok(r) => ExtractGetShareResponseResult {
            error: success(),
            channel_id,
            response_proto_bytes: vec_into_buffer(r.response.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `responses_ptr` / `responses_len` must follow the binary format documented
/// at the module level.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn recover_from_share_responses(
    responses_ptr: *const u8,
    responses_len: usize,
    secret_id: u64,
    version: u32,
) -> RecoverFromShareResponsesResult {
    let with_err = |error| RecoverFromShareResponsesResult {
        error,
        secret_data: empty_buffer(),
    };

    let responses_bytes = match parse_buffer(responses_ptr, responses_len, "responses_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };

    let response_protos = match deserialize_response_proto_list(responses_bytes) {
        Ok(v) => v,
        Err(e) => return with_err(ffi_error(DEREC_CODE_FFI_BAD_PROTO, e)),
    };

    let responses: Result<Vec<GetShareResponseMessage>, DeRecError> = response_protos
        .iter()
        .map(|bytes| {
            GetShareResponseMessage::decode(bytes.as_slice()).map_err(|e| {
                ffi_error(
                    DEREC_CODE_FFI_BAD_PROTO,
                    format!("failed to decode response: {e}"),
                )
            })
        })
        .collect();
    let responses = match responses {
        Ok(v) => v,
        Err(e) => return with_err(e),
    };

    let borrowed: Vec<&GetShareResponseMessage> = responses.iter().collect();

    match crate::primitives::recovery::response::recover(secret_id, version, &borrowed) {
        Ok(r) => RecoverFromShareResponsesResult {
            error: success(),
            secret_data: vec_into_buffer(r.secret_data),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

fn deserialize_response_proto_list(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut input = bytes;

    let count = read_u32_le(&mut input)? as usize;
    let mut out = Vec::with_capacity(count);

    for _ in 0..count {
        out.push(read_len_prefixed_vec(&mut input)?);
    }

    if !input.is_empty() {
        return Err("unexpected trailing bytes in serialized response collection".to_string());
    }

    Ok(out)
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
