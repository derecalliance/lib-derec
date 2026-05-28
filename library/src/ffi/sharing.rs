// SPDX-License-Identifier: Apache-2.0

//! C FFI for the DeRec sharing flow.
//!
//! Protocol semantics live in `library/src/primitives/sharing/`. Items below
//! describe only the FFI surface and the custom binary format used to ferry
//! the per-channel committed shares.
//!
//! # Committed-shares binary format
//!
//! [`protect_secret`] returns its share set as a single FFI container:
//!
//! ```text
//! [count: u32 LE]
//! for each entry (sorted by channel ID):
//!   [channel_id: u64 LE]
//!   [share_len: u32 LE]
//!   [serialized CommittedDeRecShare protobuf]
//! ```

use crate::{
    ffi::common::{
        DeRecBuffer, empty_buffer, vec_into_buffer, write_len_prefixed, write_u32_le, write_u64_le,
    },
    ffi::error::{
        DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_BAD_SHARED_KEY, DEREC_CODE_FFI_BAD_UTF8,
        DEREC_CODE_FFI_NULL_PTR, DeRecError, ffi_error, from_lib_error, success,
    },
    types::ChannelId,
};
use derec_proto::{
    CommittedDeRecShare, DeRecMessage, StoreShareRequestMessage, StoreShareResponseMessage,
};
use prost::Message as _;
use std::collections::HashMap;
use std::str;

#[repr(C)]
pub struct ProtectSecretResult {
    pub error: DeRecError,
    /// Committed shares in the format documented at the module level.
    pub shares_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ProduceStoreShareRequestMessageResult {
    pub error: DeRecError,
    pub wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractStoreShareRequestResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Inner `StoreShareRequestMessage` proto bytes for chaining into
    /// [`produce_store_share_response_message`].
    pub request_proto_bytes: DeRecBuffer,
}

/// `committed_share_bytes` is the serialized [`CommittedDeRecShare`] the
/// helper should persist locally for later recovery responses.
#[repr(C)]
pub struct ProduceStoreShareResponseMessageResult {
    pub error: DeRecError,
    pub wire_bytes: DeRecBuffer,
    pub committed_share_bytes: DeRecBuffer,
    pub secret_id: u64,
    pub version: u32,
}

#[repr(C)]
pub struct ExtractStoreShareResponseResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Inner `StoreShareResponseMessage` proto bytes for chaining into
    /// [`process_store_share_response_message`].
    pub response_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ProcessStoreShareResponseMessageResult {
    pub error: DeRecError,
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn protect_secret(
    secret_id: u64,
    secret_data_ptr: *const u8,
    secret_data_len: usize,
    channels_ptr: *const u64,
    channels_len: usize,
    threshold: usize,
    version: u32,
) -> ProtectSecretResult {
    let with_err = |error| ProtectSecretResult {
        error,
        shares_wire_bytes: empty_buffer(),
    };

    let secret_data = match parse_buffer(secret_data_ptr, secret_data_len, "secret_data_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    if channels_ptr.is_null() && channels_len > 0 {
        return with_err(ffi_error(DEREC_CODE_FFI_NULL_PTR, "channels_ptr is null"));
    }
    let channel_ids: Vec<ChannelId> = if channels_len == 0 {
        vec![]
    } else {
        let raw = unsafe { std::slice::from_raw_parts(channels_ptr, channels_len) };
        raw.iter().map(|&id| ChannelId(id)).collect()
    };

    match crate::primitives::sharing::request::split(
        &channel_ids,
        secret_id,
        version,
        secret_data,
        threshold,
    ) {
        Ok(r) => ProtectSecretResult {
            error: success(),
            shares_wire_bytes: vec_into_buffer(serialize_committed_shares(&r.shares)),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_store_share_request_message(
    channel_id: u64,
    version: u32,
    secret_id: u64,
    committed_share_ptr: *const u8,
    committed_share_len: usize,
    keep_list_ptr: *const u32,
    keep_list_len: usize,
    description_ptr: *const u8,
    description_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ProduceStoreShareRequestMessageResult {
    let with_err = |error| ProduceStoreShareRequestMessageResult {
        error,
        wire_bytes: empty_buffer(),
    };

    let committed_share_bytes =
        match parse_buffer(committed_share_ptr, committed_share_len, "committed_share_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    if keep_list_ptr.is_null() && keep_list_len > 0 {
        return with_err(ffi_error(DEREC_CODE_FFI_NULL_PTR, "keep_list_ptr is null"));
    }
    let keep_list: &[u32] = if keep_list_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(keep_list_ptr, keep_list_len) }
    };
    let description_bytes =
        match parse_buffer(description_ptr, description_len, "description_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    let description = match str::from_utf8(description_bytes) {
        Ok(s) => s,
        Err(_) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_UTF8,
                "description is not valid UTF-8",
            ));
        }
    };
    let shared_key = match parse_shared_key(shared_key_ptr, shared_key_len) {
        Ok(k) => k,
        Err(e) => return with_err(e),
    };

    let committed_share = match CommittedDeRecShare::decode(committed_share_bytes) {
        Ok(s) => s,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode CommittedDeRecShare: {e}"),
            ));
        }
    };

    match crate::primitives::sharing::request::produce(
        ChannelId(channel_id),
        version,
        secret_id,
        &committed_share,
        keep_list,
        description,
        &shared_key,
    ) {
        Ok(r) => ProduceStoreShareRequestMessageResult {
            error: success(),
            wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_store_share_request(
    request_ptr: *const u8,
    request_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractStoreShareRequestResult {
    let with_err = |error| ExtractStoreShareRequestResult {
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

    match crate::primitives::sharing::request::extract(request_bytes, &shared_key) {
        Ok(r) => ExtractStoreShareRequestResult {
            error: success(),
            channel_id,
            request_proto_bytes: vec_into_buffer(r.request.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
/// returned by [`extract_store_share_request`].
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_store_share_response_message(
    channel_id: u64,
    request_proto_ptr: *const u8,
    request_proto_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ProduceStoreShareResponseMessageResult {
    let with_err = |error| ProduceStoreShareResponseMessageResult {
        error,
        wire_bytes: empty_buffer(),
        committed_share_bytes: empty_buffer(),
        secret_id: 0,
        version: 0,
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

    let request = match StoreShareRequestMessage::decode(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode request: {e}"),
            ));
        }
    };

    match crate::primitives::sharing::response::produce(
        ChannelId(channel_id),
        &request,
        &shared_key,
    ) {
        Ok(r) => ProduceStoreShareResponseMessageResult {
            error: success(),
            wire_bytes: vec_into_buffer(r.envelope),
            committed_share_bytes: vec_into_buffer(r.committed_share.encode_to_vec()),
            secret_id: r.secret_id,
            version: r.version,
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_store_share_response(
    response_ptr: *const u8,
    response_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractStoreShareResponseResult {
    let with_err = |error| ExtractStoreShareResponseResult {
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

    match crate::primitives::sharing::response::extract(response_bytes, &shared_key) {
        Ok(r) => ExtractStoreShareResponseResult {
            error: success(),
            channel_id,
            response_proto_bytes: vec_into_buffer(r.response.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `response_proto_ptr` / `response_proto_len` must be the
/// `response_proto_bytes` returned by [`extract_store_share_response`].
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_store_share_response_message(
    version: u32,
    response_proto_ptr: *const u8,
    response_proto_len: usize,
) -> ProcessStoreShareResponseMessageResult {
    let with_err = |error| ProcessStoreShareResponseMessageResult { error };

    let response_bytes =
        match parse_buffer(response_proto_ptr, response_proto_len, "response_proto_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };

    let response = match StoreShareResponseMessage::decode(response_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode response: {e}"),
            ));
        }
    };

    match crate::primitives::sharing::response::process(version, &response) {
        Ok(()) => ProcessStoreShareResponseMessageResult { error: success() },
        Err(e) => with_err(from_lib_error(e)),
    }
}

fn serialize_committed_shares(shares: &HashMap<ChannelId, CommittedDeRecShare>) -> Vec<u8> {
    let mut entries: Vec<_> = shares.iter().collect();
    entries.sort_by_key(|(channel_id, _)| <u64 as From<ChannelId>>::from(**channel_id));

    let mut out = Vec::new();

    let count = u32::try_from(entries.len()).expect("too many share entries");
    write_u32_le(&mut out, count);

    for (channel_id, share) in entries {
        write_u64_le(&mut out, <u64 as From<ChannelId>>::from(*channel_id));
        write_len_prefixed(&mut out, &share.encode_to_vec());
    }

    out
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
