// SPDX-License-Identifier: Apache-2.0

//! C FFI for the DeRec discovery flow.
//!
//! Protocol semantics live in `library/src/primitives/discovery/`. Items below
//! describe only the FFI surface and the custom binary format used to ferry
//! the secret list across the boundary.
//!
//! # Secret list binary format
//!
//! Both [`produce_get_secret_ids_versions_response_message`] (input
//! `secret_list_ptr`) and [`process_get_secret_ids_versions_response_message`]
//! (output `secret_list_bytes`) use:
//!
//! ```text
//! [count: u32 LE]
//! for each entry:
//!   [secret_id: u64 LE]
//!   [versions_count: u32 LE]
//!   for each version:
//!     [version: u32 LE]
//!     [description_len: u32 LE]
//!     [description: UTF-8 bytes]
//! ```

use crate::ffi::common::{
    DeRecBuffer, empty_buffer, parse_optional_transport_protocol, read_exact, read_u32_le,
    vec_into_buffer, write_u32_le, write_u64_le,
};
use crate::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_BAD_SHARED_KEY, DEREC_CODE_FFI_NULL_PTR, DeRecError,
    ffi_error, from_lib_error, success,
};
use crate::primitives::discovery::response::{SecretVersionEntry, VersionEntry};
use derec_proto::{DeRecMessage, GetSecretIdsVersionsResponseMessage};
use prost::Message as _;

#[repr(C)]
pub struct ProduceGetSecretIdsVersionsRequestMessageResult {
    pub error: DeRecError,
    pub envelope_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractGetSecretIdsVersionsRequestResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// prost-encoded inner `GetSecretIdsVersionsRequestMessage` bytes.
    /// Empty buffer when extraction fails. SDK consumers decode this
    /// to inspect optional fields such as `reply_to`.
    pub request_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ProduceGetSecretIdsVersionsResponseMessageResult {
    pub error: DeRecError,
    pub envelope_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractGetSecretIdsVersionsResponseResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Inner `GetSecretIdsVersionsResponseMessage` proto bytes for chaining
    /// into [`process_get_secret_ids_versions_response_message`].
    pub response_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ProcessGetSecretIdsVersionsResponseMessageResult {
    pub error: DeRecError,
    /// Validated secret list in the format documented at the module level.
    pub secret_list_bytes: DeRecBuffer,
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_get_secret_ids_versions_request_message(
    channel_id: u64,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    // See `produce_store_share_request_message` for the `reply_to`
    // semantics — `reply_to_len == 0` means "no override".
    reply_to_ptr: *const u8,
    reply_to_len: usize,
) -> ProduceGetSecretIdsVersionsRequestMessageResult {
    let with_err = |error| ProduceGetSecretIdsVersionsRequestMessageResult {
        error,
        envelope_wire_bytes: empty_buffer(),
    };

    let shared_key = match parse_shared_key(shared_key_ptr, shared_key_len) {
        Ok(k) => k,
        Err(e) => return with_err(e),
    };

    let reply_to = match parse_optional_transport_protocol(reply_to_ptr, reply_to_len) {
        Ok(rt) => rt,
        Err(e) => return with_err(e),
    };

    match crate::primitives::discovery::request::produce(channel_id.into(), &shared_key, reply_to) {
        Ok(r) => ProduceGetSecretIdsVersionsRequestMessageResult {
            error: success(),
            envelope_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_get_secret_ids_versions_request(
    request_ptr: *const u8,
    request_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractGetSecretIdsVersionsRequestResult {
    let with_err = |error| ExtractGetSecretIdsVersionsRequestResult {
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

    match crate::primitives::discovery::request::extract(request_bytes, &shared_key) {
        Ok(r) => ExtractGetSecretIdsVersionsRequestResult {
            error: success(),
            channel_id,
            request_proto_bytes: vec_into_buffer(r.request.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `secret_list_ptr` / `secret_list_len` must follow the binary format
/// documented at the module level.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_get_secret_ids_versions_response_message(
    channel_id: u64,
    secret_list_ptr: *const u8,
    secret_list_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ProduceGetSecretIdsVersionsResponseMessageResult {
    let with_err = |error| ProduceGetSecretIdsVersionsResponseMessageResult {
        error,
        envelope_wire_bytes: empty_buffer(),
    };

    let secret_list_bytes = match parse_buffer(secret_list_ptr, secret_list_len, "secret_list_ptr")
    {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let shared_key = match parse_shared_key(shared_key_ptr, shared_key_len) {
        Ok(k) => k,
        Err(e) => return with_err(e),
    };

    let secret_list = match deserialize_secret_list(secret_list_bytes) {
        Ok(list) => list,
        Err(e) => return with_err(ffi_error(DEREC_CODE_FFI_BAD_PROTO, e)),
    };

    match crate::primitives::discovery::response::produce(
        channel_id.into(),
        &secret_list,
        &shared_key,
    ) {
        Ok(r) => ProduceGetSecretIdsVersionsResponseMessageResult {
            error: success(),
            envelope_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_get_secret_ids_versions_response(
    response_ptr: *const u8,
    response_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractGetSecretIdsVersionsResponseResult {
    let with_err = |error| ExtractGetSecretIdsVersionsResponseResult {
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

    match crate::primitives::discovery::response::extract(response_bytes, &shared_key) {
        Ok(r) => ExtractGetSecretIdsVersionsResponseResult {
            error: success(),
            channel_id,
            response_proto_bytes: vec_into_buffer(r.response.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `response_proto_ptr` / `response_proto_len` must be the
/// `response_proto_bytes` returned by
/// [`extract_get_secret_ids_versions_response`].
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_get_secret_ids_versions_response_message(
    response_proto_ptr: *const u8,
    response_proto_len: usize,
) -> ProcessGetSecretIdsVersionsResponseMessageResult {
    let with_err = |error| ProcessGetSecretIdsVersionsResponseMessageResult {
        error,
        secret_list_bytes: empty_buffer(),
    };

    let response_bytes =
        match parse_buffer(response_proto_ptr, response_proto_len, "response_proto_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };

    let response = match GetSecretIdsVersionsResponseMessage::decode(response_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode response: {e}"),
            ));
        }
    };

    match crate::primitives::discovery::response::process(&response) {
        Ok(r) => ProcessGetSecretIdsVersionsResponseMessageResult {
            error: success(),
            secret_list_bytes: vec_into_buffer(serialize_secret_list(&r.secret_list)),
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

fn serialize_secret_list(entries: &[SecretVersionEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    write_u32_le(&mut out, entries.len() as u32);
    for entry in entries {
        write_u64_le(&mut out, entry.secret_id);
        write_u32_le(&mut out, entry.versions.len() as u32);
        for v in &entry.versions {
            write_u32_le(&mut out, v.version);
            let desc_bytes = v.description.as_bytes();
            write_u32_le(&mut out, desc_bytes.len() as u32);
            out.extend_from_slice(desc_bytes);
            // Optional `replica_id` tail: 1-byte flag, then u64 LE
            // when set. Mirrors the layout the .NET side reads in
            // `DiscoveryWireFormat.Deserialize`.
            match v.replica_id {
                Some(id) => {
                    out.push(1u8);
                    write_u64_le(&mut out, id);
                }
                None => out.push(0u8),
            }
        }
    }
    out
}

fn deserialize_secret_list(bytes: &[u8]) -> Result<Vec<SecretVersionEntry>, String> {
    let mut input = bytes;
    let count = read_u32_le(&mut input)? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let secret_id_bytes = read_exact(&mut input, 8)?;
        let secret_id_arr: [u8; 8] = secret_id_bytes
            .try_into()
            .map_err(|_| "failed to read secret_id".to_string())?;
        let secret_id = u64::from_le_bytes(secret_id_arr);

        let versions_count = read_u32_le(&mut input)? as usize;
        let mut versions = Vec::with_capacity(versions_count);
        for _ in 0..versions_count {
            let version = read_u32_le(&mut input)?;
            let desc_len = read_u32_le(&mut input)? as usize;
            let desc_bytes = read_exact(&mut input, desc_len)?;
            let description = String::from_utf8(desc_bytes.to_vec())
                .map_err(|e| format!("invalid UTF-8 in description: {e}"))?;
            // Optional `replica_id` tail: `has_replica_id: u8` flag
            // followed by `replica_id: u64 LE` when set. `has = 0`
            // means the version came from a non-replica `Owner`.
            let has_replica_id = read_exact(&mut input, 1)?[0];
            let replica_id = if has_replica_id != 0 {
                let id_bytes = read_exact(&mut input, 8)?;
                let mut arr = [0u8; 8];
                arr.copy_from_slice(id_bytes);
                Some(u64::from_le_bytes(arr))
            } else {
                None
            };
            versions.push(VersionEntry {
                version,
                description,
                replica_id,
            });
        }
        entries.push(SecretVersionEntry {
            secret_id,
            versions,
        });
    }
    Ok(entries)
}
