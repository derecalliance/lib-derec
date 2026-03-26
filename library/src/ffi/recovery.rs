//! C FFI exports for the DeRec *recovery* flow.
//!
//! This module exposes the recovery flow through a C-compatible ABI so that
//! non-Rust consumers can:
//!
//! 1. Create a recovery request envelope for a target secret/version
//! 2. Produce a recovery response envelope from a stored share envelope
//! 3. Recover the original secret from a set of recovery response envelopes
//!
//! All exported functions follow the same general pattern:
//!
//! - inputs are passed as primitive C values or raw byte buffers
//! - protocol messages are passed as serialized wire bytes
//! - results are returned as `#[repr(C)]` structs containing:
//!   - a [`DeRecStatus`] indicating success or failure
//!   - one or more [`DeRecBuffer`] values containing output bytes
//!
//! # FFI Conventions
//!
//! - secret IDs are passed as `(*const u8, usize)` byte buffers
//! - shared symmetric keys are passed as `(*const u8, usize)` byte buffers and must
//!   be exactly 32 bytes long
//! - request and response inputs are passed as serialized outer `DeRecMessage` bytes
//! - request and response outputs are returned as serialized outer `DeRecMessage` bytes
//! - returned buffers must be released by the caller using the common FFI
//!   buffer-freeing helper exposed elsewhere in the FFI surface
//! - on error, output buffers are returned empty and details are reported in
//!   the returned [`DeRecStatus`]
//!
//! # Serialized Share Response Collection
//!
//! [`recover_from_share_responses`] accepts a custom FFI byte encoding representing
//! a sequence of recovery response inputs. Each input pairs one serialized outer
//! recovery response envelope with the 32-byte shared key required to decrypt it.
//!
//! The encoding is:
//!
//! 1. A 32-bit little-endian count
//! 2. For each entry:
//!    - a length-prefixed serialized outer `DeRecMessage` carrying an encrypted
//!      inner `GetShareResponseMessage`
//!    - exactly 32 raw bytes containing the shared key for that response
//!
//! This collection format is specific to the FFI layer and should be treated as
//! an opaque transport container by foreign callers.
//!
//! # Notes
//!
//! - this module does not expose Rust collection types directly over FFI
//! - all protobuf decoding and protocol validation are delegated to the core Rust SDK

use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, read_len_prefixed_vec,
    read_u32_le, vec_into_buffer,
};
use crate::recovery::RecoveryResponseInput;

/// FFI result returned by [`generate_share_request`].
///
/// On success:
///
/// - `status` indicates success
/// - `request_wire_bytes` contains serialized outer `DeRecMessage` bytes
///   carrying an encrypted inner `GetShareRequestMessage`
///
/// On failure:
///
/// - `status` contains an error
/// - output buffers are empty
#[repr(C)]
pub struct GenerateShareRequestResult {
    pub status: DeRecStatus,
    pub request_wire_bytes: DeRecBuffer,
}

/// FFI result returned by [`generate_share_response`].
///
/// On success:
///
/// - `status` indicates success
/// - `response_wire_bytes` contains serialized outer `DeRecMessage` bytes
///   carrying an encrypted inner `GetShareResponseMessage`
///
/// On failure:
///
/// - `status` contains an error
/// - output buffers are empty
#[repr(C)]
pub struct GenerateShareResponseResult {
    pub status: DeRecStatus,
    pub response_wire_bytes: DeRecBuffer,
}

/// FFI result returned by [`recover_from_share_responses`].
///
/// On success:
///
/// - `status` indicates success
/// - `secret_data` contains the recovered secret bytes
///
/// On failure:
///
/// - `status` contains an error
/// - output buffers are empty
#[repr(C)]
pub struct RecoverFromShareResponsesResult {
    pub status: DeRecStatus,
    pub secret_data: DeRecBuffer,
}

/// Creates a serialized recovery request envelope.
///
/// This is the C FFI entry point used by a recovering owner/requestor to ask
/// a helper for the share associated with a particular secret ID and version.
///
/// The caller provides:
///
/// - `channel_id` as a raw `u64`
/// - `secret_id_ptr` / `secret_id_len` as a secret ID byte buffer
/// - `version` as the target share version
/// - `shared_key_ptr` / `shared_key_len` as the 32-byte symmetric key previously
///   established during pairing
///
/// On success, this function returns serialized outer `DeRecMessage` bytes
/// carrying an encrypted inner `GetShareRequestMessage`.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier used for the request.
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `version` - Requested share version.
/// * `shared_key_ptr` - Pointer to 32-byte shared symmetric key bytes.
/// * `shared_key_len` - Length of the shared key buffer. Must be exactly `32`.
///
/// # Returns
///
/// Returns [`GenerateShareRequestResult`].
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `secret_id_ptr` is null while `secret_id_len > 0`
/// - `shared_key_ptr` is null while `shared_key_len > 0`
/// - `shared_key_len != 32`
/// - the underlying Rust recovery API returns an error
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn generate_share_request(
    channel_id: u64,
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    version: i32,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> GenerateShareRequestResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateShareRequestResult {
            status: err_status("secret_id_ptr is null"),
            request_wire_bytes: empty_buffer(),
        };
    }

    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return GenerateShareRequestResult {
            status: err_status("shared_key_ptr is null"),
            request_wire_bytes: empty_buffer(),
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(value) => value,
        Err(_) => {
            return GenerateShareRequestResult {
                status: err_status("shared_key must be exactly 32 bytes"),
                request_wire_bytes: empty_buffer(),
            };
        }
    };

    let result = match crate::recovery::generate_share_request(
        channel_id.into(),
        secret_id,
        version,
        &shared_key,
    ) {
        Ok(value) => value,
        Err(err) => {
            return GenerateShareRequestResult {
                status: err_status(err.to_string()),
                request_wire_bytes: empty_buffer(),
            };
        }
    };

    GenerateShareRequestResult {
        status: ok_status(),
        request_wire_bytes: vec_into_buffer(result.wire_bytes),
    }
}

/// Produces a serialized recovery response envelope from a stored share envelope.
///
/// This is the C FFI entry point used by a helper/responding party to answer
/// a recovery request with the share content it currently stores.
///
/// The caller provides:
///
/// - `channel_id` as a raw `u64`
/// - `secret_id_ptr` / `secret_id_len` as secret ID bytes
/// - `request_ptr` / `request_len` as serialized outer `DeRecMessage` bytes carrying
///   an encrypted inner `GetShareRequestMessage`
/// - `stored_share_ptr` / `stored_share_len` as serialized outer `DeRecMessage` bytes
///   carrying an encrypted inner `StoreShareRequestMessage` from the sharing flow
/// - `shared_key_ptr` / `shared_key_len` as the 32-byte symmetric key for this channel
///
/// On success, this function returns serialized outer `DeRecMessage` bytes
/// carrying an encrypted inner `GetShareResponseMessage`.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier used for the response.
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `request_ptr` - Pointer to serialized outer request envelope bytes.
/// * `request_len` - Length of the serialized request buffer.
/// * `stored_share_ptr` - Pointer to serialized outer stored-share envelope bytes.
/// * `stored_share_len` - Length of the serialized stored-share buffer.
/// * `shared_key_ptr` - Pointer to 32-byte shared symmetric key bytes.
/// * `shared_key_len` - Length of the shared key buffer. Must be exactly `32`.
///
/// # Returns
///
/// Returns [`GenerateShareResponseResult`].
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - any required pointer is null while its corresponding length is greater than zero
/// - `shared_key_len != 32`
/// - the underlying Rust recovery API returns an error
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn generate_share_response(
    channel_id: u64,
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    stored_share_ptr: *const u8,
    stored_share_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> GenerateShareResponseResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateShareResponseResult {
            status: err_status("secret_id_ptr is null"),
            response_wire_bytes: empty_buffer(),
        };
    }

    if request_ptr.is_null() && request_len > 0 {
        return GenerateShareResponseResult {
            status: err_status("request_ptr is null"),
            response_wire_bytes: empty_buffer(),
        };
    }

    if stored_share_ptr.is_null() && stored_share_len > 0 {
        return GenerateShareResponseResult {
            status: err_status("stored_share_ptr is null"),
            response_wire_bytes: empty_buffer(),
        };
    }

    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return GenerateShareResponseResult {
            status: err_status("shared_key_ptr is null"),
            response_wire_bytes: empty_buffer(),
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let request_bytes: &[u8] = if request_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(request_ptr, request_len) }
    };

    let stored_share_bytes: &[u8] = if stored_share_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(stored_share_ptr, stored_share_len) }
    };

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(value) => value,
        Err(_) => {
            return GenerateShareResponseResult {
                status: err_status("shared_key must be exactly 32 bytes"),
                response_wire_bytes: empty_buffer(),
            };
        }
    };

    let result = match crate::recovery::generate_share_response(
        channel_id.into(),
        secret_id,
        request_bytes,
        stored_share_bytes,
        &shared_key,
    ) {
        Ok(value) => value,
        Err(err) => {
            return GenerateShareResponseResult {
                status: err_status(err.to_string()),
                response_wire_bytes: empty_buffer(),
            };
        }
    };

    GenerateShareResponseResult {
        status: ok_status(),
        response_wire_bytes: vec_into_buffer(result.wire_bytes),
    }
}

/// Recovers the original secret from a serialized collection of recovery response inputs.
///
/// This is the C FFI entry point used by a recovering owner/requestor after
/// enough helpers have returned share responses.
///
/// The caller provides:
///
/// - `responses_ptr` / `responses_len` as a serialized FFI collection of recovery
///   response inputs
/// - `secret_id_ptr` / `secret_id_len` as the secret ID bytes
/// - `version` as the target version to recover
///
/// Each serialized recovery response input contains:
///
/// - one serialized outer recovery response envelope
/// - the 32-byte shared key needed to decrypt that response
///
/// On success, this function returns the recovered secret bytes.
///
/// # Arguments
///
/// * `responses_ptr` - Pointer to the serialized FFI collection of recovery response inputs.
/// * `responses_len` - Length of the serialized response collection.
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `version` - Target share version to recover.
///
/// # Returns
///
/// Returns [`RecoverFromShareResponsesResult`].
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `responses_ptr` is null while `responses_len > 0`
/// - `secret_id_ptr` is null while `secret_id_len > 0`
/// - the serialized response collection is malformed
/// - any embedded shared key is not exactly 32 bytes
/// - the underlying Rust recovery API returns an error
///
/// # Safety
///
/// `responses_ptr` and `secret_id_ptr` must either be null when
/// their lengths are zero, or point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn recover_from_share_responses(
    responses_ptr: *const u8,
    responses_len: usize,
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    version: i32,
) -> RecoverFromShareResponsesResult {
    if responses_ptr.is_null() && responses_len > 0 {
        return RecoverFromShareResponsesResult {
            status: err_status("responses_ptr is null"),
            secret_data: empty_buffer(),
        };
    }

    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return RecoverFromShareResponsesResult {
            status: err_status("secret_id_ptr is null"),
            secret_data: empty_buffer(),
        };
    }

    let responses_bytes: &[u8] = if responses_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(responses_ptr, responses_len) }
    };

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let owned_inputs = match deserialize_recovery_response_inputs(responses_bytes) {
        Ok(value) => value,
        Err(err) => {
            return RecoverFromShareResponsesResult {
                status: err_status(err),
                secret_data: empty_buffer(),
            };
        }
    };

    let borrowed_inputs: Vec<RecoveryResponseInput<'_>> = owned_inputs
        .iter()
        .map(|input| RecoveryResponseInput {
            bytes: &input.response_bytes,
            shared_key: &input.shared_key,
        })
        .collect();

    let recovered_secret =
        match crate::recovery::recover_from_share_responses(secret_id, version, &borrowed_inputs) {
            Ok(value) => value,
            Err(err) => {
                return RecoverFromShareResponsesResult {
                    status: err_status(err.to_string()),
                    secret_data: empty_buffer(),
                };
            }
        };

    RecoverFromShareResponsesResult {
        status: ok_status(),
        secret_data: vec_into_buffer(recovered_secret.secret_data),
    }
}

struct OwnedRecoveryResponseInput {
    response_bytes: Vec<u8>,
    shared_key: [u8; 32],
}

fn deserialize_recovery_response_inputs(
    bytes: &[u8],
) -> Result<Vec<OwnedRecoveryResponseInput>, String> {
    let mut input = bytes;

    let count = read_u32_le(&mut input)? as usize;
    let mut responses = Vec::with_capacity(count);

    for _ in 0..count {
        let response_bytes = read_len_prefixed_vec(&mut input)?;

        if input.len() < 32 {
            return Err(
                "unexpected end of serialized recovery response inputs while reading shared key"
                    .to_string(),
            );
        }

        let shared_key: [u8; 32] = input[..32]
            .try_into()
            .map_err(|_| "failed to parse shared key".to_string())?;
        input = &input[32..];

        responses.push(OwnedRecoveryResponseInput {
            response_bytes,
            shared_key,
        });
    }

    if !input.is_empty() {
        return Err("unexpected trailing bytes in serialized recovery response inputs".to_string());
    }

    Ok(responses)
}
