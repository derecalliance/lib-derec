//! C FFI exports for the DeRec *recovery* flow.
//!
//! This module exposes the recovery flow through a C-compatible ABI so that
//! non-Rust consumers can:
//!
//! 1. Create a [`GetShareRequestMessage`] for a target secret/version
//! 2. Produce a [`GetShareResponseMessage`] from a stored share
//! 3. Recover the original secret from a set of share responses
//!
//! All exported functions follow the same general pattern:
//!
//! - Inputs are passed as primitive C values or raw byte buffers
//! - Protobuf messages are passed as serialized protobuf bytes
//! - Results are returned as `#[repr(C)]` structs containing:
//!   - a [`DeRecStatus`] indicating success or failure
//!   - one or more [`DeRecBuffer`] values containing output bytes
//!
//! # FFI Conventions
//!
//! - Secret IDs are passed as `(*const u8, usize)` byte buffers
//! - Protobuf inputs are passed as raw serialized bytes
//! - Protobuf outputs are returned as raw serialized bytes
//! - Returned buffers must be released by the caller using the common FFI
//!   buffer-freeing helper exposed elsewhere in the FFI surface
//! - On error, output buffers are returned empty and details are reported in
//!   the returned [`DeRecStatus`]
//!
//! # Serialized Share Response Collection
//!
//! [`recover_from_share_responses`] accepts a custom FFI byte encoding representing
//! a sequence of serialized [`GetShareResponseMessage`] values:
//!
//! 1. A 32-bit little-endian count
//! 2. For each entry:
//!    - a length-prefixed serialized [`GetShareResponseMessage`]
//!
//! This collection format is specific to the FFI layer and should be treated as
//! an opaque transport container by foreign callers.
//!
//! # Notes
//!
//! - This module does not expose Rust collection types directly over FFI
//! - All protobuf decoding and validation happens inside this module before the
//!   core Rust recovery functions are invoked

use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, read_len_prefixed_vec,
    read_u32_le, vec_into_buffer,
};
use derec_proto::{GetShareRequestMessage, GetShareResponseMessage, StoreShareRequestMessage};
use prost::Message;

/// FFI result returned by [`generate_share_request`].
///
/// On success:
///
/// - `status` indicates success
/// - `get_share_request_message` contains serialized [`GetShareRequestMessage`] protobuf bytes
///
/// On failure:
///
/// - `status` contains an error
/// - output buffers are empty
#[repr(C)]
pub struct GenerateShareRequestResult {
    pub status: DeRecStatus,
    pub get_share_request_message: DeRecBuffer,
}

/// FFI result returned by [`generate_share_response`].
///
/// On success:
///
/// - `status` indicates success
/// - `get_share_response_message` contains serialized [`GetShareResponseMessage`] protobuf bytes
///
/// On failure:
///
/// - `status` contains an error
/// - output buffers are empty
#[repr(C)]
pub struct GenerateShareResponseResult {
    pub status: DeRecStatus,
    pub get_share_response_message: DeRecBuffer,
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

/// Creates a serialized [`GetShareRequestMessage`] for the recovery flow.
///
/// This is the C FFI entry point used by a recovering owner/requestor to ask
/// a helper for the share associated with a particular secret ID and version.
///
/// The caller provides:
///
/// - `channel_id` as a raw `u64`
/// - `secret_id_ptr` / `secret_id_len` as a secret ID byte buffer
/// - `version` as the target share version
///
/// On success, this function returns serialized [`GetShareRequestMessage`] protobuf bytes.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier used for the request.
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `version` - Requested share version.
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
/// - the underlying Rust recovery API returns an error
///
/// # Safety
///
/// `secret_id_ptr` must either be null when `secret_id_len == 0`, or point to
/// `secret_id_len` readable bytes.
#[unsafe(no_mangle)]
pub extern "C" fn generate_share_request(
    channel_id: u64,
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    version: i32,
) -> GenerateShareRequestResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateShareRequestResult {
            status: err_status("secret_id_ptr is null"),
            get_share_request_message: empty_buffer(),
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let request =
        match crate::recovery::generate_share_request(channel_id.into(), secret_id, version) {
            Ok(value) => value,
            Err(err) => {
                return GenerateShareRequestResult {
                    status: err_status(err.to_string()),
                    get_share_request_message: empty_buffer(),
                };
            }
        };

    let request_bytes = request.encode_to_vec();

    GenerateShareRequestResult {
        status: ok_status(),
        get_share_request_message: vec_into_buffer(request_bytes),
    }
}

/// Produces a serialized [`GetShareResponseMessage`] from a stored share.
///
/// This is the C FFI entry point used by a helper/responding party to answer
/// a recovery request with the share content it currently stores.
///
/// The caller provides:
///
/// - `channel_id` as a raw `u64`
/// - `secret_id_ptr` / `secret_id_len` as secret ID bytes
/// - `request_ptr` / `request_len` as serialized [`GetShareRequestMessage`] bytes
/// - `share_content_ptr` / `share_content_len` as serialized
///   [`StoreShareRequestMessage`] bytes representing the stored share
///
/// On success, this function returns serialized [`GetShareResponseMessage`] bytes.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier used for the response.
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `request_ptr` - Pointer to serialized [`GetShareRequestMessage`] bytes.
/// * `request_len` - Length of the serialized request buffer.
/// * `share_content_ptr` - Pointer to serialized [`StoreShareRequestMessage`] bytes.
/// * `share_content_len` - Length of the serialized share content buffer.
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
/// - `request_ptr` does not contain a valid serialized [`GetShareRequestMessage`]
/// - `share_content_ptr` does not contain a valid serialized [`StoreShareRequestMessage`]
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
    share_content_ptr: *const u8,
    share_content_len: usize,
) -> GenerateShareResponseResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateShareResponseResult {
            status: err_status("secret_id_ptr is null"),
            get_share_response_message: empty_buffer(),
        };
    }

    if request_ptr.is_null() && request_len > 0 {
        return GenerateShareResponseResult {
            status: err_status("request_ptr is null"),
            get_share_response_message: empty_buffer(),
        };
    }

    if share_content_ptr.is_null() && share_content_len > 0 {
        return GenerateShareResponseResult {
            status: err_status("share_content_ptr is null"),
            get_share_response_message: empty_buffer(),
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

    let share_content_bytes: &[u8] = if share_content_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(share_content_ptr, share_content_len) }
    };

    let request = match GetShareRequestMessage::decode(request_bytes) {
        Ok(value) => value,
        Err(err) => {
            return GenerateShareResponseResult {
                status: err_status(format!("invalid GetShareRequestMessage protobuf: {err}")),
                get_share_response_message: empty_buffer(),
            };
        }
    };

    let share_content = match StoreShareRequestMessage::decode(share_content_bytes) {
        Ok(value) => value,
        Err(err) => {
            return GenerateShareResponseResult {
                status: err_status(format!("invalid StoreShareRequestMessage protobuf: {err}")),
                get_share_response_message: empty_buffer(),
            };
        }
    };

    let response = match crate::recovery::generate_share_response(
        channel_id.into(),
        secret_id,
        &request,
        &share_content,
    ) {
        Ok(value) => value,
        Err(err) => {
            return GenerateShareResponseResult {
                status: err_status(err.to_string()),
                get_share_response_message: empty_buffer(),
            };
        }
    };

    let response_bytes = response.encode_to_vec();

    GenerateShareResponseResult {
        status: ok_status(),
        get_share_response_message: vec_into_buffer(response_bytes),
    }
}

/// Recovers the original secret from a serialized collection of share responses.
///
/// This is the C FFI entry point used by a recovering owner/requestor after
/// enough helpers have returned share responses.
///
/// The caller provides:
///
/// - `responses_ptr` / `responses_len` as a serialized FFI collection of
///   [`GetShareResponseMessage`] values
/// - `secret_id_ptr` / `secret_id_len` as the secret ID bytes
/// - `version` as the target version to recover
///
/// On success, this function returns the recovered secret bytes.
///
/// # Arguments
///
/// * `responses_ptr` - Pointer to the serialized FFI collection of share responses.
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
/// - any contained entry is not a valid serialized [`GetShareResponseMessage`]
/// - the underlying Rust recovery API returns an error
///
/// # Safety
///
/// `responses_ptr` and `secret_id_ptr` must either be null when their lengths are zero,
/// or point to the corresponding readable byte ranges.
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

    let responses = match deserialize_share_responses(responses_bytes) {
        Ok(value) => value,
        Err(err) => {
            return RecoverFromShareResponsesResult {
                status: err_status(err),
                secret_data: empty_buffer(),
            };
        }
    };

    let recovered_secret =
        match crate::recovery::recover_from_share_responses(&responses, secret_id, version) {
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
        secret_data: vec_into_buffer(recovered_secret),
    }
}

fn deserialize_share_responses(bytes: &[u8]) -> Result<Vec<GetShareResponseMessage>, String> {
    let mut input = bytes;

    let count = read_u32_le(&mut input)? as usize;
    let mut responses = Vec::with_capacity(count);

    for _ in 0..count {
        let encoded = read_len_prefixed_vec(&mut input)?;
        let response = GetShareResponseMessage::decode(encoded.as_slice())
            .map_err(|err| format!("invalid GetShareResponseMessage protobuf: {err}"))?;
        responses.push(response);
    }

    if !input.is_empty() {
        return Err("unexpected trailing bytes in serialized share responses".to_string());
    }

    Ok(responses)
}
