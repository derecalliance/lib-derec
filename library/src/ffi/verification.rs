//! C FFI exports for the DeRec *verification* flow.
//!
//! This module exposes verification through a C-compatible ABI so that
//! non-Rust consumers can:
//!
//! 1. Create a [`VerifyShareRequestMessage`] challenge
//! 2. Produce a [`VerifyShareResponseMessage`] from stored share bytes
//! 3. Verify a received [`VerifyShareResponseMessage`] against expected share content
//!
//! The verification flow is exposed through three FFI entry points:
//!
//! - [`generate_verification_request`]
//! - [`generate_verification_response`]
//! - [`verify_share_response`]
//!
//! All exported functions follow the common FFI pattern used across the SDK:
//!
//! - Inputs are passed as primitive C values or raw byte buffers
//! - Protobuf messages are passed as serialized protobuf bytes
//! - Results are returned as `#[repr(C)]` structs containing:
//!   - a [`DeRecStatus`] indicating success or failure
//!   - one or more output values, such as [`DeRecBuffer`] or a boolean
//!
//! # FFI Conventions
//!
//! - Secret IDs and share contents are passed as `(*const u8, usize)` byte buffers
//! - Protobuf inputs are passed as raw serialized bytes
//! - Protobuf outputs are returned as raw serialized bytes
//! - Returned buffers must be released by the caller using the common FFI
//!   buffer-freeing helper exposed elsewhere in the FFI surface
//! - On error, output buffers are returned empty and `is_valid` is returned as `false`
//!   where applicable, with details reported in the returned [`DeRecStatus`]
//!
//! # Notes
//!
//! - Verification requests and responses are exchanged as serialized protobuf messages
//! - This module does not expose Rust-native verification structs directly over FFI
//! - All protobuf decoding and validation happens inside this module before the
//!   core Rust verification functions are invoked

use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
};
use derec_proto::{VerifyShareRequestMessage, VerifyShareResponseMessage};
use prost::Message;

/// FFI result returned by [`generate_verification_request`].
///
/// On success:
///
/// - `status` indicates success
/// - `verify_share_request_message` contains serialized
///   [`VerifyShareRequestMessage`] protobuf bytes
///
/// On failure:
///
/// - `status` contains an error
/// - `verify_share_request_message` is empty
#[repr(C)]
pub struct GenerateVerificationRequestResult {
    pub status: DeRecStatus,
    pub verify_share_request_message: DeRecBuffer,
}

/// FFI result returned by [`generate_verification_response`].
///
/// On success:
///
/// - `status` indicates success
/// - `verify_share_response_message` contains serialized
///   [`VerifyShareResponseMessage`] protobuf bytes
///
/// On failure:
///
/// - `status` contains an error
/// - `verify_share_response_message` is empty
#[repr(C)]
pub struct GenerateVerificationResponseResult {
    pub status: DeRecStatus,
    pub verify_share_response_message: DeRecBuffer,
}

/// FFI result returned by [`verify_share_response`].
///
/// On success:
///
/// - `status` indicates success
/// - `is_valid` indicates whether the provided response matches the expected
///   share content for the given secret/channel context
///
/// On failure:
///
/// - `status` contains an error
/// - `is_valid` is `false`
#[repr(C)]
pub struct VerifyShareResponseResult {
    pub status: DeRecStatus,
    pub is_valid: bool,
}

/// Creates a serialized [`VerifyShareRequestMessage`] challenge.
///
/// This is the C FFI entry point for the first step of the DeRec verification flow.
/// The caller provides a secret ID and version, and the function returns a serialized
/// verification request protobuf that can be sent to a helper.
///
/// # Arguments
///
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `version` - Share-distribution version being verified.
///
/// # Returns
///
/// Returns [`GenerateVerificationRequestResult`].
///
/// On success, `verify_share_request_message` contains serialized
/// [`VerifyShareRequestMessage`] protobuf bytes.
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `secret_id_ptr` is null while `secret_id_len > 0`
/// - the underlying Rust verification API returns an error
///
/// # Safety
///
/// `secret_id_ptr` must either be null when `secret_id_len == 0`, or point to
/// `secret_id_len` readable bytes.
#[unsafe(no_mangle)]
pub extern "C" fn generate_verification_request(
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    version: i32,
) -> GenerateVerificationRequestResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateVerificationRequestResult {
            status: err_status("secret_id_ptr is null"),
            verify_share_request_message: empty_buffer(),
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let request = match crate::verification::generate_verification_request(secret_id, version) {
        Ok(value) => value,
        Err(err) => {
            return GenerateVerificationRequestResult {
                status: err_status(err.to_string()),
                verify_share_request_message: empty_buffer(),
            };
        }
    };

    let request_bytes = request.encode_to_vec();

    GenerateVerificationRequestResult {
        status: ok_status(),
        verify_share_request_message: vec_into_buffer(request_bytes),
    }
}

/// Produces a serialized [`VerifyShareResponseMessage`] from a verification request.
///
/// This is the C FFI entry point used by a helper/responding party to answer
/// a verification challenge using its stored share content.
///
/// The caller provides:
///
/// - a secret ID
/// - a channel ID
/// - raw share content bytes
/// - a serialized [`VerifyShareRequestMessage`] protobuf
///
/// On success, this function returns serialized [`VerifyShareResponseMessage`] bytes.
///
/// # Arguments
///
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `channel_id` - Channel identifier associated with the share.
/// * `share_content_ptr` - Pointer to raw share content bytes.
/// * `share_content_len` - Length of the share content buffer.
/// * `request_ptr` - Pointer to serialized [`VerifyShareRequestMessage`] bytes.
/// * `request_len` - Length of the serialized request buffer.
///
/// # Returns
///
/// Returns [`GenerateVerificationResponseResult`].
///
/// On success, `verify_share_response_message` contains serialized
/// [`VerifyShareResponseMessage`] protobuf bytes.
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `secret_id_ptr` is null while `secret_id_len > 0`
/// - `share_content_ptr` is null while `share_content_len > 0`
/// - `request_ptr` is null while `request_len > 0`
/// - `request_ptr` does not contain a valid serialized [`VerifyShareRequestMessage`]
/// - the underlying Rust verification API returns an error
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn generate_verification_response(
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    channel_id: u64,
    share_content_ptr: *const u8,
    share_content_len: usize,
    request_ptr: *const u8,
    request_len: usize,
) -> GenerateVerificationResponseResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateVerificationResponseResult {
            status: err_status("secret_id_ptr is null"),
            verify_share_response_message: empty_buffer(),
        };
    }

    if share_content_ptr.is_null() && share_content_len > 0 {
        return GenerateVerificationResponseResult {
            status: err_status("share_content_ptr is null"),
            verify_share_response_message: empty_buffer(),
        };
    }

    if request_ptr.is_null() && request_len > 0 {
        return GenerateVerificationResponseResult {
            status: err_status("request_ptr is null"),
            verify_share_response_message: empty_buffer(),
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let share_content: &[u8] = if share_content_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(share_content_ptr, share_content_len) }
    };

    let request_bytes: &[u8] = if request_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(request_ptr, request_len) }
    };

    let request = match VerifyShareRequestMessage::decode(request_bytes) {
        Ok(value) => value,
        Err(err) => {
            return GenerateVerificationResponseResult {
                status: err_status(format!("invalid VerifyShareRequestMessage protobuf: {err}")),
                verify_share_response_message: empty_buffer(),
            };
        }
    };

    let response = match crate::verification::generate_verification_response(
        secret_id,
        channel_id.into(),
        share_content,
        &request,
    ) {
        Ok(value) => value,
        Err(err) => {
            return GenerateVerificationResponseResult {
                status: err_status(err.to_string()),
                verify_share_response_message: empty_buffer(),
            };
        }
    };

    let response_bytes = response.encode_to_vec();

    GenerateVerificationResponseResult {
        status: ok_status(),
        verify_share_response_message: vec_into_buffer(response_bytes),
    }
}

/// Verifies a serialized [`VerifyShareResponseMessage`] against expected share content.
///
/// This is the C FFI entry point used by the requesting party to validate a helper’s
/// verification response.
///
/// The caller provides:
///
/// - a secret ID
/// - a channel ID
/// - the expected raw share content bytes
/// - a serialized [`VerifyShareResponseMessage`] protobuf
///
/// On success, the function returns whether the response is valid for the provided
/// share content and verification context.
///
/// # Arguments
///
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `channel_id` - Channel identifier associated with the share.
/// * `share_content_ptr` - Pointer to raw share content bytes.
/// * `share_content_len` - Length of the share content buffer.
/// * `response_ptr` - Pointer to serialized [`VerifyShareResponseMessage`] bytes.
/// * `response_len` - Length of the serialized response buffer.
///
/// # Returns
///
/// Returns [`VerifyShareResponseResult`].
///
/// On success:
///
/// - `status` indicates success
/// - `is_valid` is `true` if the response verifies correctly, otherwise `false`
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `secret_id_ptr` is null while `secret_id_len > 0`
/// - `share_content_ptr` is null while `share_content_len > 0`
/// - `response_ptr` is null while `response_len > 0`
/// - `response_ptr` does not contain a valid serialized [`VerifyShareResponseMessage`]
/// - the underlying Rust verification API returns an error
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn verify_share_response(
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    channel_id: u64,
    share_content_ptr: *const u8,
    share_content_len: usize,
    response_ptr: *const u8,
    response_len: usize,
) -> VerifyShareResponseResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return VerifyShareResponseResult {
            status: err_status("secret_id_ptr is null"),
            is_valid: false,
        };
    }

    if share_content_ptr.is_null() && share_content_len > 0 {
        return VerifyShareResponseResult {
            status: err_status("share_content_ptr is null"),
            is_valid: false,
        };
    }

    if response_ptr.is_null() && response_len > 0 {
        return VerifyShareResponseResult {
            status: err_status("response_ptr is null"),
            is_valid: false,
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let share_content: &[u8] = if share_content_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(share_content_ptr, share_content_len) }
    };

    let response_bytes: &[u8] = if response_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(response_ptr, response_len) }
    };

    let response = match VerifyShareResponseMessage::decode(response_bytes) {
        Ok(value) => value,
        Err(err) => {
            return VerifyShareResponseResult {
                status: err_status(format!(
                    "invalid VerifyShareResponseMessage protobuf: {err}"
                )),
                is_valid: false,
            };
        }
    };

    let is_valid = match crate::verification::verify_share_response(
        secret_id,
        channel_id.into(),
        share_content,
        &response,
    ) {
        Ok(value) => value,
        Err(err) => {
            return VerifyShareResponseResult {
                status: err_status(err.to_string()),
                is_valid: false,
            };
        }
    };

    VerifyShareResponseResult {
        status: ok_status(),
        is_valid,
    }
}
