//! C FFI exports for the DeRec *verification* flow.
//!
//! This module exposes verification through a C-compatible ABI so that
//! non-Rust consumers can:
//!
//! 1. Create a verification request envelope
//! 2. Produce a verification response envelope from stored share bytes
//! 3. Verify a received verification response envelope against expected share content
//!
//! The verification flow is exposed through three FFI entry points:
//!
//! - [`generate_verification_request`]
//! - [`generate_verification_response`]
//! - [`verify_share_response`]
//!
//! All exported functions follow the common FFI pattern used across the SDK:
//!
//! - inputs are passed as primitive C values or raw byte buffers
//! - protocol messages are passed as serialized wire bytes
//! - results are returned as `#[repr(C)]` structs containing:
//!   - a [`DeRecStatus`] indicating success or failure
//!   - one or more output values, such as [`DeRecBuffer`] or a boolean
//!
//! # FFI Conventions
//!
//! - secret IDs and share contents are passed as `(*const u8, usize)` byte buffers
//! - shared symmetric keys are passed as `(*const u8, usize)` byte buffers and must
//!   be exactly 32 bytes long
//! - request and response inputs are passed as serialized outer `DeRecMessage` bytes
//! - request and response outputs are returned as serialized outer `DeRecMessage` bytes
//! - returned buffers must be released by the caller using the common FFI
//!   buffer-freeing helper exposed elsewhere in the FFI surface
//! - on error, output buffers are returned empty and `is_valid` is returned as `false`
//!   where applicable, with details reported in the returned [`DeRecStatus`]
//!
//! # Notes
//!
//! - verification requests and responses are exchanged as serialized outer
//!   `DeRecMessage` envelopes whose inner messages are encrypted
//! - this module does not expose Rust-native verification structs directly over FFI
//! - protobuf decoding and protocol validation are delegated to the core Rust SDK

use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
};

/// FFI result returned by [`generate_verification_request`].
///
/// On success:
///
/// - `status` indicates success
/// - `verify_share_request_message` contains serialized outer `DeRecMessage` bytes
///   carrying an encrypted inner `VerifyShareRequestMessage`
///
/// On failure:
///
/// - `status` contains an error
/// - `verify_share_request_message` is empty
#[repr(C)]
pub struct GenerateVerificationRequestResult {
    pub status: DeRecStatus,
    pub request_wire_bytes: DeRecBuffer,
}

/// FFI result returned by [`generate_verification_response`].
///
/// On success:
///
/// - `status` indicates success
/// - `verify_share_response_message` contains serialized outer `DeRecMessage` bytes
///   carrying an encrypted inner `VerifyShareResponseMessage`
///
/// On failure:
///
/// - `status` contains an error
/// - `verify_share_response_message` is empty
#[repr(C)]
pub struct GenerateVerificationResponseResult {
    pub status: DeRecStatus,
    pub response_wire_bytes: DeRecBuffer,
}

/// FFI result returned by [`verify_share_response`].
///
/// On success:
///
/// - `status` indicates success
/// - `is_valid` indicates whether the provided response matches the expected
///   share content
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

/// Creates a serialized verification request envelope.
///
/// This is the C FFI entry point for the first step of the DeRec verification flow.
///
/// The caller provides:
///
/// - a secret ID
/// - a channel ID
/// - a share-distribution version
/// - the 32-byte shared symmetric key established during pairing
///
/// On success, this function returns serialized outer `DeRecMessage` bytes
/// carrying an encrypted inner `VerifyShareRequestMessage`.
///
/// # Arguments
///
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `channel_id` - Channel identifier associated with the paired helper.
/// * `version` - Share-distribution version being verified.
/// * `shared_key_ptr` - Pointer to 32-byte shared symmetric key bytes.
/// * `shared_key_len` - Length of the shared key buffer. Must be exactly `32`.
///
/// # Returns
///
/// Returns [`GenerateVerificationRequestResult`].
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `secret_id_ptr` is null while `secret_id_len > 0`
/// - `shared_key_ptr` is null while `shared_key_len > 0`
/// - `shared_key_len != 32`
/// - the underlying Rust verification API returns an error
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn generate_verification_request(
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    channel_id: u64,
    version: i32,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> GenerateVerificationRequestResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateVerificationRequestResult {
            status: err_status("secret_id_ptr is null"),
            request_wire_bytes: empty_buffer(),
        };
    }

    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return GenerateVerificationRequestResult {
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
            return GenerateVerificationRequestResult {
                status: err_status("shared_key must be exactly 32 bytes"),
                request_wire_bytes: empty_buffer(),
            };
        }
    };

    let result = match crate::verification::generate_verification_request(
        secret_id,
        channel_id.into(),
        version,
        &shared_key,
    ) {
        Ok(value) => value,
        Err(err) => {
            return GenerateVerificationRequestResult {
                status: err_status(err.to_string()),
                request_wire_bytes: empty_buffer(),
            };
        }
    };

    GenerateVerificationRequestResult {
        status: ok_status(),
        request_wire_bytes: vec_into_buffer(result.wire_bytes),
    }
}

/// Produces a serialized verification response envelope from a verification request.
///
/// This is the C FFI entry point used by a helper/responding party to answer
/// a verification challenge using its stored share content.
///
/// The caller provides:
///
/// - a secret ID
/// - a channel ID
/// - the 32-byte shared symmetric key established during pairing
/// - raw share content bytes
/// - serialized outer `DeRecMessage` bytes carrying an encrypted inner
///   `VerifyShareRequestMessage`
///
/// On success, this function returns serialized outer `DeRecMessage` bytes
/// carrying an encrypted inner `VerifyShareResponseMessage`.
///
/// # Arguments
///
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `channel_id` - Channel identifier associated with the share.
/// * `shared_key_ptr` - Pointer to 32-byte shared symmetric key bytes.
/// * `shared_key_len` - Length of the shared key buffer. Must be exactly `32`.
/// * `share_content_ptr` - Pointer to raw share content bytes.
/// * `share_content_len` - Length of the share content buffer.
/// * `request_ptr` - Pointer to serialized outer request envelope bytes.
/// * `request_len` - Length of the serialized request buffer.
///
/// # Returns
///
/// Returns [`GenerateVerificationResponseResult`].
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `secret_id_ptr` is null while `secret_id_len > 0`
/// - `shared_key_ptr` is null while `shared_key_len > 0`
/// - `shared_key_len != 32`
/// - `share_content_ptr` is null while `share_content_len > 0`
/// - `request_ptr` is null while `request_len > 0`
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
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    share_content_ptr: *const u8,
    share_content_len: usize,
    request_ptr: *const u8,
    request_len: usize,
) -> GenerateVerificationResponseResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateVerificationResponseResult {
            status: err_status("secret_id_ptr is null"),
            response_wire_bytes: empty_buffer(),
        };
    }

    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return GenerateVerificationResponseResult {
            status: err_status("shared_key_ptr is null"),
            response_wire_bytes: empty_buffer(),
        };
    }

    if share_content_ptr.is_null() && share_content_len > 0 {
        return GenerateVerificationResponseResult {
            status: err_status("share_content_ptr is null"),
            response_wire_bytes: empty_buffer(),
        };
    }

    if request_ptr.is_null() && request_len > 0 {
        return GenerateVerificationResponseResult {
            status: err_status("request_ptr is null"),
            response_wire_bytes: empty_buffer(),
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
            return GenerateVerificationResponseResult {
                status: err_status("shared_key must be exactly 32 bytes"),
                response_wire_bytes: empty_buffer(),
            };
        }
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

    let result = match crate::verification::generate_verification_response(
        secret_id,
        channel_id.into(),
        &shared_key,
        share_content,
        request_bytes,
    ) {
        Ok(value) => value,
        Err(err) => {
            return GenerateVerificationResponseResult {
                status: err_status(err.to_string()),
                response_wire_bytes: empty_buffer(),
            };
        }
    };

    GenerateVerificationResponseResult {
        status: ok_status(),
        response_wire_bytes: vec_into_buffer(result.wire_bytes),
    }
}

/// Verifies a serialized verification response envelope against expected share content.
///
/// This is the C FFI entry point used by the requesting party to validate a helper’s
/// verification response.
///
/// The caller provides:
///
/// - a secret ID
/// - a channel ID
/// - the 32-byte shared symmetric key established during pairing
/// - the expected raw share content bytes
/// - serialized outer `DeRecMessage` bytes carrying an encrypted inner
///   `VerifyShareResponseMessage`
///
/// On success, the function returns whether the response is valid for the provided
/// share content.
///
/// # Arguments
///
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `channel_id` - Channel identifier associated with the share.
/// * `shared_key_ptr` - Pointer to 32-byte shared symmetric key bytes.
/// * `shared_key_len` - Length of the shared key buffer. Must be exactly `32`.
/// * `share_content_ptr` - Pointer to raw share content bytes.
/// * `share_content_len` - Length of the share content buffer.
/// * `response_ptr` - Pointer to serialized outer response envelope bytes.
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
/// - `shared_key_ptr` is null while `shared_key_len > 0`
/// - `shared_key_len != 32`
/// - `share_content_ptr` is null while `share_content_len > 0`
/// - `response_ptr` is null while `response_len > 0`
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
    shared_key_ptr: *const u8,
    shared_key_len: usize,
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

    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return VerifyShareResponseResult {
            status: err_status("shared_key_ptr is null"),
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

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(value) => value,
        Err(_) => {
            return VerifyShareResponseResult {
                status: err_status("shared_key must be exactly 32 bytes"),
                is_valid: false,
            };
        }
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

    let is_valid = match crate::verification::verify_share_response(
        secret_id,
        channel_id.into(),
        &shared_key,
        share_content,
        response_bytes,
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
