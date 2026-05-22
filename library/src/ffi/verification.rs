//! C FFI exports for the DeRec *verification* flow.
//!
//! This module exposes verification through a C-compatible ABI so that
//! non-Rust consumers can run the complete Owner/Helper protocol.
//!
//! **Owner side**
//!
//! 1. [`produce_verify_share_request_message`] — builds the encrypted challenge envelope
//! 2. [`process_verify_share_response_message`] — decrypts and validates the Helper's proof
//!
//! **Helper side**
//!
//! 1. [`extract_verify_share_request`] — decodes the outer envelope from wire bytes and
//!    decrypts the inner challenge using the channel shared key, returning `channel_id`,
//!    `secret_id`, `version`, and `nonce` in one call
//! 2. [`produce_verify_share_response_message`] — builds the encrypted proof envelope
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
//! - request and response wire bytes are serialized outer `DeRecMessage` envelopes
//! - returned buffers must be released by the caller via the common FFI buffer-freeing helper
//! - on error, output buffers are returned empty and `is_valid` is `false` where applicable

use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
};
use derec_proto::DeRecMessage;
use prost::Message as _;

/// FFI result returned by [`produce_verify_share_request_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `request_wire_bytes` contains serialized outer `DeRecMessage` bytes
///   carrying an encrypted inner `VerifyShareRequestMessage`
/// - `message_type` is the `MessageType` discriminant from the outer envelope
///
/// On failure:
///
/// - `status` contains an error
/// - `request_wire_bytes` is empty
#[repr(C)]
pub struct ProduceVerifyShareRequestMessageResult {
    pub status: DeRecStatus,
    pub request_wire_bytes: DeRecBuffer,
    pub message_type: i32,
}

/// FFI result returned by [`extract_verify_share_request`].
///
/// On success:
///
/// - `status` indicates success
/// - `channel_id` is the channel extracted from the **unencrypted** outer envelope
/// - `secret_id` is the secret identifier from the decrypted inner request
/// - `version` is the share-distribution version being challenged
/// - `nonce` is the Owner's random challenge value — pass unchanged to
///   [`produce_verify_share_response_message`]
///
/// On failure:
///
/// - `status` contains an error
/// - all other fields are zeroed / empty
#[repr(C)]
pub struct ExtractVerifyShareRequestResult {
    pub status: DeRecStatus,
    pub channel_id: u64,
    pub secret_id: u64,
    pub version: u32,
    pub nonce: u64,
}

/// FFI result returned by [`produce_verify_share_response_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `response_wire_bytes` contains serialized outer `DeRecMessage` bytes
///   carrying an encrypted inner `VerifyShareResponseMessage`
/// - `message_type` is the `MessageType` discriminant from the outer envelope
///
/// On failure:
///
/// - `status` contains an error
/// - `response_wire_bytes` is empty
#[repr(C)]
pub struct ProduceVerifyShareResponseMessageResult {
    pub status: DeRecStatus,
    pub response_wire_bytes: DeRecBuffer,
    pub message_type: i32,
}

/// FFI result returned by [`process_verify_share_response_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `is_valid` indicates whether the SHA-384 proof matches the expected share content
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

/// Creates a serialized verification request envelope (Owner side, step 1).
///
/// Embeds `secret_id`, `version`, a fresh nonce, and a timestamp inside an encrypted
/// inner `VerifyShareRequestMessage`, then wraps it in an outer `DeRecMessage` envelope.
/// The envelope's `message_type` is set to `VERIFY_SHARE_REQUEST`.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier for the paired Helper.
/// * `secret_id_ptr` / `secret_id_len` - Secret ID bytes embedded in the request.
/// * `version` - Share-distribution version being verified.
/// * `shared_key_ptr` / `shared_key_len` - 32-byte shared symmetric key. Must be exactly 32.
///
/// # Returns
///
/// Returns [`ProduceVerifyShareRequestMessageResult`].
///
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
) -> ProduceVerifyShareRequestMessageResult {
    let err = |msg: &str| ProduceVerifyShareRequestMessageResult {
        status: err_status(msg),
        request_wire_bytes: empty_buffer(),
        message_type: 0,
    };

    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return err("shared_key_ptr is null");
    }

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(v) => v,
        Err(_) => return err("shared_key must be exactly 32 bytes"),
    };

    match crate::primitives::verification::request::produce(
        channel_id.into(),
        secret_id,
        version,
        &shared_key,
    ) {
        Ok(r) => ProduceVerifyShareRequestMessageResult {
            status: ok_status(),
            request_wire_bytes: vec_into_buffer(r.envelope),
            message_type: 0,
        },
        Err(e) => err(&e.to_string()),
    }
}

/// Decodes and decrypts a verification request envelope (Helper side, step 1).
///
/// Decodes the outer `DeRecMessage` from wire bytes, then decrypts the inner
/// `VerifyShareRequestMessage` using the channel's shared key. Validates the timestamp
/// invariant and returns `channel_id`, `secret_id`, `version`, and `nonce` in a single call.
///
/// # Arguments
///
/// * `request_ptr` / `request_len` - Serialized outer `DeRecMessage` wire bytes.
/// * `shared_key_ptr` / `shared_key_len` - 32-byte shared symmetric key. Must be exactly 32.
///
/// # Returns
///
/// Returns [`ExtractVerifyShareRequestResult`].
///
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
    let err = |msg: &str| ExtractVerifyShareRequestResult {
        status: err_status(msg),
        channel_id: 0,
        secret_id: 0,
        version: 0,
        nonce: 0,
    };

    if request_ptr.is_null() && request_len > 0 {
        return err("request_ptr is null");
    }
    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return err("shared_key_ptr is null");
    }

    let request_bytes: &[u8] = if request_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(request_ptr, request_len) }
    };

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(v) => v,
        Err(_) => return err("shared_key must be exactly 32 bytes"),
    };

    let channel_id = match DeRecMessage::decode(request_bytes) {
        Ok(e) => e.channel_id,
        Err(e) => return err(&format!("failed to decode envelope: {e}")),
    };

    match crate::primitives::verification::request::extract(request_bytes, &shared_key) {
        Ok(r) => ExtractVerifyShareRequestResult {
            status: ok_status(),
            channel_id,
            secret_id: r.request.secret_id,
            version: r.request.version,
            nonce: r.request.nonce,
        },
        Err(e) => err(&e.to_string()),
    }
}

/// Produces a serialized verification response envelope (Helper side, step 2).
///
/// Computes `SHA384(share_content || nonce_be)` and returns an encrypted
/// `VerifyShareResponseMessage` with the proof and all echoed request fields.
/// The envelope's `message_type` is set to `VERIFY_SHARE_RESPONSE`.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier.
/// * `secret_id_ptr` / `secret_id_len` - Secret ID from [`extract_verify_share_request`].
///   Echoed verbatim into the response.
/// * `version` - Version from [`extract_verify_share_request`].
/// * `nonce` - Nonce from [`extract_verify_share_request`]. Must be passed unchanged.
/// * `shared_key_ptr` / `shared_key_len` - 32-byte shared symmetric key. Must be exactly 32.
/// * `share_content_ptr` / `share_content_len` - Raw share bytes whose possession is proven.
///
/// # Returns
///
/// Returns [`ProduceVerifyShareResponseMessageResult`].
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_verify_share_response_message(
    channel_id: u64,
    secret_id: u64,
    version: u32,
    nonce: u64,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    share_content_ptr: *const u8,
    share_content_len: usize,
) -> ProduceVerifyShareResponseMessageResult {
    let err = |msg: &str| ProduceVerifyShareResponseMessageResult {
        status: err_status(msg),
        response_wire_bytes: empty_buffer(),
        message_type: 0,
    };

    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return err("shared_key_ptr is null");
    }
    if share_content_ptr.is_null() && share_content_len > 0 {
        return err("share_content_ptr is null");
    }

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(v) => v,
        Err(_) => return err("shared_key must be exactly 32 bytes"),
    };

    let share_content: &[u8] = if share_content_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(share_content_ptr, share_content_len) }
    };

    let request = derec_proto::VerifyShareRequestMessage {
        secret_id,
        version,
        nonce,
        timestamp: None,
    };

    match crate::primitives::verification::response::produce(
        channel_id.into(),
        &request,
        &shared_key,
        share_content,
    ) {
        Ok(r) => ProduceVerifyShareResponseMessageResult {
            status: ok_status(),
            response_wire_bytes: vec_into_buffer(r.envelope),
            message_type: 0,
        },
        Err(e) => err(&e.to_string()),
    }
}

/// Decrypts and validates a verification response envelope (Owner side, step 2).
///
/// Decodes the outer `DeRecMessage`, decrypts the inner `VerifyShareResponseMessage`,
/// validates the timestamp invariant, and checks whether the SHA-384 proof matches
/// `SHA384(share_content || nonce_be)`.
///
/// # Arguments
///
/// * `response_ptr` / `response_len` - Serialized outer `DeRecMessage` response wire bytes.
/// * `shared_key_ptr` / `shared_key_len` - 32-byte shared symmetric key. Must be exactly 32.
/// * `share_content_ptr` / `share_content_len` - Expected share bytes.
///
/// # Returns
///
/// Returns [`VerifyShareResponseResult`].
///
/// On success `is_valid` is `true` if the proof matches, `false` otherwise.
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_verify_share_response_message(
    response_ptr: *const u8,
    response_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    share_content_ptr: *const u8,
    share_content_len: usize,
) -> VerifyShareResponseResult {
    let err = |msg: &str| VerifyShareResponseResult {
        status: err_status(msg),
        is_valid: false,
    };

    if response_ptr.is_null() && response_len > 0 {
        return err("response_ptr is null");
    }
    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return err("shared_key_ptr is null");
    }
    if share_content_ptr.is_null() && share_content_len > 0 {
        return err("share_content_ptr is null");
    }

    let response_bytes: &[u8] = if response_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(response_ptr, response_len) }
    };

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(v) => v,
        Err(_) => return err("shared_key must be exactly 32 bytes"),
    };

    let share_content: &[u8] = if share_content_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(share_content_ptr, share_content_len) }
    };

    let extract_result = match crate::primitives::verification::response::extract(response_bytes, &shared_key) {
        Ok(r) => r,
        Err(e) => return err(&e.to_string()),
    };

    match crate::primitives::verification::response::process(
        &extract_result.response,
        share_content,
    ) {
        Ok(is_valid) => VerifyShareResponseResult {
            status: ok_status(),
            is_valid,
        },
        Err(e) => err(&e.to_string()),
    }
}
