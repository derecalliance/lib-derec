//! C FFI exports for the DeRec *unpairing* flow.
//!
//! Exposes the unpairing primitive through a C-compatible ABI so non-Rust
//! consumers can drive the full Initiator/Responder flow.
//!
//! **Initiator side**
//!
//! 1. [`produce_unpair_request_message`] — builds the encrypted request envelope
//! 2. [`process_unpair_response_message`] — decrypts and validates the
//!    responder's acknowledgement
//!
//! **Responder side**
//!
//! 1. [`extract_unpair_request`] — decodes the outer envelope from wire bytes
//!    and decrypts the inner request using the channel shared key, returning
//!    `channel_id` and `memo` in one call
//! 2. [`produce_unpair_response_message`] — builds the encrypted ack envelope
//!    (success or rejection, selected via the `status` field)
//!
//! All exported functions follow the common FFI pattern used across the SDK:
//!
//! - inputs are passed as primitive C values or raw byte buffers
//! - protocol messages are passed as serialized wire bytes
//! - results are returned as `#[repr(C)]` structs containing a
//!   [`DeRecStatus`] and the function-specific outputs
//! - returned buffers must be released by the caller via the common FFI
//!   buffer-freeing helper
//! - on error, output buffers are returned empty and boolean flags are
//!   `false` where applicable

use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
};
use derec_proto::{DeRecMessage, StatusEnum};
use prost::Message as _;
use std::ffi::CStr;
use std::os::raw::c_char;

/// FFI result returned by [`produce_unpair_request_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `request_wire_bytes` contains the serialized outer `DeRecMessage` bytes
///   carrying an encrypted inner `UnpairRequestMessage`
///
/// On failure:
///
/// - `status` contains an error
/// - `request_wire_bytes` is empty
#[repr(C)]
pub struct ProduceUnpairRequestMessageResult {
    pub status: DeRecStatus,
    pub request_wire_bytes: DeRecBuffer,
}

/// FFI result returned by [`extract_unpair_request`].
///
/// On success:
///
/// - `status` indicates success
/// - `channel_id` is the channel extracted from the **unencrypted** outer envelope
/// - `memo` is the (heap-allocated, NUL-terminated) human-readable reason
///   embedded in the request. The caller must release it with
///   [`crate::ffi::common::derec_free_string`].
///
/// On failure all output fields are zero / null.
#[repr(C)]
pub struct ExtractUnpairRequestResult {
    pub status: DeRecStatus,
    pub channel_id: u64,
    pub memo: *mut c_char,
}

/// FFI result returned by [`produce_unpair_response_message`].
///
/// On success carries the serialized outer `DeRecMessage` envelope; on
/// failure the buffer is empty.
#[repr(C)]
pub struct ProduceUnpairResponseMessageResult {
    pub status: DeRecStatus,
    pub response_wire_bytes: DeRecBuffer,
}

/// FFI result returned by [`process_unpair_response_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `acknowledged` is `true` when the responder returned `Ok`, `false`
///   for any non-`Ok` status
/// - `response_status` is the raw `StatusEnum` integer from the response
///
/// On failure `acknowledged` is `false` and `response_status` is `0`.
#[repr(C)]
pub struct ProcessUnpairResponseResult {
    pub status: DeRecStatus,
    pub acknowledged: bool,
    pub response_status: i32,
}

/// Creates a serialized unpair request envelope (Initiator side).
///
/// # Arguments
///
/// * `channel_id` - Channel identifier for the paired peer.
/// * `memo_ptr` / `memo_len` - Optional human-readable reason. Pass
///   `(null, 0)` or a zero-length slice to send an empty memo. The bytes
///   are interpreted as UTF-8; invalid sequences fail.
/// * `shared_key_ptr` / `shared_key_len` - 32-byte shared symmetric key.
///   Must be exactly 32 bytes.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte
/// ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_unpair_request_message(
    channel_id: u64,
    memo_ptr: *const u8,
    memo_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ProduceUnpairRequestMessageResult {
    let err = |msg: &str| ProduceUnpairRequestMessageResult {
        status: err_status(msg),
        request_wire_bytes: empty_buffer(),
    };

    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return err("shared_key_ptr is null");
    }
    if memo_ptr.is_null() && memo_len > 0 {
        return err("memo_ptr is null");
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

    let memo_bytes: &[u8] = if memo_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(memo_ptr, memo_len) }
    };
    let memo = match std::str::from_utf8(memo_bytes) {
        Ok(s) => s,
        Err(_) => return err("memo is not valid UTF-8"),
    };

    match crate::primitives::unpairing::request::produce(channel_id.into(), memo, &shared_key) {
        Ok(r) => ProduceUnpairRequestMessageResult {
            status: ok_status(),
            request_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => err(&e.to_string()),
    }
}

/// Decodes and decrypts an unpair request envelope (Responder side).
///
/// Returns the unencrypted outer `channel_id` and the decrypted inner `memo`.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte
/// ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_unpair_request(
    request_ptr: *const u8,
    request_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractUnpairRequestResult {
    let err = |msg: &str| ExtractUnpairRequestResult {
        status: err_status(msg),
        channel_id: 0,
        memo: std::ptr::null_mut(),
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

    match crate::primitives::unpairing::request::extract(request_bytes, &shared_key) {
        Ok(r) => {
            let memo_c = match std::ffi::CString::new(r.request.memo) {
                Ok(s) => s.into_raw(),
                Err(_) => return err("memo contains an interior NUL byte"),
            };
            ExtractUnpairRequestResult {
                status: ok_status(),
                channel_id,
                memo: memo_c,
            }
        }
        Err(e) => err(&e.to_string()),
    }
}

/// Produces a serialized unpair response envelope (Responder side).
///
/// Pass `StatusEnum::Ok` (`0`) for a successful acknowledgement, or any
/// other variant (e.g. `Fail`, `Rejected`) to reject. The `memo` argument
/// is included verbatim in the response (UTF-8 NUL-terminated C string).
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable
/// byte ranges or NUL-terminated C strings.
#[unsafe(no_mangle)]
pub extern "C" fn produce_unpair_response_message(
    channel_id: u64,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    status: i32,
    memo: *const c_char,
) -> ProduceUnpairResponseMessageResult {
    let err = |msg: &str| ProduceUnpairResponseMessageResult {
        status: err_status(msg),
        response_wire_bytes: empty_buffer(),
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

    let memo_str: &str = if memo.is_null() {
        ""
    } else {
        match unsafe { CStr::from_ptr(memo) }.to_str() {
            Ok(s) => s,
            Err(_) => return err("memo is not valid UTF-8"),
        }
    };

    let result = if status == StatusEnum::Ok as i32 {
        crate::primitives::unpairing::response::produce(channel_id.into(), &shared_key)
    } else {
        let status_enum = match StatusEnum::try_from(status) {
            Ok(s) => s,
            Err(_) => return err(&format!("invalid StatusEnum value: {status}")),
        };
        crate::primitives::unpairing::response::reject(
            channel_id.into(),
            &shared_key,
            status_enum,
            memo_str,
        )
    };

    match result {
        Ok(r) => ProduceUnpairResponseMessageResult {
            status: ok_status(),
            response_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => err(&e.to_string()),
    }
}

/// Validates an unpair response envelope (Initiator side).
///
/// Reports whether the responder acknowledged the unpair. On a non-`Ok`
/// status, `acknowledged` is `false` and the `response_status` field
/// carries the peer's status code so the caller can decide how to react.
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable
/// byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_unpair_response_message(
    response_ptr: *const u8,
    response_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ProcessUnpairResponseResult {
    let err = |msg: &str| ProcessUnpairResponseResult {
        status: err_status(msg),
        acknowledged: false,
        response_status: 0,
    };

    if response_ptr.is_null() && response_len > 0 {
        return err("response_ptr is null");
    }
    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return err("shared_key_ptr is null");
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

    let extracted =
        match crate::primitives::unpairing::response::extract(response_bytes, &shared_key) {
            Ok(r) => r,
            Err(e) => return err(&e.to_string()),
        };

    let response_status = extracted
        .response
        .result
        .as_ref()
        .map(|r| r.status)
        .unwrap_or(0);

    match crate::primitives::unpairing::response::process(&extracted.response) {
        Ok(_) => ProcessUnpairResponseResult {
            status: ok_status(),
            acknowledged: true,
            response_status,
        },
        Err(crate::Error::Unpairing(
            crate::primitives::unpairing::UnpairingError::NonOkStatus { .. },
        )) => ProcessUnpairResponseResult {
            status: ok_status(),
            acknowledged: false,
            response_status,
        },
        Err(e) => err(&e.to_string()),
    }
}
