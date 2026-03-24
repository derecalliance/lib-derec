// SPDX-License-Identifier: Apache-2.0

//! WASM bindings for the DeRec verification flow.
//!
//! The verification flow exchanges encrypted outer `DeRecMessage` envelopes:
//!
//! - `generate_verification_request` returns serialized outer `DeRecMessage` bytes
//!   carrying an encrypted inner `VerifyShareRequestMessage`
//! - `generate_verification_response` accepts serialized outer request bytes and returns
//!   serialized outer response bytes
//! - `verify_share_response` accepts serialized outer response bytes and returns whether
//!   the cryptographic proof is valid
//!
//! JavaScript callers must provide the 32-byte shared symmetric key established during pairing.

use crate::{
    ts_bindings_utils::{js_error, js_error_from_lib},
    verification,
};
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct GenerateVerificationRequestResultJs {
    /// Serialized outer `DeRecMessage` carrying encrypted inner `VerifyShareRequestMessage`.
    wire_bytes: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct GenerateVerificationResponseResultJs {
    /// Serialized outer `DeRecMessage` carrying encrypted inner `VerifyShareResponseMessage`.
    wire_bytes: Vec<u8>,
}

/// Generates a verification request envelope.
///
/// # Arguments
///
/// * `secret_id` - Secret identifier
/// * `channel_id` - Helper channel identifier
/// * `version` - Share-distribution version being verified
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// A JS object with:
///
/// - `wire_bytes`: serialized outer `DeRecMessage` bytes carrying an encrypted
///   inner `VerifyShareRequestMessage`
#[wasm_bindgen]
pub fn generate_verification_request(
    secret_id: &[u8],
    channel_id: u64,
    version: i32,
    shared_key: &[u8],
) -> Result<JsValue, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    let verification::GenerateVerificationRequestResult { wire_bytes } =
        verification::generate_verification_request(
            secret_id,
            channel_id.into(),
            version,
            &shared_key,
        )
        .map_err(js_error_from_lib)?;

    let wrapper = GenerateVerificationRequestResultJs { wire_bytes };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Generates a verification response envelope.
///
/// # Arguments
///
/// * `secret_id` - Secret identifier
/// * `channel_id` - Helper channel identifier
/// * `shared_key` - 32-byte symmetric key established during pairing
/// * `share_content` - Share bytes whose possession is being proven
/// * `request_bytes` - Serialized outer `DeRecMessage` bytes carrying encrypted
///   inner `VerifyShareRequestMessage`
///
/// # Returns
///
/// A JS object with:
///
/// - `wire_bytes`: serialized outer `DeRecMessage` bytes carrying an encrypted
///   inner `VerifyShareResponseMessage`
#[wasm_bindgen]
pub fn generate_verification_response(
    secret_id: &[u8],
    channel_id: u64,
    shared_key: &[u8],
    share_content: &[u8],
    request_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    let verification::GenerateVerificationResponseResult { wire_bytes } =
        verification::generate_verification_response(
            secret_id,
            channel_id.into(),
            &shared_key,
            share_content,
            request_bytes,
        )
        .map_err(js_error_from_lib)?;

    let wrapper = GenerateVerificationResponseResultJs { wire_bytes };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Verifies a verification response envelope.
///
/// # Arguments
///
/// * `secret_id` - Secret identifier
/// * `channel_id` - Helper channel identifier
/// * `shared_key` - 32-byte symmetric key established during pairing
/// * `share_content` - Expected share bytes
/// * `response_bytes` - Serialized outer `DeRecMessage` bytes carrying encrypted
///   inner `VerifyShareResponseMessage`
///
/// # Returns
///
/// `true` if the verification response is valid, otherwise `false`.
#[wasm_bindgen]
pub fn verify_share_response(
    secret_id: &[u8],
    channel_id: u64,
    shared_key: &[u8],
    share_content: &[u8],
    response_bytes: &[u8],
) -> Result<bool, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    verification::verify_share_response(
        secret_id,
        channel_id.into(),
        &shared_key,
        share_content,
        response_bytes,
    )
    .map_err(js_error_from_lib)
}
