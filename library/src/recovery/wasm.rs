// SPDX-License-Identifier: Apache-2.0

//! WASM bindings for the DeRec recovery flow.
//!
//! The recovery flow exchanges encrypted outer `DeRecMessage` envelopes:
//!
//! - `generate_share_request` returns serialized outer `DeRecMessage` bytes
//!   carrying an encrypted inner `GetShareRequestMessage`
//! - `generate_share_response` accepts serialized outer request bytes and a
//!   serialized stored share envelope, and returns serialized outer response bytes
//! - `recover_from_share_responses` accepts a JS array of recovery response inputs,
//!   where each entry contains:
//!   - `response_bytes`: serialized outer response envelope bytes
//!   - `shared_key`: 32-byte symmetric key required to decrypt that response
//!
//! JavaScript callers must provide the 32-byte shared symmetric key established
//! during pairing.

use crate::{
    recovery::{self, RecoveryResponseInput},
    ts_bindings_utils::{js_error, js_error_from_lib},
};
use wasm_bindgen::prelude::*;

/// Generates a recovery request envelope.
///
/// # Arguments
///
/// * `channel_id` - Helper channel identifier
/// * `secret_id` - Secret identifier being recovered
/// * `version` - Share version being requested
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// Serialized outer `DeRecMessage` bytes carrying an encrypted inner
/// `GetShareRequestMessage`.
#[wasm_bindgen]
pub fn generate_share_request(
    channel_id: u64,
    secret_id: &[u8],
    version: i32,
    shared_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let result =
        recovery::generate_share_request(channel_id.into(), secret_id, version, &shared_key)
            .map_err(js_error_from_lib)?;

    Ok(result.wire_bytes)
}

/// Generates a recovery response envelope.
///
/// # Arguments
///
/// * `secret_id` - Secret identifier being recovered
/// * `channel_id` - Helper channel identifier
/// * `stored_share_request_wire_bytes` - Serialized outer `DeRecMessage` bytes
///   carrying the encrypted inner `StoreShareRequestMessage` previously produced
///   by the sharing flow for this helper
/// * `request_wire_bytes` - Serialized outer `DeRecMessage` bytes carrying the
///   encrypted inner `GetShareRequestMessage`
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// Serialized outer `DeRecMessage` bytes carrying an encrypted inner
/// `GetShareResponseMessage`.
#[wasm_bindgen]
pub fn generate_share_response(
    secret_id: &[u8],
    channel_id: u64,
    stored_share_request_wire_bytes: &[u8],
    request_wire_bytes: &[u8],
    shared_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let result = recovery::generate_share_response(
        channel_id.into(),
        secret_id,
        request_wire_bytes,
        stored_share_request_wire_bytes,
        &shared_key,
    )
    .map_err(js_error_from_lib)?;

    Ok(result.wire_bytes)
}

/// Recovers the original secret from helper recovery responses.
///
/// # Arguments
///
/// * `responses` - JS array of recovery response inputs. Each entry must contain:
///   - `response_bytes`: serialized outer `DeRecMessage` response envelope
///   - `shared_key`: 32-byte symmetric key for decrypting that response
/// * `secret_id` - Secret identifier being recovered
/// * `version` - Secret version being recovered
///
/// # Returns
///
/// The reconstructed secret bytes.
#[wasm_bindgen]
pub fn recover_from_share_responses(
    responses: JsValue,
    secret_id: &[u8],
    version: i32,
) -> Result<Vec<u8>, JsValue> {
    let raw_inputs: Vec<WasmRecoveryResponseInput> = serde_wasm_bindgen::from_value(responses)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))?;

    let parsed_inputs: Vec<OwnedRecoveryResponseInput> = raw_inputs
        .into_iter()
        .map(|input| {
            let shared_key = parse_shared_key(&input.shared_key).map_err(|_| {
                js_error(
                    "INVALID_SHARED_KEY_LENGTH",
                    "shared_key must be exactly 32 bytes".to_string(),
                )
            })?;

            Ok(OwnedRecoveryResponseInput {
                response_bytes: input.response_bytes,
                shared_key,
            })
        })
        .collect::<Result<_, JsValue>>()?;

    let borrowed_inputs: Vec<RecoveryResponseInput<'_>> = parsed_inputs
        .iter()
        .map(|input| RecoveryResponseInput {
            bytes: &input.response_bytes,
            shared_key: &input.shared_key,
        })
        .collect();

    let result = recovery::recover_from_share_responses(secret_id, version, &borrowed_inputs)
        .map_err(js_error_from_lib)?;

    Ok(result.secret_data)
}

#[derive(serde::Deserialize)]
struct WasmRecoveryResponseInput {
    response_bytes: Vec<u8>,
    shared_key: Vec<u8>,
}

struct OwnedRecoveryResponseInput {
    response_bytes: Vec<u8>,
    shared_key: [u8; 32],
}

fn parse_shared_key(shared_key: &[u8]) -> Result<[u8; 32], JsValue> {
    shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })
}
