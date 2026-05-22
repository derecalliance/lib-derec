// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::verification::response,
    wasm::ts_bindings_utils::{derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct ExtractResultJs {
    channel_id: u64,
    secret_id: u64,
    version: u32,
    nonce: u64,
    hash: Vec<u8>,
}

/// Generates a verification response envelope (Helper side, step 2).
///
/// # Arguments
///
/// * `channel_id` - Channel identifier
/// * `secret_id` - Secret identifier from `verification_request_extract`
/// * `version` - Version from `verification_request_extract`
/// * `nonce` - Nonce from `verification_request_extract`. Must be passed unchanged.
/// * `shared_key` - 32-byte symmetric key established during pairing
/// * `stored_request` - The `DeRecMessage` JS object that the Helper stored from the
///   sharing flow (`sharing_request_produce` result). Its bytes are used as share content.
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` envelope.
#[wasm_bindgen(js_name = "verification_response_produce")]
pub fn produce(
    channel_id: u64,
    secret_id: u64,
    version: u32,
    nonce: u64,
    shared_key: &[u8],
    stored_request: JsValue,
) -> Result<JsValue, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    let stored_envelope = js_to_derec_message(stored_request, "stored_request")?;
    let share_content = stored_envelope.encode_to_vec();

    let request_msg = derec_proto::VerifyShareRequestMessage {
        secret_id,
        version,
        nonce,
        timestamp: None,
    };

    let result = response::produce(
        channel_id.into(),
        &request_msg,
        &shared_key,
        &share_content,
    )
    .map_err(js_error_from_lib)?;

    let response_envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(response_envelope))
}

/// Decodes and decrypts a verification response envelope (Owner side, step 2).
///
/// # Arguments
///
/// * `response` - Outer `DeRecMessage` JS object from `verification_response_produce`
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// A JS object `{ channel_id: bigint, secret_id: Uint8Array, version: number, nonce: bigint, hash: Uint8Array }`.
#[wasm_bindgen(js_name = "verification_response_extract")]
pub fn extract(resp: JsValue, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    let envelope = js_to_derec_message(resp, "response")?;
    let channel_id = envelope.channel_id;
    let envelope_bytes = envelope.encode_to_vec();

    let result = response::extract(&envelope_bytes, &shared_key)
        .map_err(js_error_from_lib)?;

    let wrapper = ExtractResultJs {
        channel_id,
        secret_id: result.response.secret_id,
        version: result.response.version,
        nonce: result.response.nonce,
        hash: result.response.hash,
    };

    let serializer = serde_wasm_bindgen::Serializer::new()
        .serialize_large_number_types_as_bigints(true);
    use serde::Serialize as _;
    wrapper
        .serialize(&serializer)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Verifies a verification response (Owner side, step 3).
///
/// # Arguments
///
/// * `response` - Outer `DeRecMessage` JS object from `verification_response_produce`
/// * `shared_key` - 32-byte symmetric key established during pairing
/// * `stored_request` - The same `DeRecMessage` JS object used as `stored_request` in
///   `verification_response_produce`
///
/// # Returns
///
/// `true` if the proof matches, `false` otherwise.
#[wasm_bindgen(js_name = "verification_response_process")]
pub fn process(
    resp: JsValue,
    shared_key: &[u8],
    stored_request: JsValue,
) -> Result<bool, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    let stored_envelope = js_to_derec_message(stored_request, "stored_request")?;
    let share_content = stored_envelope.encode_to_vec();

    let envelope = js_to_derec_message(resp, "response")?;
    let envelope_bytes = envelope.encode_to_vec();

    let result = response::extract(&envelope_bytes, &shared_key)
        .map_err(js_error_from_lib)?;

    response::process(&result.response, &share_content)
        .map_err(js_error_from_lib)
}
