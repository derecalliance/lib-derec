// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::unpairing::response,
    wasm::ts_bindings_utils::{
        derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib,
        js_to_derec_message,
    },
};
use derec_proto::{DeRecMessage, StatusEnum};
use prost::Message as _;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct ExtractResultJs {
    channel_id: u64,
    status: i32,
    memo: String,
}

/// Generates a successful unpair response envelope (responder side).
///
/// # Arguments
///
/// * `channel_id` - Channel identifier of the requesting peer.
/// * `shared_key` - 32-byte symmetric key established during pairing.
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` envelope.
#[wasm_bindgen(js_name = "unpairing_response_produce")]
pub fn produce(channel_id: u64, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    let result = response::produce(channel_id.into(), &shared_key).map_err(js_error_from_lib)?;
    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}

/// Generates a rejection unpair response envelope (responder side).
///
/// # Arguments
///
/// * `channel_id` - Channel identifier of the requesting peer.
/// * `shared_key` - 32-byte symmetric key established during pairing.
/// * `status` - `StatusEnum` numeric value (e.g. `2` for `Fail`, `10` for `Rejected`).
/// * `memo` - Human-readable rejection reason.
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` envelope.
#[wasm_bindgen(js_name = "unpairing_response_reject")]
pub fn reject(
    channel_id: u64,
    shared_key: &[u8],
    status: i32,
    memo: &str,
) -> Result<JsValue, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;
    let status_enum = StatusEnum::try_from(status).map_err(|_| {
        js_error(
            "INVALID_STATUS",
            format!("invalid StatusEnum value: {status}"),
        )
    })?;

    let result = response::reject(channel_id.into(), &shared_key, status_enum, memo)
        .map_err(js_error_from_lib)?;
    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}

/// Decodes and decrypts an unpair response envelope.
///
/// # Arguments
///
/// * `response` - Outer `DeRecMessage` JS object from `unpairing_response_produce`
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// `{ channel_id: bigint, status: number, memo: string }`.
#[wasm_bindgen(js_name = "unpairing_response_extract")]
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

    let result = response::extract(&envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    let (status, memo) = result
        .response
        .result
        .as_ref()
        .map(|r| (r.status, r.memo.clone()))
        .unwrap_or((0, String::new()));

    let wrapper = ExtractResultJs {
        channel_id,
        status,
        memo,
    };
    let serializer =
        serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
    use serde::Serialize as _;
    wrapper
        .serialize(&serializer)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Verifies a decoded unpair response (Initiator side).
///
/// Returns `true` when the responder reported `Ok`, `false` for any non-`Ok`
/// status. Errors are surfaced when the response is malformed (e.g. missing
/// `result` field).
#[wasm_bindgen(js_name = "unpairing_response_process")]
pub fn process(resp: JsValue, shared_key: &[u8]) -> Result<bool, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    let envelope = js_to_derec_message(resp, "response")?;
    let envelope_bytes = envelope.encode_to_vec();

    let extracted = response::extract(&envelope_bytes, &shared_key).map_err(js_error_from_lib)?;

    match response::process(&extracted.response) {
        Ok(_) => Ok(true),
        Err(crate::Error::Unpairing(
            crate::primitives::unpairing::UnpairingError::NonOkStatus { .. },
        )) => Ok(false),
        Err(e) => Err(js_error_from_lib(e)),
    }
}
