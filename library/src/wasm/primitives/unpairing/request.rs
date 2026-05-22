// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::unpairing::request,
    wasm::ts_bindings_utils::{
        derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib,
        js_to_derec_message,
    },
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct ExtractResultJs {
    channel_id: u64,
    memo: String,
}

/// Generates an unpair request envelope.
///
/// # Arguments
///
/// * `channel_id` - Helper/Owner channel identifier.
/// * `memo` - Optional human-readable reason. Pass `""` to omit.
/// * `shared_key` - 32-byte symmetric key established during pairing.
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` envelope.
#[wasm_bindgen(js_name = "unpairing_request_produce")]
pub fn produce(channel_id: u64, memo: &str, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    let result = request::produce(channel_id.into(), memo, &shared_key)
        .map_err(js_error_from_lib)?;

    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}

/// Decodes and decrypts an unpair request envelope.
///
/// # Arguments
///
/// * `request` - Outer `DeRecMessage` JS object from `unpairing_request_produce`
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// `{ channel_id: bigint, memo: string }`.
#[wasm_bindgen(js_name = "unpairing_request_extract")]
pub fn extract(req: JsValue, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    let envelope = js_to_derec_message(req, "request")?;
    let channel_id = envelope.channel_id;
    let envelope_bytes = envelope.encode_to_vec();

    let result = request::extract(&envelope_bytes, &shared_key).map_err(js_error_from_lib)?;

    let wrapper = ExtractResultJs {
        channel_id,
        memo: result.request.memo,
    };

    let serializer =
        serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
    use serde::Serialize as _;
    wrapper
        .serialize(&serializer)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}
