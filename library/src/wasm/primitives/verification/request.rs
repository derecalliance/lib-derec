// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::verification::request,
    wasm::ts_bindings_utils::{derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct ExtractResultJs {
    channel_id: u64,
    secret_id: Vec<u8>,
    version: i32,
    nonce: u64,
}

/// Generates a verification request envelope (Owner side, step 1).
///
/// # Arguments
///
/// * `channel_id` - Helper channel identifier
/// * `secret_id` - Secret identifier embedded in the request
/// * `version` - Share-distribution version being verified
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` envelope.
#[wasm_bindgen(js_name = "verification_request_produce")]
pub fn produce(
    channel_id: u64,
    secret_id: &[u8],
    version: i32,
    shared_key: &[u8],
) -> Result<JsValue, JsValue> {
    let shared_key: [u8; 32] = shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })?;

    let result = request::produce(channel_id.into(), secret_id, version, &shared_key)
        .map_err(js_error_from_lib)?;

    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}

/// Decodes and decrypts a verification request envelope (Helper side, step 1).
///
/// # Arguments
///
/// * `request` - Outer `DeRecMessage` JS object from `verification_request_produce`
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// A JS object `{ channel_id: bigint, secret_id: Uint8Array, version: number, nonce: bigint }`.
#[wasm_bindgen(js_name = "verification_request_extract")]
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

    let result = request::extract(&envelope_bytes, &shared_key)
        .map_err(js_error_from_lib)?;

    let wrapper = ExtractResultJs {
        channel_id,
        secret_id: result.request.secret_id,
        version: result.request.version,
        nonce: result.request.nonce,
    };

    let serializer = serde_wasm_bindgen::Serializer::new()
        .serialize_large_number_types_as_bigints(true);
    use serde::Serialize as _;
    wrapper
        .serialize(&serializer)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}
