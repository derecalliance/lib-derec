// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::replica_confirmation::response,
    wasm::ts_bindings_utils::{derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

/// Produces a replica confirmation response envelope.
///
/// # Arguments
///
/// * `channel_id` - Replica channel identifier
/// * `shared_key` - 32-byte symmetric key from pairing
/// * `replica_id` - Responder's replica identifier
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` envelope.
#[wasm_bindgen(js_name = "replica_confirmation_response_produce")]
pub fn produce(channel_id: u64, shared_key: &[u8], replica_id: i32) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let result = response::produce(channel_id.into(), &shared_key, replica_id)
        .map_err(js_error_from_lib)?;

    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}

/// Decodes, decrypts, and processes a replica confirmation response envelope.
///
/// # Arguments
///
/// * `response` - Outer `DeRecMessage` JS object
/// * `shared_key` - 32-byte symmetric key from pairing
///
/// # Returns
///
/// A JS object `{ replica_id: number }`.
#[wasm_bindgen(js_name = "replica_confirmation_response_process")]
pub fn process(resp: JsValue, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let envelope = js_to_derec_message(resp, "response")?;
    let envelope_bytes = envelope.encode_to_vec();

    let response::ExtractResult { response: inner } =
        response::extract(&envelope_bytes, &shared_key).map_err(js_error_from_lib)?;

    let response::ProcessResult { replica_id } =
        response::process(&inner).map_err(js_error_from_lib)?;

    #[derive(serde::Serialize)]
    struct ProcessResultJs {
        replica_id: i32,
    }

    serde_wasm_bindgen::to_value(&ProcessResultJs { replica_id })
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

fn parse_shared_key(shared_key: &[u8]) -> Result<[u8; 32], JsValue> {
    shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })
}
