// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::channels_discovery::request,
    wasm::ts_bindings_utils::{derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

/// Produces a channels discovery request envelope (Replica side).
///
/// # Arguments
///
/// * `channel_id` - Owner↔Replica channel identifier
/// * `shared_key` - 32-byte symmetric key for the Owner↔Replica channel
/// * `last_batch_index` - Index of the last batch received (0 for initial request)
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` envelope.
#[wasm_bindgen(js_name = "channels_discovery_request_produce")]
pub fn produce(
    channel_id: u64,
    shared_key: &[u8],
    last_batch_index: i32,
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let result = request::produce(channel_id.into(), &shared_key, last_batch_index)
        .map_err(js_error_from_lib)?;

    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}

/// Decodes and decrypts a channels discovery request envelope (Owner side).
///
/// # Arguments
///
/// * `request` - Outer `DeRecMessage` JS object
/// * `shared_key` - 32-byte symmetric key for the Owner↔Replica channel
///
/// # Returns
///
/// A JS object `{ last_batch_index: number }`.
#[wasm_bindgen(js_name = "channels_discovery_request_extract")]
pub fn extract(req: JsValue, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let envelope = js_to_derec_message(req, "request")?;
    let envelope_bytes = envelope.encode_to_vec();

    let request::ExtractResult { request: inner } =
        request::extract(&envelope_bytes, &shared_key).map_err(js_error_from_lib)?;

    #[derive(serde::Serialize)]
    struct ExtractResultJs {
        last_batch_index: i32,
    }

    serde_wasm_bindgen::to_value(&ExtractResultJs {
        last_batch_index: inner.last_batch_index,
    })
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
