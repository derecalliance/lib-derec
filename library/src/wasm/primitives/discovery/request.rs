// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::discovery::request,
    wasm::ts_bindings_utils::{derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

/// Produces a discovery request envelope (Owner side).
///
/// Sent by a recovering Owner to ask a Helper which secrets and versions it holds
/// for this channel. Call this after recovery-mode pairing completes and any
/// required out-of-band authentication has been performed.
///
/// # Arguments
///
/// * `channel_id` - Recovery channel identifier established during pairing
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` envelope, ready to
/// send to the Helper over any transport.
#[wasm_bindgen(js_name = "discovery_request_produce")]
pub fn produce(channel_id: u64, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let result = request::produce(channel_id.into(), &shared_key)
        .map_err(js_error_from_lib)?;

    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}

/// Decodes and decrypts a discovery request envelope (Helper side).
///
/// # Arguments
///
/// * `request` - Outer `DeRecMessage` JS object from `discovery_request_produce`
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// A JS object `{ channel_id: bigint }` confirming the request was well-formed.
#[wasm_bindgen(js_name = "discovery_request_extract")]
pub fn extract(req: JsValue, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let envelope = js_to_derec_message(req, "request")?;
    let channel_id = envelope.channel_id;
    let envelope_bytes = envelope.encode_to_vec();

    request::extract(&envelope_bytes, &shared_key)
        .map_err(js_error_from_lib)?;

    #[derive(serde::Serialize)]
    struct ExtractResultJs {
        channel_id: u64,
    }

    let serializer = serde_wasm_bindgen::Serializer::new()
        .serialize_large_number_types_as_bigints(true);
    use serde::Serialize as _;
    ExtractResultJs { channel_id }
        .serialize(&serializer)
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
