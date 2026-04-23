// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::replica_confirmation::request,
    wasm::ts_bindings_utils::{derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

/// Produces a replica confirmation request envelope.
///
/// # Arguments
///
/// * `channel_id` - Replica channel identifier
/// * `shared_key` - 32-byte symmetric key from pairing
/// * `replica_id` - Caller's replica identifier
///
/// # Returns
///
/// A JS object `{ envelope: DeRecMessage, fingerprint: Uint8Array }`.
#[wasm_bindgen(js_name = "replica_confirmation_request_produce")]
pub fn produce(channel_id: u64, shared_key: &[u8], replica_id: i32) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let result = request::produce(channel_id.into(), &shared_key, replica_id)
        .map_err(js_error_from_lib)?;

    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;

    #[derive(serde::Serialize)]
    struct ProduceResultJs {
        envelope: crate::wasm::ts_bindings_utils::DeRecMessageJs,
        fingerprint: Vec<u8>,
    }

    let js = ProduceResultJs {
        envelope: derec_message_to_js(envelope),
        fingerprint: result.fingerprint.to_vec(),
    };

    serde_wasm_bindgen::to_value(&js)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Decodes and decrypts a replica confirmation request envelope.
///
/// # Arguments
///
/// * `request` - Outer `DeRecMessage` JS object
/// * `shared_key` - 32-byte symmetric key from pairing
///
/// # Returns
///
/// A JS object `{ replica_id: number, fingerprint: Uint8Array }`.
#[wasm_bindgen(js_name = "replica_confirmation_request_extract")]
pub fn extract(req: JsValue, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let envelope = js_to_derec_message(req, "request")?;
    let envelope_bytes = envelope.encode_to_vec();

    let request::ExtractResult { request: inner } =
        request::extract(&envelope_bytes, &shared_key).map_err(js_error_from_lib)?;

    request::verify_fingerprint(&inner, &shared_key).map_err(js_error_from_lib)?;

    let fingerprint = derec_cryptography::replica::fingerprint(&shared_key);

    #[derive(serde::Serialize)]
    struct ExtractResultJs {
        replica_id: i32,
        fingerprint: Vec<u8>,
    }

    serde_wasm_bindgen::to_value(&ExtractResultJs {
        replica_id: inner.replica_id,
        fingerprint: fingerprint.to_vec(),
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
