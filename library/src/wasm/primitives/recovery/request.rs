// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::recovery::request,
    wasm::ts_bindings_utils::{derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib},
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

/// Produces a recovery share request envelope.
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
/// A plain JS object representing the outer `DeRecMessage` envelope.
#[wasm_bindgen(js_name = "recovery_request_produce")]
pub fn produce(
    channel_id: u64,
    secret_id: u64,
    version: u32,
    shared_key: &[u8],
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let result = request::produce(channel_id.into(), secret_id, version, &shared_key)
        .map_err(js_error_from_lib)?;

    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}

fn parse_shared_key(shared_key: &[u8]) -> Result<[u8; 32], JsValue> {
    shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })
}
