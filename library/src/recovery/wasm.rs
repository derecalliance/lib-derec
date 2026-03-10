// SPDX-License-Identifier: Apache-2.0

use crate::{
    recovery,
    ts_bindings_utils::{js_error, js_error_from_lib},
};
use derec_proto::{GetShareRequestMessage, GetShareResponseMessage, StoreShareRequestMessage};
use prost::Message;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct RecoverShareResponses {
    value: std::collections::HashMap<u64, Vec<u8>>,
}

#[wasm_bindgen]
pub fn generate_share_request(
    channel_id: u64,
    secret_id: &[u8],
    version: i32,
) -> Result<Vec<u8>, JsValue> {
    let result = recovery::generate_share_request(channel_id.into(), secret_id, version)
        .map_err(js_error_from_lib)?;

    Ok(result.encode_to_vec())
}

#[wasm_bindgen]
pub fn generate_share_response(
    secret_id: &[u8],
    channel_id: u64,
    share_content: &[u8],
    request: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let request = GetShareRequestMessage::decode(request)
        .map_err(|e| js_error("PROTOBUF_DECODE", e.to_string()))?;
    let share_content = StoreShareRequestMessage::decode(share_content)
        .map_err(|e| js_error("PROTOBUF_DECODE", e.to_string()))?;

    let result =
        recovery::generate_share_response(channel_id.into(), secret_id, &request, &share_content)
            .map_err(js_error_from_lib)?;

    Ok(result.encode_to_vec())
}

#[wasm_bindgen]
pub fn recover_from_share_responses(
    responses: JsValue,
    secret_id: &[u8],
    version: i32,
) -> Result<Vec<u8>, JsValue> {
    let responses: RecoverShareResponses = serde_wasm_bindgen::from_value(responses)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))?;

    let mut parsed_responses = Vec::new();
    for (_channel_id, bytes) in responses.value {
        let decoded = GetShareResponseMessage::decode(&*bytes)
            .map_err(|e| js_error("PROTOBUF_DECODE", e.to_string()))?;
        parsed_responses.push(decoded);
    }

    let secret = recovery::recover_from_share_responses(&parsed_responses, secret_id, version)
        .map_err(js_error_from_lib)?;

    Ok(secret)
}
