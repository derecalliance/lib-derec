// SPDX-License-Identifier: Apache-2.0

use crate::{
    protos::derec_proto::{VerifyShareRequestMessage, VerifyShareResponseMessage},
    ts_bindings_utils::{js_error, js_error_from_lib},
    verification,
};
use prost::Message;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_verification_request(secret_id: &[u8], version: u32) -> Result<Vec<u8>, JsValue> {
    let result = verification::generate_verification_request(secret_id, version as i32)
        .map_err(js_error_from_lib)?;

    Ok(result.encode_to_vec())
}

#[wasm_bindgen]
pub fn generate_verification_response(
    secret_id: &[u8],
    channel_id: u64,
    share_content: &[u8],
    request: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let request = VerifyShareRequestMessage::decode(request)
        .map_err(|e| js_error("PROTOBUF_DECODE", e.to_string()))?;
    let result = verification::generate_verification_response(
        secret_id,
        channel_id.into(),
        share_content,
        &request,
    )
    .map_err(js_error_from_lib)?;

    Ok(result.encode_to_vec())
}

#[wasm_bindgen]
pub fn verify_share_response(
    secret_id: &[u8],
    channel_id: u64,
    share_content: &[u8],
    response: &[u8],
) -> Result<bool, JsValue> {
    let response = VerifyShareResponseMessage::decode(response)
        .map_err(|e| js_error("PROTOBUF_DECODE", e.to_string()))?;

    let result =
        verification::verify_share_response(secret_id, channel_id.into(), share_content, &response)
            .map_err(js_error_from_lib)?;

    Ok(result)
}
