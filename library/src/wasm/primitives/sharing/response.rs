// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::sharing::response,
    wasm::ts_bindings_utils::{DeRecMessageJs, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
    types::ChannelId,
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize)]
struct ProduceResultJs {
    /// Response `DeRecMessage` envelope as a plain JS object — send back to the Owner.
    envelope: DeRecMessageJs,
    /// Serialized [`CommittedDeRecShare`] protobuf bytes for the Helper to store locally.
    committed_share: Vec<u8>,
    /// Secret identifier extracted from the inner share.
    secret_id: Vec<u8>,
    /// Share-distribution version from the request.
    version: i32,
}

/// Processes an incoming sharing request on behalf of a Helper, producing a response envelope.
///
/// # Arguments
///
/// * `channel_id` - BigInt channel ID
/// * `shared_key` - `Uint8Array` of exactly 32 bytes
/// * `request` - Outer `DeRecMessage` JS object from `sharing_request_produce`
///
/// # Returns
///
/// A JS object with:
///
/// - `envelope`: response `DeRecMessage` — send back to the Owner
/// - `committed_share`: `Uint8Array` — store locally
/// - `secret_id`: `Uint8Array`
/// - `version`: number
#[wasm_bindgen(js_name = "sharing_response_produce")]
pub fn produce(
    channel_id: u64,
    shared_key: &[u8],
    request: JsValue,
) -> Result<JsValue, JsValue> {
    if shared_key.len() != 32 {
        return Err(js_error(
            "INVALID_SHARED_KEY",
            format!("shared_key must be exactly 32 bytes, got {}", shared_key.len()),
        ));
    }

    let shared_key_arr: &[u8; 32] = shared_key
        .try_into()
        .expect("shared_key length validated to be 32");

    let request_envelope = js_to_derec_message(request, "request")?;
    let request_bytes = request_envelope.encode_to_vec();

    let crate::primitives::sharing::request::ExtractResult { request: store_request } =
        crate::primitives::sharing::request::extract(&request_bytes, shared_key_arr)
            .map_err(js_error_from_lib)?;

    let result =
        response::produce(ChannelId(channel_id), &store_request, shared_key_arr)
            .map_err(js_error_from_lib)?;

    let response_envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;

    serde_wasm_bindgen::to_value(&ProduceResultJs {
        envelope: derec_message_to_js(response_envelope),
        committed_share: result.committed_share.encode_to_vec(),
        secret_id: result.secret_id,
        version: result.version,
    })
    .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Validates a sharing response received from a Helper.
///
/// # Arguments
///
/// * `version` - Integer share-distribution version
/// * `shared_key` - `Uint8Array` of exactly 32 bytes
/// * `response` - Outer `DeRecMessage` JS object from `sharing_response_produce`
///
/// # Returns
///
/// `undefined` on success; throws on failure.
#[wasm_bindgen(js_name = "sharing_response_process")]
pub fn process(
    version: i32,
    shared_key: &[u8],
    response: JsValue,
) -> Result<(), JsValue> {
    if shared_key.len() != 32 {
        return Err(js_error(
            "INVALID_SHARED_KEY",
            format!("shared_key must be exactly 32 bytes, got {}", shared_key.len()),
        ));
    }

    let shared_key_arr: &[u8; 32] = shared_key
        .try_into()
        .expect("shared_key length validated to be 32");

    let response_envelope = js_to_derec_message(response, "response")?;
    let response_bytes = response_envelope.encode_to_vec();

    let crate::primitives::sharing::response::ExtractResult { response: store_response } =
        crate::primitives::sharing::response::extract(&response_bytes, shared_key_arr)
            .map_err(js_error_from_lib)?;

    crate::primitives::sharing::response::process(version, &store_response)
        .map_err(js_error_from_lib)
}
