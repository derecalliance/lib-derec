// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::{
        recovery::{request, response},
        recovery::response::RecoveryResponseInput,
        sharing::request as sharing_request,
    },
    ts_bindings_utils::{
        DeRecMessageJs, derec_message_js_struct_to_proto, derec_message_js_to_js_value,
        derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message,
    },
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

/// Produces a recovery share response envelope (Helper side).
///
/// # Arguments
///
/// * `secret_id` - Secret identifier being recovered
/// * `channel_id` - Helper channel identifier
/// * `stored_share_request` - The `DeRecMessage` JS object stored from the sharing flow
///   (the result of `sharing_request_produce`)
/// * `request` - The `DeRecMessage` JS object received from the recovering Owner
///   (the result of `recovery_request_produce`)
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` response envelope.
#[wasm_bindgen(js_name = "recovery_response_produce")]
pub fn produce(
    secret_id: &[u8],
    channel_id: u64,
    stored_share_request: JsValue,
    req: JsValue,
    shared_key: &[u8],
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let request_envelope = js_to_derec_message(req, "request")?;
    let request_bytes = request_envelope.encode_to_vec();
    let request::ExtractResult { request: share_request } =
        request::extract(&request_bytes, &shared_key)
            .map_err(js_error_from_lib)?;

    let stored_envelope = js_to_derec_message(stored_share_request, "stored_share_request")?;
    let stored_bytes = stored_envelope.encode_to_vec();
    let sharing_request::ExtractResult {
        request: stored_share_request_msg,
    } = sharing_request::extract(&stored_bytes, &shared_key)
        .map_err(js_error_from_lib)?;

    let result = response::produce(
        channel_id.into(),
        secret_id,
        &share_request,
        &stored_share_request_msg,
        &shared_key,
    )
    .map_err(js_error_from_lib)?;

    let response_envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(response_envelope))
}

/// Recovers the original secret from helper recovery responses (Owner side).
///
/// # Arguments
///
/// * `responses` - JS array of recovery response inputs. Each entry must contain:
///   - `response`: outer `DeRecMessage` JS object (from `recovery_response_produce`)
///   - `shared_key`: 32-byte `Uint8Array`
/// * `secret_id` - Secret identifier being recovered
/// * `version` - Secret version being recovered
///
/// # Returns
///
/// The reconstructed secret bytes.
#[wasm_bindgen(js_name = "recovery_response_recover")]
pub fn recover(
    responses: JsValue,
    secret_id: &[u8],
    version: i32,
) -> Result<Vec<u8>, JsValue> {
    let raw_inputs: Vec<WasmRecoveryResponseInput> = serde_wasm_bindgen::from_value(responses)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))?;

    let parsed_inputs: Vec<OwnedRecoveryResponseInput> = raw_inputs
        .into_iter()
        .map(|input| {
            let shared_key = parse_shared_key(&input.shared_key).map_err(|_| {
                js_error(
                    "INVALID_SHARED_KEY_LENGTH",
                    "shared_key must be exactly 32 bytes".to_string(),
                )
            })?;

            let envelope = derec_message_js_struct_to_proto(input.response, "response")?;
            let envelope_bytes = envelope.encode_to_vec();

            let response::ExtractResult { response } =
                response::extract(&envelope_bytes, &shared_key)
                    .map_err(js_error_from_lib)?;

            Ok(OwnedRecoveryResponseInput { response, shared_key })
        })
        .collect::<Result<_, JsValue>>()?;

    let borrowed_inputs: Vec<RecoveryResponseInput<'_>> = parsed_inputs
        .iter()
        .map(|input| RecoveryResponseInput {
            share_response: &input.response,
            shared_key: &input.shared_key,
        })
        .collect();

    let result = response::recover(secret_id, version, &borrowed_inputs)
        .map_err(js_error_from_lib)?;

    Ok(result.secret_data)
}

#[derive(serde::Deserialize)]
struct WasmRecoveryResponseInput {
    response: DeRecMessageJs,
    shared_key: Vec<u8>,
}

struct OwnedRecoveryResponseInput {
    response: derec_proto::GetShareResponseMessage,
    shared_key: [u8; 32],
}

fn parse_shared_key(shared_key: &[u8]) -> Result<[u8; 32], JsValue> {
    shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })
}
