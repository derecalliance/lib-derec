// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::recovery::response,
    wasm::{
        primitives::{
            helpers::{from_js, parse_shared_key, to_js},
            recovery::request::GetShareRequestMessage,
            sharing::request::StoreShareRequestMessage,
            types::{DeRecResult, Timestamp},
        },
        ts_bindings_utils::js_error_from_lib,
    },
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct GetShareResponseMessage {
    pub share_algorithm: i32,
    #[serde(with = "serde_bytes")]
    pub committed_de_rec_share: Vec<u8>,
    pub result: Option<DeRecResult>,
    pub timestamp: Option<Timestamp>,
    pub secret_id: u64,
    pub version: u32,
}

impl From<derec_proto::GetShareResponseMessage> for GetShareResponseMessage {
    fn from(value: derec_proto::GetShareResponseMessage) -> Self {
        Self {
            share_algorithm: value.share_algorithm,
            committed_de_rec_share: value.committed_de_rec_share,
            result: value.result.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
            secret_id: value.secret_id,
            version: value.version,
        }
    }
}

impl From<GetShareResponseMessage> for derec_proto::GetShareResponseMessage {
    fn from(value: GetShareResponseMessage) -> Self {
        Self {
            share_algorithm: value.share_algorithm,
            committed_de_rec_share: value.committed_de_rec_share,
            result: value.result.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
            secret_id: value.secret_id,
            version: value.version,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProduceResult {
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ExtractResult {
    pub response: GetShareResponseMessage,
}

#[derive(Serialize, Deserialize)]
pub struct RecoverResult {
    #[serde(with = "serde_bytes")]
    pub secret_data: Vec<u8>,
}

#[wasm_bindgen(js_name = "recovery_response_produce")]
pub fn produce(
    channel_id: u64,
    request: JsValue,
    stored_share_request: JsValue,
    shared_key: &[u8],
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let request: GetShareRequestMessage = from_js(request)?;
    let request_proto: derec_proto::GetShareRequestMessage = request.into();
    let stored_share_request: StoreShareRequestMessage = from_js(stored_share_request)?;
    let stored_share_request_proto: derec_proto::StoreShareRequestMessage =
        stored_share_request.into();

    let result = response::produce(
        channel_id.into(),
        &request_proto,
        &stored_share_request_proto,
        &shared_key,
    )
    .map_err(js_error_from_lib)?;

    to_js(&ProduceResult {
        envelope: result.envelope,
    })
}

#[wasm_bindgen(js_name = "recovery_response_extract")]
pub fn extract(envelope_bytes: &[u8], shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = response::extract(envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        response: result.response.into(),
    })
}

#[wasm_bindgen(js_name = "recovery_response_recover")]
pub fn recover(secret_id: u64, version: u32, responses: JsValue) -> Result<JsValue, JsValue> {
    let responses: Vec<GetShareResponseMessage> = from_js(responses)?;
    let responses_proto: Vec<derec_proto::GetShareResponseMessage> =
        responses.into_iter().map(Into::into).collect();
    let response_refs: Vec<&derec_proto::GetShareResponseMessage> =
        responses_proto.iter().collect();

    let result =
        response::recover(secret_id, version, &response_refs).map_err(js_error_from_lib)?;

    to_js(&RecoverResult {
        secret_data: result.secret_data,
    })
}
