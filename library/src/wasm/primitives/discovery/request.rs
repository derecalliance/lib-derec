// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::discovery::request,
    wasm::{
        primitives::{
            helpers::{parse_shared_key, to_js},
            types::Timestamp,
        },
        ts_bindings_utils::js_error_from_lib,
    },
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct GetSecretIdsVersionsRequestMessage {
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::GetSecretIdsVersionsRequestMessage> for GetSecretIdsVersionsRequestMessage {
    fn from(value: derec_proto::GetSecretIdsVersionsRequestMessage) -> Self {
        Self {
            timestamp: value.timestamp.map(Into::into),
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
    pub request: GetSecretIdsVersionsRequestMessage,
}

#[wasm_bindgen(js_name = "discovery_request_produce")]
pub fn produce(channel_id: u64, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = request::produce(channel_id.into(), &shared_key).map_err(js_error_from_lib)?;
    to_js(&ProduceResult {
        envelope: result.envelope,
    })
}

#[wasm_bindgen(js_name = "discovery_request_extract")]
pub fn extract(envelope_bytes: &[u8], shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = request::extract(envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        request: result.request.into(),
    })
}
