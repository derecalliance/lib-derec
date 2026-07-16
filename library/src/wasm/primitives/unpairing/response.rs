// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::{
    primitives::unpairing::response,
    wasm::{
        primitives::{
            helpers::{from_js, parse_shared_key, to_js},
            types::{DeRecResult, Timestamp},
        },
        ts_bindings_utils::js_error_from_lib,
    },
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct UnpairResponseMessage {
    pub result: Option<DeRecResult>,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::UnpairResponseMessage> for UnpairResponseMessage {
    fn from(value: derec_proto::UnpairResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<UnpairResponseMessage> for derec_proto::UnpairResponseMessage {
    fn from(value: UnpairResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
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
    pub response: UnpairResponseMessage,
}

#[derive(Serialize, Deserialize)]
pub struct ProcessResult {
    pub acknowledged: bool,
}

#[wasm_bindgen(js_name = "unpairing_response_produce")]
pub fn produce(channel_id: u64, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = response::produce(channel_id.into(), &shared_key).map_err(js_error_from_lib)?;
    to_js(&ProduceResult {
        envelope: result.envelope,
    })
}

#[wasm_bindgen(js_name = "unpairing_response_extract")]
pub fn extract(envelope_bytes: &[u8], shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = response::extract(envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        response: result.response.into(),
    })
}

#[wasm_bindgen(js_name = "unpairing_response_process")]
pub fn process(response: JsValue) -> Result<JsValue, JsValue> {
    let response: UnpairResponseMessage = from_js(response)?;
    let response_proto: derec_proto::UnpairResponseMessage = response.into();
    let result = response::process(&response_proto).map_err(js_error_from_lib)?;
    to_js(&ProcessResult {
        acknowledged: result.acknowledged,
    })
}
