// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::verification::request,
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

#[derive(Serialize, Deserialize, Clone)]
pub struct VerifyShareRequestMessage {
    pub secret_id: u64,
    pub version: u32,
    pub nonce: u64,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::VerifyShareRequestMessage> for VerifyShareRequestMessage {
    fn from(value: derec_proto::VerifyShareRequestMessage) -> Self {
        Self {
            secret_id: value.secret_id,
            version: value.version,
            nonce: value.nonce,
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<VerifyShareRequestMessage> for derec_proto::VerifyShareRequestMessage {
    fn from(value: VerifyShareRequestMessage) -> Self {
        Self {
            secret_id: value.secret_id,
            version: value.version,
            nonce: value.nonce,
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
    pub request: VerifyShareRequestMessage,
}

#[wasm_bindgen(js_name = "verification_request_produce")]
pub fn produce(
    channel_id: u64,
    secret_id: u64,
    version: u32,
    shared_key: &[u8],
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = request::produce(channel_id.into(), secret_id, version, &shared_key)
        .map_err(js_error_from_lib)?;
    to_js(&ProduceResult {
        envelope: result.envelope,
    })
}

#[wasm_bindgen(js_name = "verification_request_extract")]
pub fn extract(envelope_bytes: &[u8], shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = request::extract(envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        request: result.request.into(),
    })
}
