// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::{
    primitives::verification::response,
    wasm::{
        primitives::{
            helpers::{from_js, parse_shared_key, to_js},
            types::{DeRecResult, Timestamp},
            verification::request::VerifyShareRequestMessage,
        },
        ts_bindings_utils::js_error_from_lib,
    },
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct VerifyShareResponseMessage {
    pub result: Option<DeRecResult>,
    pub secret_id: u64,
    pub version: u32,
    pub nonce: u64,
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::VerifyShareResponseMessage> for VerifyShareResponseMessage {
    fn from(value: derec_proto::VerifyShareResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            secret_id: value.secret_id,
            version: value.version,
            nonce: value.nonce,
            hash: value.hash,
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<VerifyShareResponseMessage> for derec_proto::VerifyShareResponseMessage {
    fn from(value: VerifyShareResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            secret_id: value.secret_id,
            version: value.version,
            nonce: value.nonce,
            hash: value.hash,
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
    pub response: VerifyShareResponseMessage,
}

#[wasm_bindgen(js_name = "verification_response_produce")]
pub fn produce(
    channel_id: u64,
    request: JsValue,
    shared_key: &[u8],
    share_content: &[u8],
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let request: VerifyShareRequestMessage = from_js(request)?;
    let request_proto: derec_proto::VerifyShareRequestMessage = request.into();

    let result = response::produce(
        channel_id.into(),
        &request_proto,
        &shared_key,
        share_content,
    )
    .map_err(js_error_from_lib)?;

    to_js(&ProduceResult {
        envelope: result.envelope,
    })
}

#[wasm_bindgen(js_name = "verification_response_extract")]
pub fn extract(envelope_bytes: &[u8], shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = response::extract(envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        response: result.response.into(),
    })
}

/// Verify a `VerifyShareResponseMessage` against the originating
/// `VerifyShareRequestMessage` and the expected share content.
///
/// `request` must be the request the **owner** previously produced for
/// this challenge (kept by the caller in a per-`channel_id` pending-
/// verification map). The primitive rejects any response whose
/// `(nonce, secret_id, version)` triple doesn't match — that's the
/// anti-replay gate.
#[wasm_bindgen(js_name = "verification_response_process")]
pub fn process(
    request: JsValue,
    response: JsValue,
    share_content: &[u8],
) -> Result<bool, JsValue> {
    let request: VerifyShareRequestMessage = from_js(request)?;
    let request_proto: derec_proto::VerifyShareRequestMessage = request.into();
    let response: VerifyShareResponseMessage = from_js(response)?;
    let response_proto: derec_proto::VerifyShareResponseMessage = response.into();
    response::process(&request_proto, &response_proto, share_content).map_err(js_error_from_lib)
}
