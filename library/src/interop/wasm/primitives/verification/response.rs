// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::{
    interop::wasm::{
        primitives::{
            helpers::{from_js, parse_shared_key, to_js},
            verification::request::VerifyShareRequestMessage,
        },
        ts_bindings_utils::js_error_from_lib,
    },
    primitives::verification::response,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Shared with the C FFI boundary — see [`crate::interop::dto`], which
/// owns these definitions so the two SDK families cannot drift.
pub use crate::interop::dto::VerifyShareResponseMessage;

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
pub fn process(request: JsValue, response: JsValue, share_content: &[u8]) -> Result<bool, JsValue> {
    let request: VerifyShareRequestMessage = from_js(request)?;
    let request_proto: derec_proto::VerifyShareRequestMessage = request.into();
    let response: VerifyShareResponseMessage = from_js(response)?;
    let response_proto: derec_proto::VerifyShareResponseMessage = response.into();
    response::process(&request_proto, &response_proto, share_content).map_err(js_error_from_lib)
}
