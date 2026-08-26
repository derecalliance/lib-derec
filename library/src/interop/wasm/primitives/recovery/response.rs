// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::{
    interop::wasm::{
        primitives::{
            helpers::{from_js, parse_shared_key, to_js},
            recovery::request::GetShareRequestMessage,
            sharing::request::StoreShareRequestMessage,
        },
        ts_bindings_utils::js_error_from_lib,
    },
    primitives::recovery::response,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Shared with the C FFI boundary — see [`crate::interop::dto`], which
/// owns these definitions so the two SDK families cannot drift.
pub use crate::interop::dto::GetShareResponseMessage;

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
