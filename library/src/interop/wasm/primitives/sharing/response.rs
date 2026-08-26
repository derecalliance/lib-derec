// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::{
    interop::wasm::{
        primitives::{
            helpers::{from_js, parse_shared_key, to_js},
            sharing::request::{CommittedDeRecShare, StoreShareRequestMessage},
        },
        ts_bindings_utils::js_error_from_lib,
    },
    primitives::sharing::response,
    types::ChannelId,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Shared with the C FFI boundary — see [`crate::interop::dto`], which
/// owns these definitions so the two SDK families cannot drift.
pub use crate::interop::dto::StoreShareResponseMessage;

#[derive(Serialize, Deserialize)]
pub struct ProduceResult {
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
    pub committed_share: CommittedDeRecShare,
    pub secret_id: u64,
    pub version: u32,
}

#[derive(Serialize, Deserialize)]
pub struct ExtractResult {
    pub response: StoreShareResponseMessage,
}

#[wasm_bindgen(js_name = "sharing_response_produce")]
pub fn produce(channel_id: u64, request: JsValue, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let request: StoreShareRequestMessage = from_js(request)?;
    let request_proto: derec_proto::StoreShareRequestMessage = request.into();

    let result = response::produce(ChannelId(channel_id), &request_proto, &shared_key)
        .map_err(js_error_from_lib)?;

    to_js(&ProduceResult {
        envelope: result.envelope,
        committed_share: result.committed_share.into(),
        secret_id: result.secret_id,
        version: result.version,
    })
}

#[wasm_bindgen(js_name = "sharing_response_extract")]
pub fn extract(envelope_bytes: &[u8], shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = response::extract(envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        response: result.response.into(),
    })
}

#[wasm_bindgen(js_name = "sharing_response_process")]
pub fn process(version: u32, response: JsValue) -> Result<(), JsValue> {
    let response: StoreShareResponseMessage = from_js(response)?;
    let response_proto: derec_proto::StoreShareResponseMessage = response.into();
    response::process(version, &response_proto).map_err(js_error_from_lib)
}
