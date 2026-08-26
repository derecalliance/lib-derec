// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::{
    interop::wasm::{
        primitives::helpers::{parse_optional_transport_protocol, parse_shared_key, to_js},
        ts_bindings_utils::js_error_from_lib,
    },
    primitives::recovery::request,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Shared with the C FFI boundary — see [`crate::interop::dto`], which
/// owns these definitions so the two SDK families cannot drift.
pub use crate::interop::dto::GetShareRequestMessage;

#[derive(Serialize, Deserialize)]
pub struct ProduceResult {
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ExtractResult {
    pub request: GetShareRequestMessage,
}

#[wasm_bindgen(js_name = "recovery_request_produce")]
pub fn produce(
    channel_id: u64,
    secret_id: u64,
    version: u32,
    shared_key: &[u8],
    // Optional `TransportProtocol`. Pass null/undefined for no override.
    reply_to: JsValue,
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let reply_to_proto = parse_optional_transport_protocol(reply_to)?;
    let result = request::produce(
        channel_id.into(),
        secret_id,
        version,
        &shared_key,
        reply_to_proto,
    )
    .map_err(js_error_from_lib)?;
    to_js(&ProduceResult {
        envelope: result.envelope,
    })
}

#[wasm_bindgen(js_name = "recovery_request_extract")]
pub fn extract(envelope_bytes: &[u8], shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = request::extract(envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        request: result.request.into(),
    })
}
