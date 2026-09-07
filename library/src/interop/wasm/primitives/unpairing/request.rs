// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::{
    interop::wasm::{
        primitives::helpers::{parse_shared_key, parse_transport_protocol_list, to_js},
        ts_bindings_utils::js_error_from_lib,
    },
    primitives::unpairing::request,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Shared with the C FFI boundary — see [`crate::interop::dto`], which
/// owns these definitions so the two SDK families cannot drift.
pub use crate::interop::dto::UnpairRequestMessage;

#[derive(Serialize, Deserialize)]
pub struct ProduceResult {
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ExtractResult {
    pub request: UnpairRequestMessage,
}

#[wasm_bindgen(js_name = "unpairing_request_produce")]
pub fn produce(
    channel_id: u64,
    memo: &str,
    shared_key: &[u8],
    // Optional `TransportProtocol`. Pass null/undefined for no override.
    reply_to: JsValue,
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let reply_to_proto = parse_transport_protocol_list(reply_to)?;
    // Helper path. Replica-group removal is orchestrated through the
    // `RemoveReplica` flow, which names the departing member itself.
    let result = request::produce(channel_id.into(), memo, &shared_key, &reply_to_proto, None)
        .map_err(js_error_from_lib)?;
    to_js(&ProduceResult {
        envelope: result.envelope,
    })
}

#[wasm_bindgen(js_name = "unpairing_request_extract")]
pub fn extract(envelope_bytes: &[u8], shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = request::extract(envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        request: result.request.into(),
    })
}
