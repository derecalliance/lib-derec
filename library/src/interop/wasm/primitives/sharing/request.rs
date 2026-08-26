// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::{
    interop::wasm::{
        primitives::helpers::{
            from_js, parse_optional_transport_protocol, parse_shared_key, to_js,
        },
        ts_bindings_utils::js_error_from_lib,
    },
    primitives::sharing::request,
    types::ChannelId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

/// Shared with the C FFI boundary — see [`crate::interop::dto`], which
/// owns these definitions so the two SDK families cannot drift.
pub use crate::interop::dto::{CommittedDeRecShare, SiblingHash, StoreShareRequestMessage};

#[derive(Serialize, Deserialize)]
pub struct SplitResult {
    pub shares: HashMap<u64, CommittedDeRecShare>,
}

#[derive(Serialize, Deserialize)]
pub struct ProduceResult {
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ExtractResult {
    pub request: StoreShareRequestMessage,
}

#[wasm_bindgen(js_name = "sharing_request_split")]
pub fn split(
    channels: JsValue,
    secret_id: u64,
    version: u32,
    secret_data: &[u8],
    threshold: u32,
) -> Result<JsValue, JsValue> {
    let channel_ids_raw: Vec<u64> = from_js(channels)?;
    let channel_ids: Vec<ChannelId> = channel_ids_raw.into_iter().map(ChannelId::from).collect();

    let request::SplitResult { shares } = request::split(
        &channel_ids,
        secret_id,
        version,
        secret_data,
        threshold as usize,
    )
    .map_err(js_error_from_lib)?;

    let shares: HashMap<u64, CommittedDeRecShare> = shares
        .into_iter()
        .map(|(channel_id, share)| (channel_id.into(), share.into()))
        .collect();

    to_js(&SplitResult { shares })
}

#[wasm_bindgen(js_name = "sharing_request_produce")]
#[allow(clippy::too_many_arguments)]
pub fn produce(
    channel_id: u64,
    version: u32,
    secret_id: u64,
    committed_share: JsValue,
    keep_list: JsValue,
    description: String,
    shared_key: &[u8],
    // Optional `TransportProtocol` (serialized JS object) telling the
    // responder where to send the response. Pass `null`/`undefined` to
    // leave it absent (the responder routes to the channel's stored peer
    // endpoint).
    reply_to: JsValue,
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let committed_share: CommittedDeRecShare = from_js(committed_share)?;
    let committed_share_proto: derec_proto::CommittedDeRecShare = committed_share.into();
    let keep_list_raw: Vec<u32> = from_js(keep_list)?;
    let reply_to_proto = parse_optional_transport_protocol(reply_to)?;
    let result = request::produce(
        ChannelId(channel_id),
        version,
        secret_id,
        &committed_share_proto,
        &keep_list_raw,
        description,
        &shared_key,
        reply_to_proto,
    )
    .map_err(js_error_from_lib)?;

    to_js(&ProduceResult {
        envelope: result.envelope,
    })
}

#[wasm_bindgen(js_name = "sharing_request_extract")]
pub fn extract(envelope_bytes: &[u8], shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = request::extract(envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        request: result.request.into(),
    })
}
