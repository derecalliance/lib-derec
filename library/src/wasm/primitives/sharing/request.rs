// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::{
    primitives::sharing::request,
    types::ChannelId,
    wasm::{
        primitives::{
            helpers::{from_js, parse_optional_transport_protocol, parse_shared_key, to_js},
            pairing::TransportProtocol,
            types::Timestamp,
        },
        ts_bindings_utils::js_error_from_lib,
    },
};
use derec_proto::committed_de_rec_share::SiblingHash as SiblingHashProto;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct SiblingHash {
    pub is_left: bool,
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

impl From<SiblingHashProto> for SiblingHash {
    fn from(value: SiblingHashProto) -> Self {
        Self {
            is_left: value.is_left,
            hash: value.hash,
        }
    }
}

impl From<SiblingHash> for SiblingHashProto {
    fn from(value: SiblingHash) -> Self {
        Self {
            is_left: value.is_left,
            hash: value.hash,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommittedDeRecShare {
    #[serde(with = "serde_bytes")]
    pub de_rec_share: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub commitment: Vec<u8>,
    pub merkle_path: Vec<SiblingHash>,
}

impl From<derec_proto::CommittedDeRecShare> for CommittedDeRecShare {
    fn from(value: derec_proto::CommittedDeRecShare) -> Self {
        Self {
            de_rec_share: value.de_rec_share,
            commitment: value.commitment,
            merkle_path: value.merkle_path.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<CommittedDeRecShare> for derec_proto::CommittedDeRecShare {
    fn from(value: CommittedDeRecShare) -> Self {
        Self {
            de_rec_share: value.de_rec_share,
            commitment: value.commitment,
            merkle_path: value.merkle_path.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoreShareRequestMessage {
    #[serde(with = "serde_bytes")]
    pub share: Vec<u8>,
    pub share_algorithm: i32,
    pub version: u32,
    pub keep_list: Vec<u32>,
    pub version_description: String,
    pub timestamp: Option<Timestamp>,
    pub secret_id: u64,
    /// Optional ephemeral response endpoint. See `replyTo` on the request
    /// proto for the routing semantics.
    pub reply_to: Option<TransportProtocol>,
    /// Optional `replica_id` of the writer. See the proto's `replicaId`
    /// field for the disambiguation contract.
    pub replica_id: Option<u64>,
}

impl From<derec_proto::StoreShareRequestMessage> for StoreShareRequestMessage {
    fn from(value: derec_proto::StoreShareRequestMessage) -> Self {
        Self {
            share: value.share,
            share_algorithm: value.share_algorithm,
            version: value.version,
            keep_list: value.keep_list,
            version_description: value.version_description,
            timestamp: value.timestamp.map(Into::into),
            secret_id: value.secret_id,
            reply_to: value.reply_to.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

impl From<StoreShareRequestMessage> for derec_proto::StoreShareRequestMessage {
    fn from(value: StoreShareRequestMessage) -> Self {
        Self {
            share: value.share,
            share_algorithm: value.share_algorithm,
            version: value.version,
            keep_list: value.keep_list,
            version_description: value.version_description,
            timestamp: value.timestamp.map(Into::into),
            secret_id: value.secret_id,
            reply_to: value.reply_to.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

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
    // Optional writer `replica_id` as a JS `Option<u64>` (passed as
    // `null`/`undefined` for "non-replica Owner", or a `bigint` /
    // decimal string for the producing replica's id). Stamped onto the
    // outbound `StoreShareRequestMessage.replicaId` — see the proto's
    // `replicaId` doc for the disambiguation contract.
    replica_id: JsValue,
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let committed_share: CommittedDeRecShare = from_js(committed_share)?;
    let committed_share_proto: derec_proto::CommittedDeRecShare = committed_share.into();
    let keep_list_raw: Vec<u32> = from_js(keep_list)?;
    let reply_to_proto = parse_optional_transport_protocol(reply_to)?;
    let replica_id_opt: Option<u64> = if replica_id.is_null() || replica_id.is_undefined() {
        None
    } else {
        Some(from_js(replica_id)?)
    };

    let result = request::produce(
        ChannelId(channel_id),
        version,
        secret_id,
        &committed_share_proto,
        &keep_list_raw,
        description,
        &shared_key,
        reply_to_proto,
        replica_id_opt,
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
