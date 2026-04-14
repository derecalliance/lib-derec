// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::sharing::request,
    ts_bindings_utils::{
        derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib,
        js_to_derec_message,
    },
    types::ChannelId,
};
use derec_proto::{CommittedDeRecShare, DeRecMessage};
use prost::Message as _;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct SplitResultJs {
    /// One serialized [`CommittedDeRecShare`] per helper channel, keyed by channel ID.
    value: HashMap<u64, Vec<u8>>,
}

/// Splits a secret into verifiable committed shares, one per helper channel.
///
/// # Arguments
///
/// * `secret_id` - Secret identifier bytes
/// * `secret_data` - Raw secret bytes to split
/// * `channels` - JS array of BigInt channel IDs (one share per channel)
/// * `threshold` - Minimum shares required to reconstruct (must satisfy `2 <= threshold <= channels.len()`)
/// * `version` - Logical version of this secret distribution
///
/// # Returns
///
/// A JS object `{ value: { [channelId: bigint]: Uint8Array } }` — one serialized
/// `CommittedDeRecShare` per helper channel.
#[wasm_bindgen(js_name = "sharing_request_split")]
pub fn split(
    secret_id: &[u8],
    secret_data: &[u8],
    channels: JsValue,
    threshold: u32,
    version: i32,
) -> Result<JsValue, JsValue> {
    let channel_ids_raw: Vec<u64> = serde_wasm_bindgen::from_value(channels)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))?;

    let channel_ids: Vec<ChannelId> = channel_ids_raw.into_iter().map(ChannelId::from).collect();

    let request::SplitResult { shares } =
        request::split(&channel_ids, secret_id, version, secret_data, threshold as usize)
            .map_err(js_error_from_lib)?;

    let wrapper = SplitResultJs {
        value: shares
            .into_iter()
            .map(|(channel_id, share)| {
                (<u64 as From<ChannelId>>::from(channel_id), share.encode_to_vec())
            })
            .collect(),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Wraps a committed helper share into an encrypted delivery envelope.
///
/// # Arguments
///
/// * `channel_id` - BigInt channel ID of the target helper
/// * `version` - Integer share-distribution version
/// * `secret_id` - Secret identifier bytes
/// * `committed_share` - `Uint8Array` of serialized `CommittedDeRecShare` protobuf bytes
/// * `keep_list` - JS array of integers
/// * `description` - String description
/// * `shared_key` - `Uint8Array` of exactly 32 bytes
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` envelope.
/// Send this object to the helper over the channel transport.
#[wasm_bindgen(js_name = "sharing_request_produce")]
pub fn produce(
    channel_id: u64,
    version: i32,
    secret_id: &[u8],
    committed_share: &[u8],
    keep_list: JsValue,
    description: String,
    shared_key: &[u8],
) -> Result<JsValue, JsValue> {
    if shared_key.len() != 32 {
        return Err(js_error(
            "INVALID_SHARED_KEY",
            format!("shared_key must be exactly 32 bytes, got {}", shared_key.len()),
        ));
    }

    let shared_key_arr: &[u8; 32] = shared_key
        .try_into()
        .expect("shared_key length validated to be 32");

    let keep_list_raw: Vec<i32> = serde_wasm_bindgen::from_value(keep_list)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))?;

    let committed_share_proto = CommittedDeRecShare::decode(committed_share)
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;

    let result = request::produce(
        ChannelId(channel_id),
        version,
        secret_id,
        &committed_share_proto,
        &keep_list_raw,
        description,
        shared_key_arr,
    )
    .map_err(js_error_from_lib)?;

    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}
