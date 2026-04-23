// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::channels_discovery::response::{self, ChannelEntry},
    types::ChannelId,
    wasm::ts_bindings_utils::{derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct ChannelEntryJs {
    channel_id: u64,
    shared_key: Vec<u8>,
}

/// Produces a channels discovery response envelope (Owner side).
///
/// # Arguments
///
/// * `channel_id` - Owner↔Replica channel identifier
/// * `shared_key` - 32-byte symmetric key for the Owner↔Replica channel
/// * `entries` - JS array of `{ channel_id: number, shared_key: Uint8Array }` objects
/// * `total_batches` - Total number of batches
/// * `current_batch` - 1-based index of this batch
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` envelope.
#[wasm_bindgen(js_name = "channels_discovery_response_produce")]
pub fn produce(
    channel_id: u64,
    shared_key: &[u8],
    entries: JsValue,
    total_batches: i32,
    current_batch: i32,
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let entries_js: Vec<ChannelEntryJs> = serde_wasm_bindgen::from_value(entries)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))?;

    let channel_entries: Vec<ChannelEntry> = entries_js
        .into_iter()
        .map(|e| {
            let key: [u8; 32] = e.shared_key.as_slice().try_into().map_err(|_| {
                js_error(
                    "INVALID_SHARED_KEY_LENGTH",
                    "each entry shared_key must be exactly 32 bytes".to_string(),
                )
            })?;
            Ok(ChannelEntry {
                channel_id: ChannelId(e.channel_id),
                shared_key: key,
            })
        })
        .collect::<Result<Vec<_>, JsValue>>()?;

    let result = response::produce(
        channel_id.into(),
        &shared_key,
        &channel_entries,
        total_batches,
        current_batch,
    )
    .map_err(js_error_from_lib)?;

    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}

/// Decodes, decrypts, and processes a channels discovery response envelope (Replica side).
///
/// # Arguments
///
/// * `response` - Outer `DeRecMessage` JS object
/// * `shared_key` - 32-byte symmetric key for the Owner↔Replica channel
///
/// # Returns
///
/// A JS object `{ total_batches: number, current_batch: number, entries: ChannelEntry[] }`.
#[wasm_bindgen(js_name = "channels_discovery_response_process")]
pub fn process(resp: JsValue, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let envelope = js_to_derec_message(resp, "response")?;
    let envelope_bytes = envelope.encode_to_vec();

    let response::ExtractResult { response: inner } =
        response::extract(&envelope_bytes, &shared_key).map_err(js_error_from_lib)?;

    let response::ProcessResult {
        total_batches,
        current_batch,
        entries,
    } = response::process(&inner).map_err(js_error_from_lib)?;

    #[derive(serde::Serialize)]
    struct ProcessResultJs {
        total_batches: i32,
        current_batch: i32,
        entries: Vec<ChannelEntryJs>,
    }

    let entries_js: Vec<ChannelEntryJs> = entries
        .into_iter()
        .map(|e| ChannelEntryJs {
            channel_id: e.channel_id.0,
            shared_key: e.shared_key.to_vec(),
        })
        .collect();

    serde_wasm_bindgen::to_value(&ProcessResultJs {
        total_batches,
        current_batch,
        entries: entries_js,
    })
    .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

fn parse_shared_key(shared_key: &[u8]) -> Result<[u8; 32], JsValue> {
    shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })
}
