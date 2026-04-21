// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::discovery::response::{self, SecretVersionEntry, VersionEntry},
    wasm::ts_bindings_utils::{derec_message_js_to_js_value, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

/// One stored version paired with its human-readable description, as used in JS.
#[derive(serde::Serialize, serde::Deserialize)]
struct VersionEntryJs {
    version: i32,
    description: String,
}

/// One entry in a discovery response as used in JS: a secret ID with all stored versions.
#[derive(serde::Serialize, serde::Deserialize)]
struct SecretVersionEntryJs {
    secret_id: Vec<u8>,
    versions: Vec<VersionEntryJs>,
}

impl From<SecretVersionEntry> for SecretVersionEntryJs {
    fn from(e: SecretVersionEntry) -> Self {
        Self {
            secret_id: e.secret_id,
            versions: e
                .versions
                .into_iter()
                .map(|v| VersionEntryJs {
                    version: v.version,
                    description: v.description,
                })
                .collect(),
        }
    }
}

impl From<SecretVersionEntryJs> for SecretVersionEntry {
    fn from(e: SecretVersionEntryJs) -> Self {
        Self {
            secret_id: e.secret_id,
            versions: e
                .versions
                .into_iter()
                .map(|v| VersionEntry {
                    version: v.version,
                    description: v.description,
                })
                .collect(),
        }
    }
}

/// Produces a discovery response envelope (Helper side).
///
/// Called after the Helper receives and extracts a discovery request. The Helper
/// enumerates all secrets it currently stores for this channel — including the
/// human-readable description for each version — and passes them here.
///
/// # Arguments
///
/// * `channel_id` - Recovery channel identifier established during pairing
/// * `secret_list` - JS array of objects with shape
///   `{ secret_id: Uint8Array, versions: [{ version: number, description: string }] }`.
///   Pass an empty array if no secrets are stored for this channel.
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// A plain JS object representing the outer `DeRecMessage` response envelope,
/// ready to send back to the Owner.
#[wasm_bindgen(js_name = "discovery_response_produce")]
pub fn produce(
    channel_id: u64,
    secret_list: JsValue,
    shared_key: &[u8],
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let entries_js: Vec<SecretVersionEntryJs> = serde_wasm_bindgen::from_value(secret_list)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))?;

    let secret_list: Vec<SecretVersionEntry> =
        entries_js.into_iter().map(SecretVersionEntry::from).collect();

    let result = response::produce(channel_id.into(), &secret_list, &shared_key)
        .map_err(js_error_from_lib)?;

    let envelope = DeRecMessage::decode(result.envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    derec_message_js_to_js_value(derec_message_to_js(envelope))
}

/// Decodes, decrypts, and processes a discovery response envelope (Owner side).
///
/// Combines the `extract` and `process` steps into a single call. The Owner
/// passes the response envelope received from the Helper and receives the full
/// list of secrets with their versions and descriptions.
///
/// # Arguments
///
/// * `response` - Outer `DeRecMessage` JS object from `discovery_response_produce`
/// * `shared_key` - 32-byte symmetric key established during pairing
///
/// # Returns
///
/// A JS array of objects with shape
/// `{ secret_id: Uint8Array, versions: [{ version: number, description: string }] }`.
/// The Owner can inspect `description` to identify secrets by their human-readable
/// label before calling `recovery_request_produce`.
#[wasm_bindgen(js_name = "discovery_response_process")]
pub fn process(resp: JsValue, shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let envelope = js_to_derec_message(resp, "response")?;
    let envelope_bytes = envelope.encode_to_vec();

    let response::ExtractResult { response } =
        response::extract(&envelope_bytes, &shared_key).map_err(js_error_from_lib)?;

    let response::ProcessResult { secret_list } =
        response::process(&response).map_err(js_error_from_lib)?;

    let entries_js: Vec<SecretVersionEntryJs> =
        secret_list.into_iter().map(SecretVersionEntryJs::from).collect();

    serde_wasm_bindgen::to_value(&entries_js)
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
