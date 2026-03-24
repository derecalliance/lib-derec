// SPDX-License-Identifier: Apache-2.0

//! WASM bindings for the DeRec sharing flow.
//!
//! The sharing flow returns one serialized outer `DeRecMessage` envelope per helper
//! channel. Each envelope contains an encrypted inner `StoreShareRequestMessage`.
//!
//! JavaScript callers must provide the paired helper channels together with their
//! 32-byte shared symmetric keys established during pairing.

use crate::{
    sharing,
    ts_bindings_utils::{js_error, js_error_from_lib},
    types::ChannelId,
};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct ChannelSharedKeyInput {
    /// Helper channel identifier.
    channel_id: u64,
    /// 32-byte shared symmetric key established during pairing.
    shared_key: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProtectSecretResultJs {
    /// One serialized outer `DeRecMessage` per helper channel.
    value: HashMap<u64, Vec<u8>>,
}

/// Generates verifiable secret shares and returns one serialized outer `DeRecMessage`
/// envelope per helper channel.
///
/// # JavaScript input shape
///
/// The `channels` argument must be a JS array of objects like:
///
/// ```ts
/// [
///   { channel_id: 1, shared_key: new Uint8Array(32) },
///   { channel_id: 2, shared_key: new Uint8Array(32) },
/// ]
/// ```
///
/// Each `shared_key` must be exactly 32 bytes.
///
/// The `keep_list` argument may be:
///
/// - `undefined` or `null`, meaning no keep-list is provided
/// - an array of integers, for example:
///
/// ```ts
/// [1, 2, 3]
/// ```
///
/// The `description` argument may be:
///
/// - `undefined` or `null`, meaning no description is provided
/// - a string, for example:
///
/// ```ts
/// "initial distribution"
/// ```
///
/// # Returns
///
/// A JS object of the form:
///
/// ```ts
/// {
///   value: {
///     [channelId: number]: Uint8Array
///   }
/// }
/// ```
///
/// where each value is a serialized outer `DeRecMessage` envelope.
///
/// # Arguments
///
/// * `secret_id` - Secret identifier embedded into each generated share
/// * `secret_data` - Secret bytes to split and distribute
/// * `channels` - JS array of `{ channel_id, shared_key }` entries
/// * `threshold` - Minimum number of shares required for reconstruction
/// * `version` - Share-distribution version embedded into the generated messages
/// * `keep_list` - Optional JS array of versions helpers should retain
/// * `description` - Optional version description
#[wasm_bindgen]
pub fn protect_secret(
    secret_id: &[u8],
    secret_data: &[u8],
    channels: JsValue,
    threshold: u32,
    version: i32,
    keep_list: JsValue,
    description: Option<String>,
) -> Result<JsValue, JsValue> {
    let channel_inputs: Vec<ChannelSharedKeyInput> = serde_wasm_bindgen::from_value(channels)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))?;

    let keep_list = parse_optional_i32_vec(keep_list)?;

    let mut channel_map: HashMap<ChannelId, [u8; 32]> =
        HashMap::with_capacity(channel_inputs.len());

    for entry in channel_inputs {
        let shared_key: [u8; 32] = entry.shared_key.try_into().map_err(|_| {
            js_error(
                "INVALID_SHARED_KEY_LENGTH",
                format!(
                    "shared_key for channel {} must be exactly 32 bytes",
                    entry.channel_id
                ),
            )
        })?;

        channel_map.insert(ChannelId::from(entry.channel_id), shared_key);
    }

    let sharing::ProtectSecretResult { shares } = sharing::protect_secret(
        secret_id,
        secret_data,
        channel_map,
        threshold as usize,
        version,
        keep_list.as_deref(),
        description.as_deref(),
    )
    .map_err(js_error_from_lib)?;

    let wrapper = ProtectSecretResultJs {
        value: shares
            .into_iter()
            .map(|(channel_id, wire_bytes)| {
                (<u64 as From<ChannelId>>::from(channel_id), wire_bytes)
            })
            .collect(),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

fn parse_optional_i32_vec(value: JsValue) -> Result<Option<Vec<i32>>, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }

    serde_wasm_bindgen::from_value(value)
        .map(Some)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))
}
