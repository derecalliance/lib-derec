// SPDX-License-Identifier: Apache-2.0

//! WASM bindings for the DeRec sharing flow.
//!
//! The sharing flow returns one [`CommittedDeRecShare`] per helper channel.
//! Each share must then be wrapped into a delivery envelope using
//! `produce_store_share_request_message` before being sent to the helper.
//!
//! JavaScript callers provide the set of helper channel identifiers and receive
//! one serialized [`CommittedDeRecShare`] per channel.

use crate::{
    sharing,
    ts_bindings_utils::{js_error, js_error_from_lib},
    types::ChannelId,
};
use derec_proto::CommittedDeRecShare;
use prost::Message;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize)]
struct ProduceStoreShareRequestMessageResultJs {
    wire_bytes: Vec<u8>,
}

#[derive(serde::Serialize)]
struct ProduceStoreShareResponseMessageResultJs {
    /// Response wire bytes to send back to the Owner.
    wire_bytes: Vec<u8>,
    /// Serialized [`CommittedDeRecShare`] protobuf bytes for the Helper to store locally.
    committed_share: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProtectSecretResultJs {
    /// One serialized [`CommittedDeRecShare`] per helper channel, keyed by channel ID.
    value: HashMap<u64, Vec<u8>>,
}

/// Generates verifiable secret shares and returns one serialized
/// [`CommittedDeRecShare`] per helper channel.
///
/// # JavaScript input shape
///
/// The `channels` argument must be a JS array of channel ID numbers:
///
/// ```ts
/// [1n, 2n, 3n]
/// ```
///
/// Duplicate channel IDs are deduplicated automatically.
///
/// # Returns
///
/// A JS object of the form:
///
/// ```ts
/// {
///   value: {
///     [channelId: number]: Uint8Array  // serialized CommittedDeRecShare bytes
///   }
/// }
/// ```
///
/// Each `Uint8Array` value is serialized [`CommittedDeRecShare`] protobuf bytes.
/// Pass each entry to `produce_store_share_request_message` together with the
/// helper's shared key to produce the encrypted delivery envelope.
///
/// # Arguments
///
/// * `secret_id` - Secret identifier embedded into each generated share
/// * `secret_data` - Secret bytes to split and distribute
/// * `channels` - JS array of channel ID numbers
/// * `threshold` - Minimum number of shares required for reconstruction
/// * `version` - Share-distribution version embedded into the generated shares
#[wasm_bindgen]
pub fn protect_secret(
    secret_id: &[u8],
    secret_data: &[u8],
    channels: JsValue,
    threshold: u32,
    version: i32,
) -> Result<JsValue, JsValue> {
    let channel_ids_raw: Vec<u64> = serde_wasm_bindgen::from_value(channels)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))?;

    let channel_ids: Vec<ChannelId> = channel_ids_raw
        .into_iter()
        .map(ChannelId::from)
        .collect();

    let sharing::ProtectSecretResult { shares } = sharing::protect_secret(
        secret_id,
        secret_data,
        &channel_ids,
        threshold as usize,
        version,
    )
    .map_err(js_error_from_lib)?;

    let wrapper = ProtectSecretResultJs {
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
/// Call this once for each share returned by [`protect_secret`], providing the corresponding
/// helper's shared key (established during pairing). Send the resulting `wire_bytes` to the
/// helper over the channel transport.
///
/// # JavaScript input
///
/// - `channel_id`: BigInt channel ID of the target helper
/// - `version`: integer share-distribution version
/// - `committed_share`: `Uint8Array` of serialized `CommittedDeRecShare` protobuf bytes
///   (a value from the map returned by [`protect_secret`])
/// - `keep_list`: JS array of integers representing version numbers the helper should retain
/// - `description`: string description for this share distribution
/// - `shared_key`: `Uint8Array` of exactly 32 bytes (symmetric shared key from pairing)
///
/// # Returns
///
/// A JS object of the form:
///
/// ```ts
/// { wire_bytes: Uint8Array }
/// ```
#[wasm_bindgen]
pub fn produce_store_share_request_message(
    channel_id: u64,
    version: i32,
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

    let result = sharing::produce_store_share_request_message(
        ChannelId(channel_id),
        version,
        &committed_share_proto,
        &keep_list_raw,
        description,
        shared_key_arr,
    )
    .map_err(js_error_from_lib)?;

    serde_wasm_bindgen::to_value(&ProduceStoreShareRequestMessageResultJs {
        wire_bytes: result.wire_bytes,
    })
    .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Processes an incoming sharing request on behalf of a Helper.
///
/// Decrypts and validates the [`StoreShareRequestMessage`] carried inside the provided
/// [`DeRecMessage`] envelope, extracts the [`CommittedDeRecShare`], and returns an
/// encrypted [`StoreShareResponseMessage`] plus the committed share bytes for local storage.
///
/// # JavaScript input
///
/// - `channel_id`: BigInt channel ID of the Owner channel this request arrived on
/// - `shared_key`: `Uint8Array` of exactly 32 bytes (symmetric shared key from pairing)
/// - `request_bytes`: `Uint8Array` of the serialized `DeRecMessage` envelope received from the
///   Owner (as produced by `produce_store_share_request_message`)
///
/// # Returns
///
/// A JS object of the form:
///
/// ```ts
/// {
///   wire_bytes: Uint8Array,    // response envelope — send back to the Owner
///   committed_share: Uint8Array // serialized CommittedDeRecShare — store locally
/// }
/// ```
#[wasm_bindgen]
pub fn produce_store_share_response_message(
    channel_id: u64,
    shared_key: &[u8],
    request_bytes: &[u8],
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

    let result = sharing::produce_store_share_response_message(
        ChannelId(channel_id),
        shared_key_arr,
        request_bytes,
    )
    .map_err(js_error_from_lib)?;

    serde_wasm_bindgen::to_value(&ProduceStoreShareResponseMessageResultJs {
        wire_bytes: result.wire_bytes,
        committed_share: result.committed_share.encode_to_vec(),
    })
    .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Validates a sharing response received from a Helper.
///
/// Call this on the **Owner** side after receiving the Helper's response to a
/// `produce_store_share_request_message` envelope.
///
/// # JavaScript input
///
/// - `version`: integer share-distribution version that was sent in the request
/// - `shared_key`: `Uint8Array` of exactly 32 bytes (symmetric shared key from pairing)
/// - `response_bytes`: `Uint8Array` of the serialized `DeRecMessage` envelope received from
///   the Helper (as produced by `produce_store_share_response_message`)
///
/// # Returns
///
/// Returns `undefined` (void) on success. Throws if the response cannot be decrypted,
/// decoded, fails invariant checks, or the Helper's status is not `Ok` (in which case
/// the thrown error includes the Helper's status code and memo).
#[wasm_bindgen]
pub fn process_store_share_response_message(
    version: i32,
    shared_key: &[u8],
    response_bytes: &[u8],
) -> Result<(), JsValue> {
    if shared_key.len() != 32 {
        return Err(js_error(
            "INVALID_SHARED_KEY",
            format!("shared_key must be exactly 32 bytes, got {}", shared_key.len()),
        ));
    }

    let shared_key_arr: &[u8; 32] = shared_key
        .try_into()
        .expect("shared_key length validated to be 32");

    sharing::process_store_share_response_message(version, shared_key_arr, response_bytes)
        .map_err(js_error_from_lib)
}
