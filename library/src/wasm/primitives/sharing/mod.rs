// SPDX-License-Identifier: Apache-2.0

pub mod request;
pub mod response;

use crate::ts_bindings_utils::js_error;
use derec_proto::{CommittedDeRecShare, DeRecShare};
use prost::Message as _;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize)]
struct DeRecShareDecodedJs {
    encrypted_secret: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
    secret_id: Vec<u8>,
    version: i32,
}

#[derive(serde::Serialize)]
struct SiblingHashJs {
    is_left: bool,
    hash: Vec<u8>,
}

#[derive(serde::Serialize)]
struct CommittedShareDecodedJs {
    de_rec_share: DeRecShareDecodedJs,
    commitment: Vec<u8>,
    merkle_path: Vec<SiblingHashJs>,
}

/// Decodes a serialized `CommittedDeRecShare` protobuf into a plain JS object.
///
/// Useful for inspecting the contents of a share returned by `sharing_request_split`.
///
/// # Arguments
///
/// * `bytes` - Serialized `CommittedDeRecShare` protobuf bytes.
///
/// # Returns
///
/// A JS object with:
///
/// - `de_rec_share`: `{ encrypted_secret, x, y, secret_id, version }`
/// - `commitment`: `Uint8Array` (Merkle root)
/// - `merkle_path`: `Array<{ is_left: bool, hash: Uint8Array }>`
#[wasm_bindgen(js_name = "sharing_decode_committed_share")]
pub fn decode_committed_share(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let committed = CommittedDeRecShare::decode(bytes)
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;

    let de_rec_share = DeRecShare::decode(committed.de_rec_share.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;

    let result = CommittedShareDecodedJs {
        de_rec_share: DeRecShareDecodedJs {
            encrypted_secret: de_rec_share.encrypted_secret,
            x: de_rec_share.x,
            y: de_rec_share.y,
            secret_id: de_rec_share.secret_id,
            version: de_rec_share.version,
        },
        commitment: committed.commitment,
        merkle_path: committed
            .merkle_path
            .into_iter()
            .map(|s| SiblingHashJs {
                is_left: s.is_left,
                hash: s.hash,
            })
            .collect(),
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}
