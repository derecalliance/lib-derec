// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::module_inception)]
mod error;
pub use error::RecoveryError;

mod recovery;
pub use recovery::*;

use crate::protos::derec_proto::{
    GetShareRequestMessage, GetShareResponseMessage, StoreShareRequestMessage,
};
use prost::Message;

use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct TsRecoverShareResponses {
    value: std::collections::HashMap<u64, Vec<u8>>,
}

#[wasm_bindgen]
pub fn ts_generate_share_request(channel_id: u64, secret_id: &[u8], version: i32) -> Vec<u8> {
    recovery::generate_share_request(&channel_id, secret_id, version).encode_to_vec()
}

#[wasm_bindgen]
pub fn ts_generate_share_response(
    secret_id: &[u8],
    channel_id: u64,
    share_content: &[u8],
    request: &[u8],
) -> Vec<u8> {
    let request = GetShareRequestMessage::decode(request).unwrap();
    let share_content = StoreShareRequestMessage::decode(share_content).unwrap();
    recovery::generate_share_response(&channel_id, secret_id, &request, &share_content)
        .encode_to_vec()
}

#[wasm_bindgen]
pub fn ts_recover_from_share_responses(
    responses: JsValue,
    secret_id: &[u8],
    version: i32,
) -> Result<Vec<u8>, String> {
    let responses: TsRecoverShareResponses = serde_wasm_bindgen::from_value(responses).unwrap();
    let mut parsed_responses = Vec::new();
    for (_channel_id, bytes) in responses.value {
        let decoded = GetShareResponseMessage::decode(&*bytes).map_err(|e| e.to_string())?;
        parsed_responses.push(decoded);
    }

    let secret = recovery::recover_from_share_responses(&parsed_responses, secret_id, version)
        .map_err(|e| e.to_string())?;
    Ok(secret)
}

#[cfg(test)]
mod test;
