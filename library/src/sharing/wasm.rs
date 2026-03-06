// SPDX-License-Identifier: Apache-2.0

use crate::{
    sharing::{ProtectSecretResult, protect_secret},
    ts_bindings_utils::{js_error, js_error_from_lib},
    types::ChannelId,
};
use prost::Message;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct TsProtectSecretResult {
    value: HashMap<ChannelId, Vec<u8>>,
}

#[wasm_bindgen]
pub fn ts_protect_secret(
    secret_id: &[u8],
    secret_data: &[u8],
    channels: &[u64],
    threshold: u32,
    version: u32,
) -> Result<JsValue, JsValue> {
    let channels: Vec<ChannelId> = channels.iter().copied().map(ChannelId::from).collect();

    let ProtectSecretResult { shares } = protect_secret(
        secret_id,
        secret_data,
        channels,
        threshold as usize,
        version as i32,
        None,
        None,
    )
    .map_err(js_error_from_lib)?;

    let wrapper = TsProtectSecretResult {
        value: shares
            .into_iter()
            .map(|(k, v)| (k, v.encode_to_vec()))
            .collect(),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}
