// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::module_inception)]
mod error;
pub use error::SharingError;

mod sharing;
pub use sharing::*;

mod types;
pub use types::*;

use crate::ts_bindings_utils::{js_error, js_error_from_lib};
use prost::Message;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct TsProtectSecretResult {
    value: HashMap<u64, Vec<u8>>,
}

#[wasm_bindgen]
pub fn ts_protect_secret(
    secret_id: &[u8],
    secret_data: &[u8],
    channels: &[u64],
    threshold: u32,
    version: u32,
) -> Result<JsValue, JsValue> {
    let ProtectSecretResult { shares } = sharing::protect_secret(
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

#[cfg(test)]
mod test;
