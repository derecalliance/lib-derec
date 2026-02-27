pub mod sharing;
use prost::Message;
pub use sharing::protect_secret;

use wasm_bindgen::prelude::*;
use std::collections::HashMap;
use crate::Error;

#[derive(serde::Serialize, serde::Deserialize)]
struct TsProtectSecretResult {
    value: HashMap<u64, Vec<u8>>,
}

fn to_js_error(err: Error) -> JsValue {
    JsValue::from_str(&err.to_string())
}

#[wasm_bindgen]
pub fn ts_protect_secret(
    secret_id: &[u8],
    secret_data: &[u8],
    channels: &[u64],
    threshold: u32,
    version: u32,
) -> Result<JsValue, JsValue> {

    let sharing = sharing::protect_secret(
        secret_id,
        secret_data,
        channels,
        threshold as usize,
        version as i32,
        None,
        None,
    ).map_err(to_js_error)?;

    let wrapper = TsProtectSecretResult { value: sharing.into_iter().map(|(k, v)| (k, v.encode_to_vec())).collect() };
    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|err| to_js_error(Error::Serialization(err.to_string())))
}

#[cfg(test)]
mod test;
