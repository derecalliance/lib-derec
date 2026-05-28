// SPDX-License-Identifier: Apache-2.0

use crate::wasm::ts_bindings_utils::js_error;
use serde::Serialize;
use wasm_bindgen::JsValue;

pub(crate) fn parse_shared_key(shared_key: &[u8]) -> Result<[u8; 32], JsValue> {
    shared_key.try_into().map_err(|_| {
        js_error(
            "INVALID_SHARED_KEY_LENGTH",
            "shared_key must be exactly 32 bytes".to_string(),
        )
    })
}

pub(crate) fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    let serializer =
        serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
    value
        .serialize(&serializer)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

pub(crate) fn from_js<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))
}
