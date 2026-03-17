use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(serde::Serialize)]
struct TsError {
    code: &'static str,
    message: String,
}

pub(crate) fn js_error(code: &'static str, message: impl Into<String>) -> JsValue {
    serde_wasm_bindgen::to_value(&TsError {
        code,
        message: message.into(),
    })
    .unwrap_or_else(|_| JsValue::from_str("failed to serialize error"))
}

pub(crate) fn js_error_from_lib(err: crate::Error) -> JsValue {
    js_error("DEREC_ERROR", err.to_string())
}

#[wasm_bindgen(start)]
pub fn wasm_start() {
    console_error_panic_hook::set_once();
}
