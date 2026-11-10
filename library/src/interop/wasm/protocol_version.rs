use wasm_bindgen::prelude::*;

use crate::interop::wasm::ts_bindings_utils::js_error;
use crate::protocol_version::ProtocolVersion;

#[derive(serde::Serialize)]
struct ProtocolVersionJs {
    major: u32,
    minor: u32,
}

/// The DeRec protocol version this build speaks — the `protocolVersionMajor`
/// / `protocolVersionMinor` it writes into every envelope it produces —
/// as `{ major, minor }`.
#[wasm_bindgen(js_name = "protocol_version")]
pub fn protocol_version() -> Result<JsValue, JsValue> {
    let version = ProtocolVersion::current();
    serde_wasm_bindgen::to_value(&ProtocolVersionJs {
        major: version.major,
        minor: version.minor,
    })
    .map_err(|e| js_error("serialize", e.to_string()))
}
