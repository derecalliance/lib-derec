use derec_proto::DeRecMessage;
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

/// A `DeRecMessage` represented as a plain JS object, safe for TypeScript consumers.
///
/// `channel_id` and `timestamp.seconds` are serialized as decimal strings to safely
/// round-trip `u64`/`i64` through JavaScript, which cannot represent integers above
/// `Number.MAX_SAFE_INTEGER` (2^53 − 1).
///
/// The `message` field contains raw encrypted bytes and is exposed as a byte array.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct DeRecMessageJs {
    pub protocol_version_major: u32,
    pub protocol_version_minor: u32,
    pub sequence: u32,
    /// Decimal string representation of the u64 channel identifier.
    pub channel_id: String,
    pub timestamp: Option<TimestampJs>,
    /// Encrypted inner message bytes.
    pub message: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct TimestampJs {
    /// Decimal string representation of the i64 seconds field.
    pub seconds: String,
    pub nanos: i32,
}

pub(crate) fn derec_message_to_js(msg: DeRecMessage) -> DeRecMessageJs {
    DeRecMessageJs {
        protocol_version_major: msg.protocol_version_major,
        protocol_version_minor: msg.protocol_version_minor,
        sequence: msg.sequence,
        channel_id: msg.channel_id.to_string(),
        timestamp: msg.timestamp.map(|ts| TimestampJs {
            seconds: ts.seconds.to_string(),
            nanos: ts.nanos,
        }),
        message: msg.message,
    }
}

pub(crate) fn js_to_derec_message(
    js_val: JsValue,
    context: &'static str,
) -> Result<DeRecMessage, JsValue> {
    let js: DeRecMessageJs = serde_wasm_bindgen::from_value(js_val)
        .map_err(|e| js_error("DECODE_ERROR", format!("{context}: {e}")))?;

    let channel_id = js
        .channel_id
        .parse::<u64>()
        .map_err(|e| js_error("DECODE_ERROR", format!("{context}: invalid channel_id: {e}")))?;

    let timestamp = js.timestamp.map(|ts| {
        let seconds = ts.seconds.parse::<i64>().unwrap_or(0);
        prost_types::Timestamp {
            seconds,
            nanos: ts.nanos,
        }
    });

    Ok(DeRecMessage {
        protocol_version_major: js.protocol_version_major,
        protocol_version_minor: js.protocol_version_minor,
        sequence: js.sequence,
        channel_id,
        timestamp,
        message: js.message,
    })
}

/// Convert an already-deserialized `DeRecMessageJs` struct into a `DeRecMessage` protobuf.
pub(crate) fn derec_message_js_struct_to_proto(
    js: DeRecMessageJs,
    context: &'static str,
) -> Result<DeRecMessage, JsValue> {
    let channel_id = js
        .channel_id
        .parse::<u64>()
        .map_err(|e| js_error("DECODE_ERROR", format!("{context}: invalid channel_id: {e}")))?;
    let timestamp = js.timestamp.map(|ts| {
        let seconds = ts.seconds.parse::<i64>().unwrap_or(0);
        prost_types::Timestamp {
            seconds,
            nanos: ts.nanos,
        }
    });
    Ok(DeRecMessage {
        protocol_version_major: js.protocol_version_major,
        protocol_version_minor: js.protocol_version_minor,
        sequence: js.sequence,
        channel_id,
        timestamp,
        message: js.message,
    })
}

/// Serialize a `DeRecMessageJs` to a `JsValue`.
pub(crate) fn derec_message_js_to_js_value(msg_js: DeRecMessageJs) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&msg_js)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

#[wasm_bindgen(start)]
pub fn wasm_start() {
    console_error_panic_hook::set_once();
}
