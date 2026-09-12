// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::interop::wasm::ts_bindings_utils::js_error;
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

/// Serialize a `T` into a `JsValue` across the wasm→JS boundary.
///
/// # Security: `serialize_large_number_types_as_bigints(true)` is required
///
/// Several primitive return types (e.g.
/// [`crate::interop::wasm::primitives::verification::request::VerifyShareRequestMessage`])
/// expose `u64` fields directly — `secret_id`, `nonce`, `channel_id`,
/// and friends. The default `serde_wasm_bindgen` behaviour would
/// serialize a `u64` as a JS `number`, which can only exactly
/// represent integers up to `2^53 − 1` (`Number.MAX_SAFE_INTEGER`).
/// For full 64-bit identifiers and random nonces that is a silent
/// truncation — distinct values collide after rounding, breaking
/// equality checks, nonce-uniqueness invariants, and per-secret
/// routing on the JS side.
///
/// Enabling `serialize_large_number_types_as_bigints(true)` forces
/// every `u64` / `i64` field to cross the boundary as a JS
/// `BigInt`, preserving the full 64-bit value. **Do not remove
/// this flag** without understanding the precision/security
/// implications; the binding `.d.ts` files type these fields as
/// `bigint` and consumers rely on that contract.
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

/// Parse a `TransportProtocol` array from a JS value. `null` and `undefined`
/// both yield an empty list — the convention every `produce_*_request`
/// wrapper uses for `reply_to`, where "none supplied" means "route to the
/// endpoints already on file for the channel".
pub(crate) fn parse_transport_protocol_list(
    value: JsValue,
) -> Result<Vec<derec_proto::TransportProtocol>, JsValue> {
    if value.is_null() || value.is_undefined() {
        return Ok(Vec::new());
    }
    let list: Vec<crate::interop::wasm::primitives::pairing::TransportProtocol> = from_js(value)?;
    Ok(list.into_iter().map(Into::into).collect())
}
