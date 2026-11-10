// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! WASM bindings for envelope-level helpers that operate on raw
//! `DeRecMessage` bytes. Mirrors the FFI shape in `crate::interop::ffi::envelope`.

use crate::derec_message;
use crate::interop::wasm::primitives::helpers::to_js;
use crate::interop::wasm::ts_bindings_utils::{js_error, js_error_from_lib};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct MessageId {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    timestamp: u64,
}

/// Overwrite `trace_id` on a primitive-produced envelope and return the
/// re-encoded bytes. The outer envelope is plaintext, so this does no
/// crypto work.
///
/// Useful for consumers driving the protocol through primitives directly
/// (the orchestrator-level `DeRecProtocol` already handles trace_id
/// end-to-end on its own).
#[wasm_bindgen(js_name = "envelope_apply_trace_id")]
pub fn apply_trace_id(envelope_bytes: &[u8], trace_id: u64) -> Result<Vec<u8>, JsValue> {
    derec_message::apply_trace_id(envelope_bytes, trace_id)
        .map_err(|e| js_error("envelope_decode_error", e.to_string()))
}

/// Read `trace_id` off an inbound envelope without touching the encrypted
/// inner payload. Returns `0` when the sender didn't set one — the protobuf
/// default is indistinguishable from an explicit zero.
#[wasm_bindgen(js_name = "envelope_read_trace_id")]
pub fn read_trace_id(envelope_bytes: &[u8]) -> Result<u64, JsValue> {
    derec_message::read_trace_id(envelope_bytes)
        .map_err(|e| js_error("envelope_decode_error", e.to_string()))
}

/// Read `sequence` off an inbound envelope without touching the encrypted
/// inner payload: the epoch of the channel key that encrypted it. A caller
/// driving the protocol through primitives reads it to pick the key to pass
/// to an `*_extract` call, deriving it forward with `channel_key_derive` when
/// the epoch is newer than the key it holds.
#[wasm_bindgen(js_name = "envelope_read_sequence")]
pub fn read_sequence(envelope_bytes: &[u8]) -> Result<u32, JsValue> {
    derec_message::read_sequence(envelope_bytes)
        .map_err(|e| js_error("envelope_decode_error", e.to_string()))
}

/// Identify an envelope for replay and reflection detection: `{ id, timestamp }`,
/// where `id` (32 bytes) is the same for every copy of one message, whatever
/// its unauthenticated cleartext fields say, and different for every other
/// message. Mirrors [`derec_message::message_id`].
#[wasm_bindgen(js_name = "envelope_message_id")]
pub fn message_id(envelope_bytes: &[u8]) -> Result<JsValue, JsValue> {
    let identity = derec_message::message_id(envelope_bytes).map_err(js_error_from_lib)?;
    to_js(&MessageId {
        id: identity.id.to_vec(),
        timestamp: identity.timestamp,
    })
}
