// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! WASM bindings for envelope-level helpers that operate on raw
//! `DeRecMessage` bytes. Mirrors the FFI shape in `crate::ffi::envelope`.

use crate::wasm::ts_bindings_utils::js_error;
use wasm_bindgen::prelude::*;

/// Overwrite `trace_id` on a primitive-produced envelope and return the
/// re-encoded bytes. The outer envelope is plaintext, so this does no
/// crypto work.
///
/// Useful for consumers driving the protocol through primitives directly
/// (the orchestrator-level `DeRecProtocol` already handles trace_id
/// end-to-end on its own).
#[wasm_bindgen(js_name = "envelope_apply_trace_id")]
pub fn apply_trace_id(envelope_bytes: &[u8], trace_id: u64) -> Result<Vec<u8>, JsValue> {
    crate::derec_message::apply_trace_id(envelope_bytes, trace_id)
        .map_err(|e| js_error("ENVELOPE_DECODE_ERROR", e.to_string()))
}

/// Read `trace_id` off an inbound envelope without touching the encrypted
/// inner payload. Returns `0` when the sender didn't set one — the protobuf
/// default is indistinguishable from an explicit zero.
#[wasm_bindgen(js_name = "envelope_read_trace_id")]
pub fn read_trace_id(envelope_bytes: &[u8]) -> Result<u64, JsValue> {
    crate::derec_message::read_trace_id(envelope_bytes)
        .map_err(|e| js_error("ENVELOPE_DECODE_ERROR", e.to_string()))
}
