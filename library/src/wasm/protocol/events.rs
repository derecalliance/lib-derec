// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Converts [`DeRecEvent`] values to plain JS objects for TypeScript
//! consumers.
//!
//! The wire shape is shared with the FFI bridge via
//! [`crate::protocol::events::wire`] — see that module for the
//! per-variant docs and the field-name conventions.

use serde::Serialize;
use wasm_bindgen::JsValue;

use crate::protocol::{events::wire, DeRecEvent};
use crate::wasm::ts_bindings_utils::js_error;

pub fn event_to_js(event: DeRecEvent) -> Result<JsValue, JsValue> {
    let mirror = wire::Event::from_event(event)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e))?;
    let serializer =
        serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    mirror
        .serialize(&serializer)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}
