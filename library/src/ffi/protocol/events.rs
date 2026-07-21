// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! JSON encoder for [`DeRecEvent`] streams emitted by the orchestrator
//! across the FFI boundary. The wire shape lives in
//! [`crate::protocol::events::wire`] and is shared with the WASM bridge
//! — every event is a JSON object with a `"type"` discriminator and the
//! variant payload as sibling fields.

use crate::protocol::{events::wire, DeRecEvent};

/// Encode an event stream to a UTF-8 JSON array (`[ {...}, {...}, ... ]`)
/// ready to ship over the FFI boundary as a `DeRecBuffer`. Events whose
/// inner [`crate::protocol::PendingAction`] fails to serialize are
/// emitted as `NoOp` so the array length still matches the input.
pub fn encode_events(events: Vec<DeRecEvent>) -> Vec<u8> {
    let mapped: Vec<wire::Event> = events
        .into_iter()
        .map(|e| wire::Event::from_event(e).unwrap_or(wire::Event::NoOp))
        .collect();
    serde_json::to_vec(&mapped).expect("DeRecEvent JSON encoding is infallible")
}
