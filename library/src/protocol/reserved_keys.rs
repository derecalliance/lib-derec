// SPDX-License-Identifier: Apache-2.0

//! Reserved keys the orchestrator owns inside `CommunicationInfo`.
//!
//! `CommunicationInfo` is otherwise an opaque app-defined string map — the
//! protocol never inspects keys or values *except* for entries under the
//! `derec.*` namespace, which are reserved for the library. Apps SHOULD NOT
//! use this namespace; if they do, the library silently overwrites/strips
//! those entries at the protocol boundary.

use crate::{Error, Result};

/// Reserved key carrying the sender's hex-encoded `replica_id` on
/// replica-mode `PairRequest` / `PairResponse` envelopes.
///
/// Auto-injected by the orchestrator on outbound replica pairings and
/// auto-extracted on inbound (populating `Channel.replica_id`). Validated
/// per-pairing-kind: replica pairings MUST carry it; non-replica pairings
/// MUST NOT (see
/// [`crate::primitives::pairing::PairingError::MissingReplicaId`] /
/// [`crate::primitives::pairing::PairingError::UnexpectedReplicaId`]).
pub const DEREC_REPLICA_ID_KEY: &str = "derec.replica_id";

/// Encode a `replica_id` for transmission inside `CommunicationInfo`.
///
/// Lowercase, unpadded hex. The receiver parses with
/// [`decode_replica_id`]; padding is cosmetic, not semantic.
pub fn encode_replica_id(id: u64) -> String {
    format!("{id:x}")
}

/// Decode a hex-encoded `replica_id` extracted from `CommunicationInfo`.
///
/// Accepts any number of hex digits up to a `u64` (so the encoder may pad
/// or not pad — both round-trip). Whitespace is **not** tolerated; trim at
/// the call site if needed.
pub fn decode_replica_id(s: &str) -> Result<u64> {
    u64::from_str_radix(s, 16).map_err(|_| {
        Error::InvalidInput("CommunicationInfo `derec.replica_id` is not valid hex u64")
    })
}
