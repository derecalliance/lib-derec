// SPDX-License-Identifier: Apache-2.0

//! Reserved keys the orchestrator owns inside `CommunicationInfo`.
//!
//! `CommunicationInfo` is otherwise an opaque app-defined string map — the
//! protocol never inspects keys or values *except* for entries under the
//! `derec.*` namespace, which are reserved for the library. Apps SHOULD NOT
//! use this namespace; if they do, the library silently overwrites/strips
//! those entries at the protocol boundary.

use crate::{Error, Result};

/// Reserved key carrying the sender's decimal-encoded `replica_id` on
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
/// Decimal string, matching the convention used by `channel_id` and
/// `secret_id` across the SDK boundary so callers never have to track
/// which id type uses which encoding.
pub fn encode_replica_id(id: u64) -> String {
    id.to_string()
}

/// Decode a decimal-encoded `replica_id` extracted from
/// `CommunicationInfo`. Whitespace is **not** tolerated; trim at the
/// call site if needed.
pub fn decode_replica_id(s: &str) -> Result<u64> {
    s.parse::<u64>().map_err(|_| {
        Error::InvalidInput("CommunicationInfo `derec.replica_id` is not valid decimal u64")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_replica_id_is_decimal() {
        assert_eq!(encode_replica_id(51966), "51966");
        assert_eq!(encode_replica_id(0), "0");
        assert_eq!(encode_replica_id(u64::MAX), "18446744073709551615");
    }

    #[test]
    fn decode_replica_id_round_trips_decimal() {
        for id in [0_u64, 1, 42, 51966, u64::MAX] {
            assert_eq!(decode_replica_id(&encode_replica_id(id)).unwrap(), id);
        }
    }

    #[test]
    fn decode_replica_id_rejects_invalid_input() {
        // Out of u64 range.
        assert!(decode_replica_id("18446744073709551616").is_err());
        // Hex form is rejected — the boundary is decimal-only.
        assert!(decode_replica_id("cafe").is_err());
        assert!(decode_replica_id("0xcafe").is_err());
        // Non-digit characters.
        assert!(decode_replica_id("g").is_err());
        assert!(decode_replica_id("-1").is_err());
        // Whitespace explicitly not tolerated per the docs.
        assert!(decode_replica_id(" 42").is_err());
        assert!(decode_replica_id("42 ").is_err());
        // Empty string.
        assert!(decode_replica_id("").is_err());
    }
}
