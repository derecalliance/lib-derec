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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_replica_id_is_unpadded_lowercase_hex() {
        assert_eq!(encode_replica_id(0xcafe), "cafe");
        assert_eq!(encode_replica_id(0), "0");
        assert_eq!(encode_replica_id(u64::MAX), "ffffffffffffffff");
    }

    /// 5.6 — A peer that pads the hex string before sending (e.g.
    /// `"00000000cafe"`) must still decode to the same `u64` as the
    /// unpadded form. `encode_replica_id` does not pad; `decode_replica_id`
    /// is lenient, and this invariant has to hold so two peers using
    /// different conventions interoperate.
    #[test]
    fn decode_replica_id_accepts_padded_input() {
        let id = 0xcafe_u64;
        // Round-trip the canonical encoder.
        assert_eq!(decode_replica_id(&encode_replica_id(id)).unwrap(), id);
        // A peer that pads with leading zeros must still decode cleanly.
        for padded in ["00cafe", "0000cafe", "00000000cafe", "000000000000cafe"] {
            assert_eq!(
                decode_replica_id(padded).unwrap(),
                id,
                "padded input {padded:?} must decode to the same id",
            );
        }
        // u64::MAX padded to 16 hex chars stays u64::MAX.
        assert_eq!(decode_replica_id("ffffffffffffffff").unwrap(), u64::MAX);
        // Zero in either form.
        assert_eq!(decode_replica_id("0").unwrap(), 0);
        assert_eq!(decode_replica_id("0000000000000000").unwrap(), 0);
    }

    #[test]
    fn decode_replica_id_rejects_invalid_input() {
        // Out of u64 range — 17 chars of 'f' is one bit past u64::MAX.
        assert!(decode_replica_id("fffffffffffffffff").is_err());
        // Non-hex characters.
        assert!(decode_replica_id("g").is_err());
        assert!(decode_replica_id("0x123").is_err());
        // Whitespace explicitly not tolerated per the docs.
        assert!(decode_replica_id(" cafe").is_err());
        assert!(decode_replica_id("cafe ").is_err());
        // Empty string.
        assert!(decode_replica_id("").is_err());
    }
}
