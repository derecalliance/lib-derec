// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::derec_message::current_timestamp;
use crate::primitives::pairing::PairingError;
use crate::types::ChannelId;
use derec_cryptography::pairing::PairingContactMessageMaterial;
use derec_proto::{ContactMessage, ContactMode, SenderKind, TransportProtocol};
use rand::{Rng, rng};
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub(crate) fn generate_seed<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut entropy = Zeroizing::new([0u8; N]);
    let mut rng = rng();
    rng.fill_bytes(&mut *entropy);
    entropy
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Binding check between an outer DeRec envelope timestamp and the
/// inner request/response timestamp.
///
/// # Security
///
/// Both timestamps MUST be present **and** equal. A naive
/// `Option<T> == Option<T>` comparison would accept `(None, None)`
/// as a match (because `Option::PartialEq` returns `true` for
/// `None == None`), which lets a peer strip both timestamp fields
/// and silently bypass this binding. Proto3 makes every message
/// field optional on the wire, so this is reachable for any
/// remote peer.
///
/// Treat absence as a failure here. The remaining anti-replay
/// concerns (freshness window, per-channel monotonic nonce log) are
/// the application/protocol layer's responsibility — see the
/// per-primitive `# Security: no freshness or replay protection`
/// notes on each `extract` function for the full discussion.
pub(crate) fn verify_timestamps(
    envelope_timestamp: Option<prost_types::Timestamp>,
    timestamp: Option<prost_types::Timestamp>,
) -> Result<(), crate::Error> {
    match (envelope_timestamp, timestamp) {
        (Some(envelope_ts), Some(inner_ts)) if envelope_ts == inner_ts => Ok(()),
        (None, None) => {
            #[cfg(feature = "logging")]
            tracing::warn!(
                "timestamp invariant violated: both envelope and inner timestamp absent"
            );

            Err(crate::Error::Invariant(
                "Envelope and request/response timestamps are both absent; absence cannot be used to satisfy the binding check",
            ))
        }
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("timestamp invariant violated");

            Err(crate::Error::Invariant(
                "Envelope timestamp does not match request/response timestamp",
            ))
        }
    }
}

/// Extension trait that attaches structural validation as a method on
/// the proto [`ContactMessage`].
///
/// The proto type lives in [`derec_proto`], so an inherent `impl` is
/// impossible from this crate — this trait sidesteps the orphan rule
/// the same way [`crate::transport::TransportProtocolExt`] does for
/// [`derec_proto::TransportProtocol`]. Bring the trait into scope
/// (`use crate::utils::ContactMessageExt as _;`) at every parse
/// boundary that ingests an untrusted `ContactMessage` and call
/// `contact.validate()?` before handing it to protocol code.
pub(crate) trait ContactMessageExt {
    /// Structural validator for a decoded [`ContactMessage`]. Enforces
    /// the per-mode field-presence invariants the proto schema
    /// documents but cannot itself express:
    ///
    /// - The declared `contact_mode` must be a known [`ContactMode`]
    ///   value.
    /// - [`ContactMode::InlineKeys`]: `mlkem_encapsulation_key` and
    ///   `ecies_public_key` MUST be present and non-empty;
    ///   `contact_binding_hash` MUST be absent (would mean the contact
    ///   is misshaped — keys present AND a commitment).
    /// - [`ContactMode::HashedKeys`]: both inline-key fields MUST be
    ///   absent, and `contact_binding_hash` MUST be present with
    ///   exactly 48 bytes (SHA-384 digest size).
    /// - [`ContactMode::NoKeys`]: all three of
    ///   `mlkem_encapsulation_key`, `ecies_public_key`, and
    ///   `contact_binding_hash` MUST be absent. The contact carries
    ///   only `channel_id`, `nonce`, and `transport_protocol`; any
    ///   key-shaped field on a NoKeys contact is a protocol misuse.
    ///
    /// The bidirectional check matters most for `HashedKeys` and
    /// `NoKeys`: a malformed `HashedKeys` contact that carried inline
    /// keys could have its keys consumed downstream without the
    /// binding-hash recomputation that gives the mode its MITM
    /// resistance; a malformed `NoKeys` contact that carried
    /// unauthenticated key material would silently upgrade the flow to
    /// a mode the OOB channel wasn't trusted for.
    fn validate(&self) -> Result<(), crate::Error>;

    /// Returns `true` when this contact's mode requires a `PrePairRequest`
    /// round-trip before the responder can produce a `PairRequestMessage`.
    ///
    /// - [`ContactMode::HashedKeys`] and [`ContactMode::NoKeys`] return
    ///   `true` — both require the responder to fetch key material via
    ///   `PrePair` before the encrypted pairing handshake can begin.
    /// - [`ContactMode::InlineKeys`] returns `false` — the keys are
    ///   already carried in the contact itself.
    /// - Unknown enum values return `false`; downstream validation
    ///   (e.g. [`Self::validate`]) is responsible for rejecting them.
    fn requires_pre_pair(&self) -> bool;

    /// Build a [`ContactMode::InlineKeys`] [`ContactMessage`] carrying
    /// the given ML-KEM + ECIES public key material verbatim.
    ///
    /// Timestamp is stamped with the current wall-clock; callers that
    /// need deterministic timestamps must construct the proto struct
    /// directly.
    fn inline_keys(
        channel_id: ChannelId,
        nonce: u64,
        transport_protocol: TransportProtocol,
        pk: PairingContactMessageMaterial,
    ) -> ContactMessage;

    /// Build a [`ContactMode::HashedKeys`] [`ContactMessage`]: no key
    /// material inlined, but a SHA-384 commitment (`contact_binding_hash`)
    /// over `(mlkem_encapsulation_key || ecies_public_key || u64_be(nonce)
    /// || u64_be(channel_id))` so the scanner can verify keys received
    /// later via `PrePair` against the commitment.
    ///
    /// Timestamp is stamped with the current wall-clock.
    fn hashed_keys(
        channel_id: ChannelId,
        nonce: u64,
        transport_protocol: TransportProtocol,
        pk: &PairingContactMessageMaterial,
    ) -> ContactMessage;

    /// Build a [`ContactMode::NoKeys`] [`ContactMessage`]: no key
    /// material and no commitment — only `channel_id`, `nonce`, and
    /// `transport_protocol`. The contact creator generates key material
    /// on the fly when the corresponding `PrePairRequest` arrives; the
    /// scanner accepts the returned keys without cryptographic
    /// verification.
    ///
    /// Trust rests entirely on the out-of-band delivery channel being
    /// fully trusted. Applications MUST rate-limit inbound
    /// `PrePairRequest`s per channel and expire outstanding NoKeys
    /// contacts on a short timer.
    ///
    /// Timestamp is stamped with the current wall-clock.
    fn no_keys(
        channel_id: ChannelId,
        nonce: u64,
        transport_protocol: TransportProtocol,
    ) -> ContactMessage;
}

impl ContactMessageExt for ContactMessage {
    fn validate(&self) -> Result<(), crate::Error> {
        let mode = ContactMode::try_from(self.contact_mode).map_err(|_| {
            #[cfg(feature = "logging")]
            tracing::warn!(
                contact_mode = self.contact_mode,
                "unknown contact_mode value"
            );
            PairingError::InvalidContactMessage("unknown contact_mode value")
        })?;

        let mlkem_present = self
            .mlkem_encapsulation_key
            .as_ref()
            .is_some_and(|v| !v.is_empty());
        let ecies_present = self
            .ecies_public_key
            .as_ref()
            .is_some_and(|v| !v.is_empty());
        let hash_present = self
            .contact_binding_hash
            .as_ref()
            .is_some_and(|v| !v.is_empty());

        match mode {
            ContactMode::InlineKeys => {
                if !mlkem_present {
                    return Err(PairingError::InvalidContactMessage(
                        "inline_keys contact missing mlkem_encapsulation_key",
                    )
                    .into());
                }
                if !ecies_present {
                    return Err(PairingError::InvalidContactMessage(
                        "inline_keys contact missing ecies_public_key",
                    )
                    .into());
                }
                if hash_present {
                    return Err(PairingError::InvalidContactMessage(
                        "inline_keys contact must not carry contact_binding_hash",
                    )
                    .into());
                }
            }
            ContactMode::HashedKeys => {
                if mlkem_present || ecies_present {
                    return Err(PairingError::InvalidContactMessage(
                        "hashed_keys contact must not carry inline keys",
                    )
                    .into());
                }
                const BINDING_HASH_LEN: usize = 48;
                let hash = self.contact_binding_hash.as_ref().ok_or(
                    PairingError::InvalidContactMessage(
                        "hashed_keys contact missing contact_binding_hash",
                    ),
                )?;
                if hash.is_empty() {
                    return Err(PairingError::InvalidContactMessage(
                        "hashed_keys contact missing contact_binding_hash",
                    )
                    .into());
                }
                if hash.len() != BINDING_HASH_LEN {
                    return Err(PairingError::InvalidContactMessage(
                        "hashed_keys contact_binding_hash is not a SHA-384 digest",
                    )
                    .into());
                }
            }
            ContactMode::NoKeys => {
                if mlkem_present || ecies_present {
                    return Err(PairingError::InvalidContactMessage(
                        "no_keys contact must not carry inline keys",
                    )
                    .into());
                }
                if hash_present {
                    return Err(PairingError::InvalidContactMessage(
                        "no_keys contact must not carry contact_binding_hash",
                    )
                    .into());
                }
            }
        }

        Ok(())
    }

    fn requires_pre_pair(&self) -> bool {
        self.contact_mode == ContactMode::HashedKeys as i32
            || self.contact_mode == ContactMode::NoKeys as i32
    }

    fn inline_keys(
        channel_id: ChannelId,
        nonce: u64,
        transport_protocol: TransportProtocol,
        pk: PairingContactMessageMaterial,
    ) -> ContactMessage {
        ContactMessage {
            channel_id: channel_id.into(),
            transport_protocol: Some(transport_protocol),
            contact_mode: ContactMode::InlineKeys as i32,
            mlkem_encapsulation_key: Some(pk.mlkem_encapsulation_key),
            ecies_public_key: Some(pk.ecies_public_key),
            contact_binding_hash: None,
            nonce,
            timestamp: Some(current_timestamp()),
        }
    }

    fn hashed_keys(
        channel_id: ChannelId,
        nonce: u64,
        transport_protocol: TransportProtocol,
        pk: &PairingContactMessageMaterial,
    ) -> ContactMessage {
        let binding_hash = derec_cryptography::pairing::contact_binding_hash(
            &pk.mlkem_encapsulation_key,
            &pk.ecies_public_key,
            nonce,
            channel_id.into(),
        );

        ContactMessage {
            channel_id: channel_id.into(),
            transport_protocol: Some(transport_protocol),
            contact_mode: ContactMode::HashedKeys as i32,
            mlkem_encapsulation_key: None,
            ecies_public_key: None,
            contact_binding_hash: Some(binding_hash.to_vec()),
            nonce,
            timestamp: Some(current_timestamp()),
        }
    }

    fn no_keys(
        channel_id: ChannelId,
        nonce: u64,
        transport_protocol: TransportProtocol,
    ) -> ContactMessage {
        ContactMessage {
            channel_id: channel_id.into(),
            transport_protocol: Some(transport_protocol),
            contact_mode: ContactMode::NoKeys as i32,
            mlkem_encapsulation_key: None,
            ecies_public_key: None,
            contact_binding_hash: None,
            nonce,
            timestamp: Some(current_timestamp()),
        }
    }
}

/// Extension trait that attaches pairing-role helpers as methods on the
/// proto [`SenderKind`].
///
/// Sidesteps the orphan rule the same way [`ContactMessageExt`] does for
/// [`ContactMessage`] and [`crate::transport::TransportProtocolExt`] does
/// for [`derec_proto::TransportProtocol`].
pub(crate) trait SenderKindExt {
    /// Derive the peer's pairing kind from the local kind, following the
    /// pair-completion role-inversion rule:
    ///
    /// | local                 | peer                  |
    /// |-----------------------|-----------------------|
    /// | `Owner`               | `Helper`              |
    /// | `Helper`              | `Owner`               |
    /// | `ReplicaSource`       | `ReplicaDestination`  |
    /// | `ReplicaDestination`  | `ReplicaSource`       |
    ///
    /// [`PairResponseMessage`] does not carry `sender_kind` over the wire,
    /// so the initiator must look up its own role on the channel record
    /// (committed at pairing-start time) and invert it via this helper.
    ///
    /// [`PairResponseMessage`]: derec_proto::PairResponseMessage
    fn derive_peer(&self) -> SenderKind;

    /// Returns `true` for either replica-mode `SenderKind`
    /// ([`SenderKind::ReplicaSource`] or [`SenderKind::ReplicaDestination`]).
    ///
    /// Centralises the "is this any kind of replica?" check needed at
    /// several handler seams (channel-status assignment,
    /// `replica_id` gating, communication-info validation).
    fn is_replica(&self) -> bool;
}

impl SenderKindExt for SenderKind {
    fn derive_peer(&self) -> SenderKind {
        match self {
            SenderKind::Owner => SenderKind::Helper,
            SenderKind::Helper => SenderKind::Owner,
            SenderKind::ReplicaSource => SenderKind::ReplicaDestination,
            SenderKind::ReplicaDestination => SenderKind::ReplicaSource,
        }
    }

    fn is_replica(&self) -> bool {
        matches!(
            self,
            SenderKind::ReplicaSource | SenderKind::ReplicaDestination
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use derec_proto::{Protocol, TransportProtocol};
    use prost_types::Timestamp;

    fn ts(seconds: i64) -> Timestamp {
        Timestamp { seconds, nanos: 0 }
    }

    fn well_formed_inline_keys_contact() -> ContactMessage {
        ContactMessage {
            channel_id: 42,
            transport_protocol: Some(TransportProtocol {
                uri: "https://relay.example/alice".to_owned(),
                protocol: Protocol::Https.into(),
            }),
            contact_mode: ContactMode::InlineKeys as i32,
            mlkem_encapsulation_key: Some(vec![1; 1184]),
            ecies_public_key: Some(vec![2; 33]),
            contact_binding_hash: None,
            nonce: 0xCAFE_BABE,
            timestamp: Some(ts(1_700_000_000)),
        }
    }

    fn well_formed_hashed_keys_contact() -> ContactMessage {
        ContactMessage {
            channel_id: 42,
            transport_protocol: Some(TransportProtocol {
                uri: "https://relay.example/alice/ephemeral".to_owned(),
                protocol: Protocol::Https.into(),
            }),
            contact_mode: ContactMode::HashedKeys as i32,
            mlkem_encapsulation_key: None,
            ecies_public_key: None,
            contact_binding_hash: Some(vec![0xAB; 48]),
            nonce: 0xDEAD_BEEF,
            timestamp: Some(ts(1_700_000_000)),
        }
    }

    fn well_formed_no_keys_contact() -> ContactMessage {
        ContactMessage {
            channel_id: 1234,
            transport_protocol: Some(TransportProtocol {
                uri: "https://institution.example/pair".to_owned(),
                protocol: Protocol::Https.into(),
            }),
            contact_mode: ContactMode::NoKeys as i32,
            mlkem_encapsulation_key: None,
            ecies_public_key: None,
            contact_binding_hash: None,
            nonce: 4321,
            timestamp: Some(ts(1_700_000_000)),
        }
    }

    fn assert_invalid_contact(result: Result<(), crate::Error>, expected: &'static str) {
        match result {
            Err(Error::Pairing(PairingError::InvalidContactMessage(m))) => {
                assert_eq!(m, expected, "wrong InvalidContactMessage payload")
            }
            other => panic!("expected InvalidContactMessage({expected:?}), got {other:?}"),
        }
    }

    #[test]
    fn accepts_matching_some_timestamps() {
        assert!(verify_timestamps(Some(ts(1_700_000_000)), Some(ts(1_700_000_000))).is_ok());
    }

    #[test]
    fn rejects_mismatched_some_timestamps() {
        let res = verify_timestamps(Some(ts(1_700_000_000)), Some(ts(1_700_000_001)));
        match res {
            Err(crate::Error::Invariant(msg)) => {
                assert!(msg.contains("does not match"), "msg: {msg}")
            }
            other => panic!("expected Invariant mismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_both_none() {
        let res = verify_timestamps(None, None);
        match res {
            Err(crate::Error::Invariant(msg)) => {
                assert!(
                    msg.contains("absent"),
                    "expected absence-specific message, got: {msg}"
                )
            }
            other => panic!("expected Invariant for (None, None), got {other:?}"),
        }
    }

    #[test]
    fn rejects_envelope_none() {
        let res = verify_timestamps(None, Some(ts(1_700_000_000)));
        assert!(matches!(res, Err(crate::Error::Invariant(_))));
    }

    #[test]
    fn rejects_inner_none() {
        let res = verify_timestamps(Some(ts(1_700_000_000)), None);
        assert!(matches!(res, Err(crate::Error::Invariant(_))));
    }

    #[test]
    fn validate_accepts_well_formed_inline_keys() {
        well_formed_inline_keys_contact()
            .validate()
            .expect("well-formed inline_keys must pass");
    }

    #[test]
    fn validate_accepts_well_formed_hashed_keys() {
        well_formed_hashed_keys_contact()
            .validate()
            .expect("well-formed hashed_keys must pass");
    }

    #[test]
    fn validate_accepts_well_formed_no_keys() {
        well_formed_no_keys_contact()
            .validate()
            .expect("well-formed no_keys must pass");
    }

    #[test]
    fn validate_rejects_unknown_contact_mode() {
        let mut c = well_formed_inline_keys_contact();
        c.contact_mode = 7;
        assert_invalid_contact(c.validate(), "unknown contact_mode value");
    }

    #[test]
    fn validate_rejects_inline_missing_mlkem_key() {
        let mut c = well_formed_inline_keys_contact();
        c.mlkem_encapsulation_key = None;
        assert_invalid_contact(
            c.validate(),
            "inline_keys contact missing mlkem_encapsulation_key",
        );
    }

    #[test]
    fn validate_rejects_inline_missing_ecies_key() {
        let mut c = well_formed_inline_keys_contact();
        c.ecies_public_key = None;
        assert_invalid_contact(c.validate(), "inline_keys contact missing ecies_public_key");
    }

    #[test]
    fn validate_rejects_inline_with_binding_hash() {
        let mut c = well_formed_inline_keys_contact();
        c.contact_binding_hash = Some(vec![0xCD; 48]);
        assert_invalid_contact(
            c.validate(),
            "inline_keys contact must not carry contact_binding_hash",
        );
    }

    #[test]
    fn validate_rejects_hashed_with_inline_keys() {
        let mut c = well_formed_hashed_keys_contact();
        c.mlkem_encapsulation_key = Some(vec![1; 1184]);
        assert_invalid_contact(
            c.validate(),
            "hashed_keys contact must not carry inline keys",
        );
    }

    #[test]
    fn validate_rejects_hashed_missing_binding_hash() {
        let mut c = well_formed_hashed_keys_contact();
        c.contact_binding_hash = None;
        assert_invalid_contact(
            c.validate(),
            "hashed_keys contact missing contact_binding_hash",
        );
    }

    #[test]
    fn validate_rejects_hashed_empty_binding_hash() {
        let mut c = well_formed_hashed_keys_contact();
        c.contact_binding_hash = Some(Vec::new());
        assert_invalid_contact(
            c.validate(),
            "hashed_keys contact missing contact_binding_hash",
        );
    }

    #[test]
    fn validate_rejects_hashed_wrong_hash_length() {
        let mut c = well_formed_hashed_keys_contact();
        c.contact_binding_hash = Some(vec![0xAB; 32]);
        assert_invalid_contact(
            c.validate(),
            "hashed_keys contact_binding_hash is not a SHA-384 digest",
        );
    }

    #[test]
    fn validate_rejects_no_keys_with_mlkem_key() {
        let mut c = well_formed_no_keys_contact();
        c.mlkem_encapsulation_key = Some(vec![1; 1184]);
        assert_invalid_contact(c.validate(), "no_keys contact must not carry inline keys");
    }

    #[test]
    fn validate_rejects_no_keys_with_ecies_key() {
        let mut c = well_formed_no_keys_contact();
        c.ecies_public_key = Some(vec![2; 33]);
        assert_invalid_contact(c.validate(), "no_keys contact must not carry inline keys");
    }

    #[test]
    fn validate_rejects_no_keys_with_binding_hash() {
        let mut c = well_formed_no_keys_contact();
        c.contact_binding_hash = Some(vec![0xAB; 48]);
        assert_invalid_contact(
            c.validate(),
            "no_keys contact must not carry contact_binding_hash",
        );
    }
}
