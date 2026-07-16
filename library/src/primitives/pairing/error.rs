// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PairingError {
    #[error("transport_uri is empty")]
    EmptyTransportUri,

    #[error("invalid contact message: {0}")]
    InvalidContactMessage(&'static str),

    #[error("invalid pairing request message: {0}")]
    InvalidPairRequestMessage(&'static str),

    #[error("invalid pairing response message: {0}")]
    InvalidPairResponseMessage(&'static str),

    #[error("pairing response indicates a non-OK status (status={status}): {memo}")]
    NonOkStatus { status: i32, memo: String },

    #[error("pairing protocol violation: {0}")]
    ProtocolViolation(&'static str),

    #[error("contact binding hash mismatch: published keys do not match the contact commitment")]
    PrePairHashMismatch,

    #[error(
        "replica-mode pairing (sender_kind={sender_kind:?}) missing the reserved `derec.replica_id` key"
    )]
    MissingReplicaId {
        sender_kind: derec_proto::SenderKind,
    },

    #[error(
        "non-replica pairing (sender_kind={sender_kind:?}) carries the reserved `derec.replica_id` key"
    )]
    UnexpectedReplicaId {
        sender_kind: derec_proto::SenderKind,
    },

    /// The peer's advertised [`ParameterRange`](derec_proto::ParameterRange)
    /// does not overlap the local one on `field`. `local` and `peer` are
    /// the offending `(min, max)` pair so the application can render a
    /// useful diagnostic.
    #[error(
        "incompatible parameter range on `{field}`: local=[{local_min}, {local_max}], peer=[{peer_min}, {peer_max}]"
    )]
    IncompatibleParameterRange {
        field: &'static str,
        local_min: i64,
        local_max: i64,
        peer_min: i64,
        peer_max: i64,
    },

    #[error("internal invariant violated: {0}")]
    Invariant(&'static str),

    #[error("failed to generate contact message key material")]
    ContactMessageKeygen {
        #[source]
        source: derec_cryptography::pairing::DerecPairingError,
    },

    #[error("failed to generate pairing request key material")]
    PairRequestKeygen {
        #[source]
        source: derec_cryptography::pairing::DerecPairingError,
    },

    #[error("failed to finalize pairing (initiator side)")]
    FinishPairingInitiator {
        #[source]
        source: derec_cryptography::pairing::DerecPairingError,
    },

    #[error("failed to finalize pairing (responder side)")]
    FinishPairingResponder {
        #[source]
        source: derec_cryptography::pairing::DerecPairingError,
    },

    #[error(transparent)]
    PairingEncryption(#[from] derec_cryptography::pairing::envelope::DerecEncryptionError),
}
