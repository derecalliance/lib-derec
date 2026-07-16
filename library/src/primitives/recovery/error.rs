// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecoveryError {
    #[error("no share responses provided")]
    EmptyResponses,

    #[error("share response indicates a non-OK status (status={status}): {memo}")]
    NonOkStatus { status: i32, memo: String },

    #[error("committed_de_rec_share is empty")]
    EmptyCommittedDeRecShare,

    #[error("failed to decode CommittedDeRecShare")]
    DecodeCommittedDeRecShare {
        #[source]
        source: prost::DecodeError,
    },

    #[error("failed to decode DeRecShare")]
    DecodeDeRecShare {
        #[source]
        source: prost::DecodeError,
    },

    #[error("secret_id mismatch in share response")]
    SecretIdMismatch,

    #[error("share version mismatch in share response (expected={expected}, got={got})")]
    VersionMismatch { expected: u32, got: u32 },

    #[error("failed to reconstruct secret from shares")]
    ReconstructionFailed {
        #[source]
        source: derec_cryptography::vss::DerecVSSError,
    },

    /// VSS reconstruction succeeded but the resulting bytes did not
    /// decode as the canonical `DeRecSecret` / `Secret` protobuf
    /// wrapping the library applies on `start(ProtectSecret)`. The
    /// shares almost certainly came from a corrupted source (a buggy
    /// helper, a tampered store) — the math reconstructed *something*,
    /// just not a protobuf the protocol can interpret.
    #[error(
        "recovered bytes did not decode as the canonical DeRecSecret/Secret \
         protobuf — share corruption likely"
    )]
    MalformedRecoveredSecret {
        #[source]
        source: prost::DecodeError,
    },
}
