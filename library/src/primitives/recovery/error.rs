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

    /// VSS reconstruction succeeded but the resulting bytes were not the
    /// canonical `DeRecSecret` envelope, or its `secret_data` was not a
    /// valid encoded secret. The shares almost certainly came from a
    /// corrupted source — the math reconstructed *something*, just not a
    /// shape the protocol can interpret.
    #[error(
        "recovered bytes were not a valid DeRecSecret envelope / encoded secret \
         — share corruption likely"
    )]
    MalformedRecoveredSecret {
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}
