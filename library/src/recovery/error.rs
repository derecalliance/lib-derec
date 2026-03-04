// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RecoveryError {
    #[error("secret_id is empty")]
    EmptySecretId,

    #[error("share version must be >= 0 (got={version})")]
    InvalidVersion { version: i32 },

    #[error("no share responses provided")]
    EmptyResponses,

    #[error("share response does not contain a result")]
    MissingResult,

    #[error("share response indicates an error status (status={status})")]
    NonOkStatus { status: i32 },

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
    VersionMismatch { expected: i32, got: i32 },

    #[error("failed to reconstruct secret from shares")]
    ReconstructionFailed {
        #[source]
        source: derec_cryptography::vss::DerecVSSError,
    },
}
