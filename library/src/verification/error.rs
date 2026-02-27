// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("verification response missing result")]
    MissingResult,

    #[error("verification response indicates failure (status={status})")]
    NonOkStatus { status: i32 },

    #[error("nonce mismatch")]
    NonceMismatch,

    #[error("version mismatch (expected={expected}, got={got})")]
    VersionMismatch { expected: i32, got: i32 },

    #[error("hash mismatch")]
    HashMismatch,

    #[error("internal invariant violated: {0}")]
    Invariant(&'static str),
}
