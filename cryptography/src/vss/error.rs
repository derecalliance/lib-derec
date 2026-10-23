// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Errors of verifiable secret sharing.

/// Custom error type for Verifiable Secret Sharing (VSS) operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DerecVSSError {
    #[error("inconsistent ciphertexts")]
    InconsistentCiphertexts,

    #[error("inconsistent commitments")]
    InconsistentCommitments,

    #[error("one or more shares are corrupted")]
    CorruptShares,

    #[error("insufficient shares")]
    InsufficientShares,

    #[error("decryption failed")]
    DecryptionFailure,

    #[error("encryption failed")]
    EncryptionFailure,

    #[error("invalid access structure")]
    InvalidAccessStructure,
}
