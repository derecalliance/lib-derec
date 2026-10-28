// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Errors of the pairing module's primitives.

/// Failure of the pairing protocol and its ML-KEM and ECIES primitives.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DerecPairingError {
    #[error("serialization error: {0:?}")]
    SerializationError(ark_serialize::SerializationError),

    #[error("ml-kem encapsulation failed")]
    MLKemEncapsulationError,

    #[error("invalid input size: expected {expected} bytes, got {got}")]
    InvalidSize { expected: usize, got: usize },

    #[error("fingerprint nonce does not open the initiator's commitment")]
    FingerprintCommitmentMismatch,
}

/// Failure of the ECIES pairing envelope ([`encrypt`](super::envelope::encrypt) and
/// [`decrypt`](super::envelope::decrypt)).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DerecEncryptionError {
    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("invalid ciphertext format")]
    InvalidFormat,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("decryption failed")]
    DecryptionFailed,
}
