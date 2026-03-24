//! Cryptographic encryption primitives for DeRec message protection.
//!
//! This module provides ECIES-style hybrid encryption using:
//!
//! - secp256k1 ECDH (via `pairing_ecies`)
//! - AES-256-GCM (via `channel`)
//!
//! # Purpose
//!
//! In the DeRec protocol, messages are:
//!
//! 1. Built as a `DeRecMessage`
//! 2. Signed by the sender
//! 3. **Encrypted for the recipient**
//! 4. Sent over the wire
//!
//! This module implements step (3): **public-key encryption of message payloads**.
//!
//! # Design
//!
//! The encryption scheme follows a standard ECIES pattern:
//!
//! ## Encryption
//!
//! 1. Generate ephemeral keypair `(esk, epk)`
//! 2. Derive shared key using ECDH:
//!    ```text
//!    shared_key = ECDH(esk, receiver_public_key)
//!    ```
//! 3. Encrypt payload using AES-256-GCM
//! 4. Output:
//!
//! ```text
//! [u32 epk_len][epk_bytes][ciphertext]
//! ```
//!
//! ## Decryption
//!
//! 1. Extract `epk`
//! 2. Derive shared key:
//!    ```text
//!    shared_key = ECDH(receiver_secret_key, epk)
//!    ```
//! 3. Decrypt ciphertext
//!
//! # Responsibilities
//!
//! This module:
//!
//! - encrypts arbitrary bytes to a recipient public key
//! - decrypts ciphertext using a recipient secret key
//!
//! This module does **not**:
//!
//! - know about `DeRecMessage`
//! - perform signing
//! - enforce protocol semantics
//!
//! # Security properties
//!
//! - Confidentiality via AES-256-GCM
//! - Integrity via GCM authentication tag
//! - Forward secrecy via ephemeral keys
//!
//! # Usage
//!
//! ```rust
//! use derec_cryptography::envelope::encryption;
//!
//! let ciphertext = encryption::encrypt(&plaintext, &receiver_pk)?;
//! let plaintext = encryption::decrypt(&ciphertext, &receiver_sk)?;
//! ```

use rand::rngs::OsRng;
use thiserror::Error;

use crate::channel;
use crate::pairing::pairing_ecies;

/// Length of nonce used for AES-GCM (we reuse 32 bytes but only first 12 are used)
const NONCE_SIZE: usize = 32;

#[derive(Debug, Error)]
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

/// Encrypts a payload to a recipient public key using ECIES.
///
/// Output format:
///
/// ```text
/// [u32 epk_len][epk_bytes][ciphertext]
/// ```
///
/// # Arguments
///
/// * `plaintext` - Message bytes to encrypt
/// * `public_key` - Recipient secp256k1 public key (SEC1 encoding)
///
/// # Returns
///
/// Encrypted bytes including ephemeral public key and ciphertext.
///
/// # Errors
///
/// Returns [`DerecEncryptionError`] if:
///
/// - key is invalid
/// - encryption fails
///
/// # Example
///
/// ```rust
/// use derec_cryptography::envelope::encryption;
///
/// let ciphertext = encryption::encrypt(b"hello", &receiver_pk).unwrap();
/// ```
pub fn encrypt(bytes: &[u8], public_key: &[u8]) -> Result<Vec<u8>, DerecEncryptionError> {
    if public_key.is_empty() {
        return Err(DerecEncryptionError::InvalidPublicKey);
    }

    // 1. Generate ephemeral keypair
    let (esk, epk) = pairing_ecies::generate_key(&mut OsRng)
        .map_err(|_| DerecEncryptionError::EncryptionFailed)?;

    // 2. Derive shared key
    let shared = pairing_ecies::derive_shared_key(&esk, public_key)
        .map_err(|_| DerecEncryptionError::EncryptionFailed)?;

    // 3. Encrypt using AES-GCM
    let nonce = rand::random::<[u8; NONCE_SIZE]>();

    let ciphertext = channel::encrypt_message(bytes, &shared, &nonce)
        .map_err(|_| DerecEncryptionError::EncryptionFailed)?;

    // 4. Build output
    let mut out = Vec::with_capacity(4 + epk.len() + ciphertext.len());

    let epk_len = epk.len() as u32;
    out.extend_from_slice(&epk_len.to_le_bytes());
    out.extend_from_slice(&epk);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Decrypts a ciphertext produced by [`encrypt`].
///
/// Expected format:
///
/// ```text
/// [u32 epk_len][epk_bytes][ciphertext]
/// ```
///
/// # Arguments
///
/// * `ciphertext` - Encrypted message
/// * `secret_key` - Recipient secp256k1 private key
///
/// # Returns
///
/// Decrypted plaintext bytes.
///
/// # Errors
///
/// Returns [`DerecEncryptionError`] if:
///
/// - format is invalid
/// - key is invalid
/// - authentication fails
///
/// # Example
///
/// ```rust
/// use derec_cryptography::envelope::encryption;
///
/// let plaintext = encryption::decrypt(&ciphertext, &receiver_sk).unwrap();
/// ```
pub fn decrypt(ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, DerecEncryptionError> {
    if ciphertext.len() < 4 {
        return Err(DerecEncryptionError::InvalidFormat);
    }

    // Read epk length
    let epk_len = u32::from_le_bytes(
        ciphertext[0..4]
            .try_into()
            .map_err(|_| DerecEncryptionError::InvalidFormat)?,
    ) as usize;

    if ciphertext.len() < 4 + epk_len {
        return Err(DerecEncryptionError::InvalidFormat);
    }

    let epk = &ciphertext[4..4 + epk_len];
    let encrypted = &ciphertext[4 + epk_len..];

    // Derive shared key
    let shared = pairing_ecies::derive_shared_key(secret_key, epk)
        .map_err(|_| DerecEncryptionError::DecryptionFailed)?;

    // Decrypt
    let plaintext = channel::decrypt_message(encrypted, &shared)
        .map_err(|_| DerecEncryptionError::DecryptionFailed)?;

    Ok(plaintext)
}
