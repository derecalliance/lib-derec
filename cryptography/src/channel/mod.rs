// SPDX-License-Identifier: Apache-2.0

//! This module provides cryptographic primitives for encrypting and decrypting messages
//! given a (shared) symmetric key using AES-256-GCM authenticated encryption.

use aes::cipher::KeyInit;
use aes_gcm::{Aes256Gcm, Key, Nonce, aead::Aead};

/// Custom error type for Derec channel encryption and decryption operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DerecChannelError {
    #[error("encryption failed: {0:?}")]
    EncryptionError(aead::Error),

    #[error("decryption failed: {0:?}")]
    DecryptionError(aead::Error),

    #[error("ciphertext too short (need at least 12 bytes for nonce prefix, got {got})")]
    CiphertextTooShort { got: usize },
}

/// Encrypts a message using AES-256-GCM authenticated encryption.
///
/// # Arguments
///
/// * `msg` - The plaintext message to encrypt as a byte slice.
/// * `key` - A 32-byte array representing the AES-256 encryption key.
/// * `nonce` - A 32-byte array used as the nonce; only the first 12 bytes are used for AES-GCM.
///
/// # Returns
///
/// Returns a `Result` containing the ciphertext as a `Vec<u8>` on success. The ciphertext
/// consists of the 12-byte nonce prefix followed by the encrypted message and authentication tag.
/// Returns an error if encryption fails.
///
/// # Example
///
/// ```
/// use derec_cryptography::channel::encrypt_message;
/// let msg = b"hello world";
/// let key = [0u8; 32];
/// let nonce = [0u8; 32];
/// let ciphertext = encrypt_message(msg, &key, &nonce).unwrap();
/// ```
pub fn encrypt_message(
    msg: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<Vec<u8>, DerecChannelError> {
    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(key);

    let e = cipher
        .encrypt(Nonce::from_slice(&nonce[0..12]), msg)
        .map_err(DerecChannelError::EncryptionError)?;

    let mut ctxt = Vec::new();
    ctxt.extend_from_slice(&nonce[0..12]);
    ctxt.extend_from_slice(&e);
    Ok(ctxt)
}

/// Decrypts a message encrypted with AES-256-GCM authenticated encryption.
///
/// # Arguments
///
/// * `ctxt` - The ciphertext as a byte slice. The first 12 bytes are expected to be the nonce,
///   followed by the encrypted message and authentication tag.
/// * `key` - A 32-byte array representing the AES-256 decryption key.
///
/// # Returns
///
/// Returns a `Result` containing the decrypted plaintext as a `Vec<u8>` on success.
/// Returns an error if decryption fails or authentication does not pass.
///
/// # Example
///
/// ```
/// use derec_cryptography::channel::{encrypt_message, decrypt_message};
/// let msg = b"hello world";
/// let key = [0u8; 32];
/// let nonce = [0u8; 32];
/// let ciphertext = encrypt_message(msg, &key, &nonce).unwrap();
/// let plaintext = decrypt_message(&ciphertext, &key).unwrap();
/// assert_eq!(plaintext, msg);
/// ```
pub fn decrypt_message(ctxt: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, DerecChannelError> {
    if ctxt.len() < 12 {
        return Err(DerecChannelError::CiphertextTooShort { got: ctxt.len() });
    }

    let key: &Key<Aes256Gcm> = key.into();
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(Nonce::from_slice(&ctxt[0..12]), &ctxt[12..])
        .map_err(DerecChannelError::DecryptionError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let msg = b"hello derec";
        let key = [0u8; 32];
        let nonce = [0u8; 32];

        // let alice sign-then-encrypt the message for bob
        let ctxt = encrypt_message(msg, &key, &nonce).unwrap();

        // let bob decrypt-then-verify the message from alice
        let received = decrypt_message(&ctxt, &key).unwrap();

        assert_eq!(received, msg);
    }
}
