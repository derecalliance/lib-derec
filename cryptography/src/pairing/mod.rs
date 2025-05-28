// SPDX-License-Identifier: Apache-2.0

//! Cryptographic pairing module for Derec, providing secure key exchange mechanisms using ML-KEM and ECIES.
//!
//! This module defines the types and functions required to perform a two-party pairing protocol,
//! combining post-quantum (ML-KEM) and classical (ECIES) cryptography. The protocol enables two parties
//! to securely derive a shared 256-bit key using a combination of encapsulation/decapsulation and ECDH key exchange.
//!
//! # Modules
//! - `pairing_mlkem`: ML-KEM (Kyber) encapsulation/decapsulation primitives.
//! - `pairing_ecies`: ECIES (Elliptic Curve Integrated Encryption Scheme) primitives.
//!
//! # Error Handling
//! Defines `DerecPairingError` for error reporting throughout the pairing process.
//!
//! # Data Structures
//! - `PairingContactMessageMaterial`: Public material sent by the contactor (initiator).
//! - `PairingSecretKeyMaterial`: Secret material held by each party during the protocol.
//! - `PairingRequestMessageMaterial`: Public material sent by the requestor (responder).
//! - `PairingSharedKey`: The final 256-bit shared key derived by both parties.
//!
//! # Protocol Overview
//! 1. **Contact Message Generation**: The contactor generates a contact message and secret material.
//! 2. **Pairing Request Message**: The requestor uses the contact message to generate a request message and secret material.
//! 3. **Shared Key Derivation**: Both parties independently derive the shared key by xor-ing secrets from ML-KEM and ECIES.
//!
//! # Functions
//! - `contact_message`: Generates a contact message and secret key material for the contactor.
//! - `pairing_request_message`: Generates a pairing request message and secret key material for the requestor.
//! - `finish_pairing_requestor`: Used by the requestor to derive the shared key.
//! - `finish_pairing_contactor`: Used by the contactor to derive the shared key.
//!

use rand_chacha::rand_core::SeedableRng;

pub mod pairing_mlkem;
pub mod pairing_ecies;

/// Custom error type for Derec pairing operations.
#[derive(Debug)]
pub enum DerecPairingError {
    SerializationError(ark_serialize::SerializationError),
    MLKemEncapsulationError,
    MLKemDecapsulationError,
    PairingStateError,
}

pub struct PairingContactMessageMaterial {
    pub mlkem_encapsulation_key: Vec<u8>,
    pub ecies_public_key: Vec<u8>,
}

pub struct PairingSecretKeyMaterial {
    mlkem_decapsulation_key: Option<Vec<u8>>,
    mlkem_shared_secret: Option<[u8; 32]>,
    ecies_secret_key: Vec<u8>,
}

pub struct PairingRequestMessageMaterial {
    pub mlkem_ciphertext: Vec<u8>,
    pub ecies_public_key: Vec<u8>,
}

pub type PairingSharedKey = [u8; 32];

/// Generates a contact message and corresponding secret key material for the contactor (initiator) in the pairing protocol.
///
/// This function performs the following steps:
/// 1. Generates a fresh ML-KEM (Kyber) keypair for post-quantum encapsulation/decapsulation.
/// 2. Generates a fresh ECIES (Elliptic Curve Integrated Encryption Scheme) keypair for classical ECDH key exchange.
/// 3. Packages the public components into a `PairingContactMessageMaterial` to be sent to the responder.
/// 4. Returns the secret components as `PairingSecretKeyMaterial` to be retained by the contactor.
///
///
/// # Arguments
/// * `entropy` - A cryptographically secure random seed of length `λ` (32 bytes).
/// 
/// # Returns
/// - `Ok((PairingContactMessageMaterial, PairingSecretKeyMaterial))` on success, containing:
///     - The public contact message material to send to the responder.
///     - The secret key material to be kept by the contactor.
/// - `Err(DerecPairingError)` if key generation fails.
///
/// # Errors
/// Returns `DerecPairingError` if ECIES key generation fails.
///
/// # Example
/// ```rust
/// use derec_cryptography::pairing::*;
/// let (contact_msg, secret_keys) = contact_message([0u8; 32]).unwrap();
/// // Send `contact_msg` to the responder, keep `secret_keys` for later.
/// ```
pub fn contact_message(entropy: [u8; 32]) -> Result<(PairingContactMessageMaterial, PairingSecretKeyMaterial), DerecPairingError> {
    let mut csprng = rand_chacha::ChaCha8Rng::from_seed(entropy);
    let (dk, ek) = pairing_mlkem::generate_encapsulation_key(&mut csprng);
    let (sk, pk) = pairing_ecies::generate_key(&mut csprng)?;
    
    Ok((
        PairingContactMessageMaterial {
            mlkem_encapsulation_key: ek,
            ecies_public_key: pk,
        },
        PairingSecretKeyMaterial {
            mlkem_decapsulation_key: Some(dk),
            mlkem_shared_secret: None,
            ecies_secret_key: sk,
        }
    ))
}

/// Generates a pairing request message and corresponding secret key material for the requestor (responder) in the pairing protocol.
///
/// This function performs the following steps:
/// 1. Uses the received `PairingContactMessageMaterial` (from the contactor) to perform ML-KEM (Kyber) encapsulation,
///    producing a ciphertext and a shared secret.
/// 2. Generates a fresh ECIES (Elliptic Curve Integrated Encryption Scheme) keypair for classical ECDH key exchange.
/// 3. Packages the ML-KEM ciphertext and ECIES public key into a `PairingRequestMessageMaterial` to be sent back to the contactor.
/// 4. Returns the secret components as `PairingSecretKeyMaterial` to be retained by the requestor.
///
/// # Arguments
/// * `entropy` - A cryptographically secure random seed of length `λ` (32 bytes).
/// * `received` - The `PairingContactMessageMaterial` received from the contactor (initiator).
///
/// # Returns
/// - `Ok((PairingRequestMessageMaterial, PairingSecretKeyMaterial))` on success, containing:
///     - The public pairing request message material to send to the contactor.
///     - The secret key material to be kept by the requestor.
/// - `Err(DerecPairingError)` if encapsulation or key generation fails.
///
/// # Errors
/// Returns `DerecPairingError` if ML-KEM encapsulation or ECIES key generation fails.
///
/// # Example
/// ```rust
/// use derec_cryptography::pairing::*;
/// let (contact_msg, _) = contact_message([0u8; 32]).unwrap();
/// let (request_msg, secret_keys) = pairing_request_message([0u8; 32], &contact_msg).unwrap();
/// // Send `request_msg` to the contactor, keep `secret_keys` for later.
/// ```
pub fn pairing_request_message(
    entropy: [u8; 32],
    received: &PairingContactMessageMaterial
) -> Result<(PairingRequestMessageMaterial, PairingSecretKeyMaterial), DerecPairingError> {
    let mut csprng = rand_chacha::ChaCha8Rng::from_seed(entropy);

    let (ct, shared_key) = pairing_mlkem::encapsulate(&received.mlkem_encapsulation_key, &mut csprng)?;
    let (sk, pk) = pairing_ecies::generate_key(&mut csprng)?;

    Ok((
        PairingRequestMessageMaterial {
            mlkem_ciphertext: ct,
            ecies_public_key: pk,
        },
        PairingSecretKeyMaterial {
            mlkem_decapsulation_key: None,
            mlkem_shared_secret: Some(shared_key),
            ecies_secret_key: sk,
        },
    ))
}

/// Completes the pairing protocol for the requestor (responder) and derives the final shared 256-bit key.
///
/// This function is called by the requestor after generating their secret key material and receiving the
/// contact message from the contactor. It combines the post-quantum shared secret (from ML-KEM encapsulation)
/// and the classical ECDH shared secret (from ECIES) by XOR-ing them together to produce the final shared key.
///
/// # Arguments
/// * `secrets` - The `PairingSecretKeyMaterial` held by the requestor, containing the ML-KEM shared secret and ECIES secret key.
/// * `received` - The `PairingContactMessageMaterial` received from the contactor, containing the ECIES public key.
///
/// # Returns
/// - `Ok(PairingSharedKey)` containing the derived 256-bit shared key if successful.
/// - `Err(DerecPairingError)` if the required secrets are missing or key derivation fails.
///
/// # Errors
/// Returns `DerecPairingError::PairingStateError` if the ML-KEM shared secret is missing,
/// or propagates errors from ECIES shared key derivation.
///
/// # Example
/// ```rust
/// use derec_cryptography::pairing::*;
/// let (contact_msg, _) = contact_message([0u8; 32]).unwrap();
/// let (request_msg, secret_keys) = pairing_request_message([0u8; 32], &contact_msg).unwrap();
/// let shared_key = finish_pairing_requestor(&secret_keys, &contact_msg).unwrap();
/// ```
pub fn finish_pairing_requestor(
    secrets: &PairingSecretKeyMaterial,
    received: &PairingContactMessageMaterial
) -> Result<PairingSharedKey, DerecPairingError> {
    let mlkem_shared_key = secrets.mlkem_shared_secret.ok_or(DerecPairingError::PairingStateError)?;
    let ecies_shared_key = pairing_ecies::derive_shared_key(&secrets.ecies_secret_key, &received.ecies_public_key)?;

    // xor and return
    Ok(std::array::from_fn(|i| mlkem_shared_key[i] ^ ecies_shared_key[i]))
}

/// Completes the pairing protocol for the contactor (initiator) and derives the final shared 256-bit key.
///
/// This function is called by the contactor after receiving the pairing request message from the requestor.
/// It performs the following steps:
/// 1. Uses the stored ML-KEM decapsulation key to decapsulate the received ML-KEM ciphertext,
///    recovering the post-quantum shared secret.
/// 2. Uses the ECIES secret key and the requestor's ECIES public key to derive the classical ECDH shared secret.
/// 3. Combines the two secrets by XOR-ing them together to produce the final shared key.
///
/// # Arguments
/// * `secrets` - The `PairingSecretKeyMaterial` held by the contactor, containing the ML-KEM decapsulation key and ECIES secret key.
/// * `received` - The `PairingRequestMessageMaterial` received from the requestor, containing the ML-KEM ciphertext and ECIES public key.
///
/// # Returns
/// - `Ok(PairingSharedKey)` containing the derived 256-bit shared key if successful.
/// - `Err(DerecPairingError)` if the required secrets are missing or key derivation fails.
///
/// # Errors
/// Returns `DerecPairingError::PairingStateError` if the ML-KEM decapsulation key is missing,
/// or propagates errors from ML-KEM decapsulation or ECIES shared key derivation.
///
/// # Example
/// ```rust
/// use derec_cryptography::pairing::*;
/// let (contact_msg, contactor_secrets) = contact_message([0u8; 32]).unwrap();
/// let (request_msg, _) = pairing_request_message([0u8; 32], &contact_msg).unwrap();
/// let shared_key = finish_pairing_contactor(&contactor_secrets, &request_msg).unwrap();
/// ```
pub fn finish_pairing_contactor(
    secrets: &PairingSecretKeyMaterial,
    received: &PairingRequestMessageMaterial
) -> Result<PairingSharedKey, DerecPairingError> {
    let mlkem_dk = secrets.mlkem_decapsulation_key.to_owned().ok_or(DerecPairingError::PairingStateError)?;
    let mlkem_shared_key = pairing_mlkem::decapsulate(&mlkem_dk, &received.mlkem_ciphertext)?;
    let ecies_shared_key = pairing_ecies::derive_shared_key(&secrets.ecies_secret_key, &received.ecies_public_key)?;

    // xor and return
    Ok(std::array::from_fn(|i| mlkem_shared_key[i] ^ ecies_shared_key[i]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing() {
        // generated by Bob
        let (bob_contact, bob_secrets) = contact_message([0u8; 32]).unwrap();
        let (alice_request, alice_secrets) = pairing_request_message([0u8; 32], &bob_contact).unwrap();

        let alice_shared_key = finish_pairing_requestor(&alice_secrets, &bob_contact).unwrap();
        let bob_shared_key = finish_pairing_contactor(&bob_secrets, &alice_request).unwrap();

        assert_eq!(alice_shared_key, bob_shared_key);
    }
}
