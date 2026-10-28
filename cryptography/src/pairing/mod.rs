// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Cryptographic pairing module for Derec, providing secure key exchange mechanisms using ML-KEM and ECIES.
//!
//! This module defines the types and functions required to perform a two-party pairing protocol,
//! combining post-quantum (ML-KEM) and classical (ECIES) cryptography. The protocol enables two parties
//! to securely derive a shared 256-bit key using a combination of encapsulation/decapsulation and ECDH key exchange.
//!
//! # Roles
//! - **Initiator**: the party that creates and broadcasts the contact message.
//! - **Responder**: the party that receives the contact message and replies with the pairing request.
//!
//! # Modules
//! - `mlkem`: ML-KEM (Kyber) encapsulation/decapsulation primitives.
//! - `ecies`: ECIES (Elliptic Curve Integrated Encryption Scheme) primitives.
//!
//! # Error Handling
//! Defines `DerecPairingError` for error reporting throughout the pairing process.
//!
//! # Data Structures
//! - `PairingContactMessageMaterial`: Public material produced by the initiator and sent to the responder.
//! - `InitiatorSecretKeyMaterial`: Secret material held by the **initiator** during pairing.
//! - `ResponderSecretKeyMaterial`: Secret material held by the **responder** during pairing.
//! - `PairingSecretKeyMaterial`: Enum wrapping either role's secret material for unified storage.
//! - `PairingRequestMessageMaterial`: Public material produced by the responder and sent back to the initiator.
//! - `PairingSharedKey`: The final 256-bit shared key derived by both parties.
//!
//! # Protocol Overview
//! 1. **Contact Message Generation**: The initiator generates a contact message and secret material.
//! 2. **Pairing Request Message**: The responder uses the contact message to generate a request message and secret material.
//! 3. **Shared Key Derivation**: Both parties independently derive the handshake key by XOR-ing secrets from ML-KEM and ECIES,
//!    then hash it together with the initiator's fingerprint nonce into the channel key.
//!
//! # Fingerprint commitment
//!
//! The responder picks every random input of the handshake key after it has
//! seen the initiator's public keys. The initiator therefore draws a random
//! [`FingerprintNonce`], publishes [`fingerprint_commitment`] with its keys,
//! and reveals the nonce only after the responder's pairing request has fixed
//! the handshake key. The channel key depends on both, so neither party can
//! steer it, and with it the fingerprint compared out of band, by searching
//! over its own contribution.
//!
//! # Functions
//! - `contact_message`: Generates a contact message and secret key material for the initiator.
//! - `pairing_request_message`: Generates a pairing request message and secret key material for the responder.
//! - `finish_pairing_responder`: Used by the responder to derive the shared key.
//! - `finish_pairing_initiator`: Used by the initiator to derive the shared key.
//!

use rand::Rng as _;
use rand::SeedableRng;
use rand::rngs::ChaCha20Rng;
use zeroize::Zeroizing;

pub mod ecies;
pub mod envelope;
mod error;
pub mod mlkem;
mod types;

pub use error::*;
pub use types::*;

/// Domain-separation label prefixed to the [`fingerprint_commitment`] hash.
const FINGERPRINT_COMMITMENT_LABEL: &[u8] = b"DeRec fingerprint commitment v1";

/// Domain-separation label prefixed to the [`channel_key`] hash.
const CHANNEL_KEY_LABEL: &[u8] = b"DeRec channel key v1";

/// Generates a contact message and corresponding secret key material for the initiator in the pairing protocol.
///
/// This function performs the following steps:
/// 1. Generates a fresh ML-KEM (Kyber) keypair for post-quantum encapsulation/decapsulation.
/// 2. Generates a fresh ECIES (Elliptic Curve Integrated Encryption Scheme) keypair for classical ECDH key exchange.
/// 3. Draws the [`FingerprintNonce`] the initiator commits to and later reveals.
/// 4. Packages the public components into a `PairingContactMessageMaterial` to be sent to the responder.
/// 5. Returns the secret components as `PairingSecretKeyMaterial` to be retained by the initiator.
///
/// # Arguments
/// * `entropy` - A cryptographically secure random seed of length `λ` (32 bytes).
///
/// # Returns
/// - `Ok((PairingContactMessageMaterial, PairingSecretKeyMaterial))` on success, containing:
///     - The public contact message material to send to the responder.
///     - The secret key material to be kept by the initiator.
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
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(role = "initiator"))
)]
pub fn contact_message(
    entropy: [u8; 32],
) -> Result<(PairingContactMessageMaterial, InitiatorSecretKeyMaterial), DerecPairingError> {
    let mut csprng = ChaCha20Rng::from_seed(entropy);
    let (dk, ek) = mlkem::generate_keypair(&mut csprng);
    let (sk, pk) = ecies::generate_key(&mut csprng).inspect_err(|_e| {
        #[cfg(feature = "logging")]
        tracing::warn!(error = %_e, "ECIES key generation failed");
    })?;
    let mut fingerprint_nonce = [0u8; 32];
    csprng.fill_bytes(&mut fingerprint_nonce);

    #[cfg(feature = "logging")]
    {
        tracing::debug!(
            mlkem_encapsulation_key_len = ek.len(),
            ecies_public_key_len = pk.len(),
            "keypairs generated"
        );
        tracing::trace!(
            mlkem_decapsulation_key_len = dk.len(),
            "secret key material ready — lengths only, no key bytes"
        );
        tracing::info!("contact message generated");
    }

    Ok((
        PairingContactMessageMaterial {
            mlkem_encapsulation_key: ek.clone(),
            ecies_public_key: pk.clone(),
        },
        InitiatorSecretKeyMaterial {
            mlkem_decapsulation_key: dk,
            ecies_secret_key: sk,
            mlkem_encapsulation_key: ek,
            ecies_public_key: pk,
            fingerprint_nonce,
        },
    ))
}

/// SHA-256 commitment that binds an initiator's [`FingerprintNonce`] to the
/// public keys it publishes.
///
/// The initiator publishes this with its keys: inline in an `InlineKeys`
/// contact, in the `PrePairResponse` otherwise. The responder holds it until
/// the pairing response reveals the nonce, and
/// [`finish_pairing_responder`] refuses a nonce that does not open it.
/// Covering the keys keeps a commitment made for one initiator's keys from
/// being replayed alongside another's.
///
/// # Domain
///
/// ```text
/// SHA-256( "DeRec fingerprint commitment v1"
///       || mlkem_encapsulation_key
///       || ecies_public_key
///       || fingerprint_nonce )
/// ```
pub fn fingerprint_commitment(
    mlkem_encapsulation_key: &[u8],
    ecies_public_key: &[u8],
    fingerprint_nonce: &FingerprintNonce,
) -> FingerprintCommitment {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_COMMITMENT_LABEL);
    hasher.update(mlkem_encapsulation_key);
    hasher.update(ecies_public_key);
    hasher.update(fingerprint_nonce);
    hasher.finalize().into()
}

/// The channel key both parties derive from the handshake key and the
/// initiator's [`FingerprintNonce`].
///
/// Every message after pairing is encrypted under it, and the fingerprint
/// compared out of band is computed from it.
///
/// # Domain
///
/// ```text
/// SHA-256( "DeRec channel key v1" || handshake_key || fingerprint_nonce )
/// ```
///
/// where `handshake_key` is the ML-KEM shared secret XOR the ECDH shared
/// secret.
pub fn channel_key(
    handshake_key: &[u8; 32],
    fingerprint_nonce: &FingerprintNonce,
) -> PairingSharedKey {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(CHANNEL_KEY_LABEL);
    hasher.update(handshake_key);
    hasher.update(fingerprint_nonce);
    hasher.finalize().into()
}

/// SHA-384 binding hash that commits an initiator's pairing public keys to a
/// `(nonce, channel_id)` session.
///
/// Used by `HashedKeys`-mode pairing: the initiator emits a `ContactMessage`
/// carrying only this 48-byte hash, and the scanner — after fetching the real
/// keys via a `PrePair` round-trip — recomputes the same hash and compares.
/// Mismatch means the published keys don't match the contact's commitment
/// (man-in-the-middle on the PrePair leg, swapped keys, etc.) and pairing
/// MUST be refused.
///
/// # Domain
///
/// ```text
/// SHA-384( mlkem_encapsulation_key
///       || ecies_public_key
///       || u64_be(nonce)
///       || u64_be(channel_id) )
/// ```
///
/// Integers are big-endian and the field order is fixed — both sides must
/// hash identical bytes, byte-for-byte, for the comparison to succeed.
///
/// # Constant-time use
///
/// Returns the raw 48-byte digest. Callers MUST compare against
/// `ContactMessage.contact_binding_hash` with a constant-time equality
/// (`subtle::ConstantTimeEq`) — otherwise a timing oracle could leak which
/// prefix of the expected hash an attacker has guessed correctly.
pub fn contact_binding_hash(
    mlkem_encapsulation_key: &[u8],
    ecies_public_key: &[u8],
    nonce: u64,
    channel_id: u64,
) -> [u8; 48] {
    use sha2::{Digest, Sha384};

    let mut hasher = Sha384::new();
    hasher.update(mlkem_encapsulation_key);
    hasher.update(ecies_public_key);
    hasher.update(nonce.to_be_bytes());
    hasher.update(channel_id.to_be_bytes());
    hasher.finalize().into()
}

/// Generates a pairing request message and corresponding secret key material for the responder in the pairing protocol.
///
/// This function performs the following steps:
/// 1. Uses the received `PairingContactMessageMaterial` (from the initiator) to perform ML-KEM (Kyber) encapsulation,
///    producing a ciphertext and a shared secret.
/// 2. Generates a fresh ECIES (Elliptic Curve Integrated Encryption Scheme) keypair for classical ECDH key exchange.
/// 3. Packages the ML-KEM ciphertext and ECIES public key into a `PairingRequestMessageMaterial` to be sent back to the initiator.
/// 4. Returns the secret components as `ResponderSecretKeyMaterial` to be retained by the responder.
///
/// # Arguments
/// * `entropy` - A cryptographically secure random seed of length `λ` (32 bytes).
/// * `received` - The `PairingContactMessageMaterial` received from the initiator.
///
/// # Returns
/// - `Ok((PairingRequestMessageMaterial, ResponderSecretKeyMaterial))` on success, containing:
///     - The public pairing request message material to send to the initiator.
///     - The secret key material to be kept by the responder.
/// - `Err(DerecPairingError)` if encapsulation or key generation fails.
///
/// # Errors
/// Returns `DerecPairingError` if ML-KEM encapsulation or ECIES key generation fails.
///
/// # Example
/// ```rust
/// use derec_cryptography::pairing::*;
///
/// let (contact_msg, _) = contact_message([0u8; 32]).unwrap();
/// let (request_msg, secret_keys) = pairing_request_message([0u8; 32], &contact_msg).unwrap();
/// // Send `request_msg` to the initiator, keep `secret_keys` for later.
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            role = "responder",
            mlkem_encapsulation_key_len = received.mlkem_encapsulation_key.len(),
            ecies_peer_public_key_len = received.ecies_public_key.len(),
        )
    )
)]
pub fn pairing_request_message(
    entropy: [u8; 32],
    received: &PairingContactMessageMaterial,
) -> Result<(PairingRequestMessageMaterial, ResponderSecretKeyMaterial), DerecPairingError> {
    let mut csprng = ChaCha20Rng::from_seed(entropy);

    let (ct, shared_key) = mlkem::encapsulate(&received.mlkem_encapsulation_key, &mut csprng)
        .inspect_err(|_e| {
            #[cfg(feature = "logging")]
            tracing::warn!(error = %_e, "ML-KEM encapsulation failed");
        })?;

    let (sk, pk) = ecies::generate_key(&mut csprng).inspect_err(|_e| {
        #[cfg(feature = "logging")]
        tracing::warn!(error = %_e, "ECIES key generation failed");
    })?;

    #[cfg(feature = "logging")]
    {
        tracing::debug!(
            mlkem_ciphertext_len = ct.len(),
            ecies_public_key_len = pk.len(),
            "encapsulation and ECIES keypair complete"
        );
        tracing::trace!(
            mlkem_shared_secret_len = shared_key.len(),
            "ML-KEM shared secret established — length only, no secret bytes"
        );
        tracing::info!("pairing request message created");
    }

    Ok((
        PairingRequestMessageMaterial {
            mlkem_ciphertext: ct,
            ecies_public_key: pk,
        },
        ResponderSecretKeyMaterial {
            mlkem_shared_secret: shared_key,
            ecies_secret_key: sk,
        },
    ))
}

/// Completes the pairing protocol for the responder and derives the 256-bit channel key.
///
/// This function is called by the responder once the initiator's pairing response has revealed
/// the fingerprint nonce. It:
///
/// 1. Checks that `fingerprint_nonce` opens `fingerprint_commitment` for the initiator's keys.
/// 2. Combines the post-quantum shared secret (from ML-KEM encapsulation) and the classical ECDH
///    shared secret (from ECIES) by XOR-ing them into the handshake key.
/// 3. Derives the channel key from the handshake key and the nonce with [`channel_key`].
///
/// # Arguments
/// * `secrets` - The `ResponderSecretKeyMaterial` held by the responder, containing the ML-KEM shared secret and ECIES secret key.
/// * `received` - The `PairingContactMessageMaterial` received from the initiator, containing its public keys.
/// * `fingerprint_commitment` - The commitment the initiator published with those keys.
/// * `fingerprint_nonce` - The nonce revealed in the initiator's pairing response.
///
/// # Returns
/// - `Ok(PairingSharedKey)` containing the derived 256-bit channel key if successful.
/// - `Err(DerecPairingError)` if the nonce does not open the commitment or key derivation fails.
///
/// # Errors
/// - [`DerecPairingError::FingerprintCommitmentMismatch`] if `fingerprint_nonce` does not open
///   `fingerprint_commitment` for `received`'s keys.
/// - Propagates errors from ECIES shared key derivation.
///
/// # Example
/// ```rust
/// use derec_cryptography::pairing::*;
///
/// let (contact_msg, initiator_secrets) = contact_message([0u8; 32]).unwrap();
/// let commitment = initiator_secrets.fingerprint_commitment();
/// let (request_msg, secret_keys) = pairing_request_message([0u8; 32], &contact_msg).unwrap();
/// // The pairing response reveals `initiator_secrets.fingerprint_nonce`.
/// let shared_key = finish_pairing_responder(
///     &secret_keys,
///     &contact_msg,
///     &commitment,
///     &initiator_secrets.fingerprint_nonce,
/// ).unwrap();
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            role = "responder",
            ecies_peer_public_key_len = received.ecies_public_key.len(),
        )
    )
)]
pub fn finish_pairing_responder(
    secrets: &ResponderSecretKeyMaterial,
    received: &PairingContactMessageMaterial,
    fingerprint_commitment: &FingerprintCommitment,
    fingerprint_nonce: &FingerprintNonce,
) -> Result<PairingSharedKey, DerecPairingError> {
    use subtle::ConstantTimeEq;

    let opened = self::fingerprint_commitment(
        &received.mlkem_encapsulation_key,
        &received.ecies_public_key,
        fingerprint_nonce,
    );
    if !bool::from(opened.ct_eq(fingerprint_commitment)) {
        #[cfg(feature = "logging")]
        tracing::warn!("fingerprint nonce does not open the initiator's commitment");
        return Err(DerecPairingError::FingerprintCommitmentMismatch);
    }

    let mlkem_shared_key = &secrets.mlkem_shared_secret;

    let ecies_shared_key = Zeroizing::new(
        ecies::derive_shared_key(&secrets.ecies_secret_key, &received.ecies_public_key)
            .inspect_err(|_e| {
                #[cfg(feature = "logging")]
                tracing::warn!(error = %_e, "ECIES shared key derivation failed");
            })?,
    );

    #[cfg(feature = "logging")]
    tracing::trace!(
        mlkem_ss_len = mlkem_shared_key.len(),
        ecies_ss_len = ecies_shared_key.len(),
        shared_key_len = 32,
        "XOR combiner inputs — lengths only, no secret bytes"
    );

    let handshake_key: Zeroizing<[u8; 32]> = Zeroizing::new(std::array::from_fn(|i| {
        mlkem_shared_key[i] ^ ecies_shared_key[i]
    }));
    let shared_key = channel_key(&handshake_key, fingerprint_nonce);

    #[cfg(feature = "logging")]
    tracing::info!(
        shared_key_len = 32,
        "pairing complete — channel key derived"
    );

    Ok(shared_key)
}

/// Completes the pairing protocol for the initiator and derives the final shared 256-bit key.
///
/// This function is called by the initiator after receiving the pairing request message from the responder.
/// It performs the following steps:
/// 1. Uses the stored ML-KEM decapsulation key to decapsulate the received ML-KEM ciphertext,
///    recovering the post-quantum shared secret.
/// 2. Uses the ECIES secret key and the responder's ECIES public key to derive the classical ECDH shared secret.
/// 3. Combines the two secrets by XOR-ing them together into the handshake key.
/// 4. Derives the channel key from the handshake key and its own fingerprint nonce with
///    [`channel_key`]. The nonce is revealed to the responder in the pairing response.
///
/// # Arguments
/// * `secrets` - The `InitiatorSecretKeyMaterial` held by the initiator, containing the ML-KEM decapsulation key, ECIES secret key and fingerprint nonce.
/// * `received` - The `PairingRequestMessageMaterial` received from the responder, containing the ML-KEM ciphertext and ECIES public key.
///
/// # Returns
/// - `Ok(PairingSharedKey)` containing the derived 256-bit channel key if successful.
/// - `Err(DerecPairingError)` if key derivation fails.
///
/// # Errors
/// Propagates errors from ML-KEM decapsulation or ECIES shared key derivation.
///
/// # Example
/// ```rust
/// use derec_cryptography::pairing::*;
///
/// let (contact_msg, initiator_secrets) = contact_message([0u8; 32]).unwrap();
/// let (request_msg, _) = pairing_request_message([0u8; 32], &contact_msg).unwrap();
/// let shared_key = finish_pairing_initiator(&initiator_secrets, &request_msg).unwrap();
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            role = "initiator",
            mlkem_ciphertext_len = received.mlkem_ciphertext.len(),
            ecies_peer_public_key_len = received.ecies_public_key.len(),
        )
    )
)]
pub fn finish_pairing_initiator(
    secrets: &InitiatorSecretKeyMaterial,
    received: &PairingRequestMessageMaterial,
) -> Result<PairingSharedKey, DerecPairingError> {
    #[cfg(feature = "logging")]
    tracing::debug!(
        mlkem_decapsulation_key_len = secrets.mlkem_decapsulation_key.len(),
        "decapsulation key loaded — length only, no key bytes"
    );

    let mlkem_shared_key = Zeroizing::new(
        mlkem::decapsulate(&secrets.mlkem_decapsulation_key, &received.mlkem_ciphertext)
            .inspect_err(|_e| {
                #[cfg(feature = "logging")]
                tracing::warn!(error = %_e, "ML-KEM decapsulation failed");
            })?,
    );

    let ecies_shared_key = Zeroizing::new(
        ecies::derive_shared_key(&secrets.ecies_secret_key, &received.ecies_public_key)
            .inspect_err(|_e| {
                #[cfg(feature = "logging")]
                tracing::warn!(error = %_e, "ECIES shared key derivation failed");
            })?,
    );

    #[cfg(feature = "logging")]
    tracing::trace!(
        mlkem_ss_len = mlkem_shared_key.len(),
        ecies_ss_len = ecies_shared_key.len(),
        shared_key_len = 32,
        "XOR combiner inputs — lengths only, no secret bytes"
    );

    let handshake_key: Zeroizing<[u8; 32]> = Zeroizing::new(std::array::from_fn(|i| {
        mlkem_shared_key[i] ^ ecies_shared_key[i]
    }));
    let shared_key = channel_key(&handshake_key, &secrets.fingerprint_nonce);

    #[cfg(feature = "logging")]
    tracing::info!(
        shared_key_len = 32,
        "pairing complete — channel key derived"
    );

    Ok(shared_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing() {
        let (bob_contact, bob_secrets) = contact_message([0u8; 32]).unwrap();
        let (alice_request, alice_secrets) =
            pairing_request_message([0u8; 32], &bob_contact).unwrap();

        let alice_shared_key = finish_pairing_responder(
            &alice_secrets,
            &bob_contact,
            &bob_secrets.fingerprint_commitment(),
            &bob_secrets.fingerprint_nonce,
        )
        .unwrap();
        let bob_shared_key = finish_pairing_initiator(&bob_secrets, &alice_request).unwrap();

        assert_eq!(alice_shared_key, bob_shared_key);
    }

    #[test]
    fn a_nonce_that_does_not_open_the_commitment_is_refused() {
        let (bob_contact, bob_secrets) = contact_message([1u8; 32]).unwrap();
        let (_, alice_secrets) = pairing_request_message([2u8; 32], &bob_contact).unwrap();

        let mut wrong_nonce = bob_secrets.fingerprint_nonce;
        wrong_nonce[0] ^= 1;
        assert!(matches!(
            finish_pairing_responder(
                &alice_secrets,
                &bob_contact,
                &bob_secrets.fingerprint_commitment(),
                &wrong_nonce,
            ),
            Err(DerecPairingError::FingerprintCommitmentMismatch)
        ));
    }

    #[test]
    fn a_commitment_made_for_other_keys_is_refused() {
        let (bob_contact, _) = contact_message([1u8; 32]).unwrap();
        let (_, carol_secrets) = contact_message([3u8; 32]).unwrap();
        let (_, alice_secrets) = pairing_request_message([2u8; 32], &bob_contact).unwrap();

        // Carol's commitment opens with Carol's nonce, but not over Bob's keys.
        assert!(matches!(
            finish_pairing_responder(
                &alice_secrets,
                &bob_contact,
                &carol_secrets.fingerprint_commitment(),
                &carol_secrets.fingerprint_nonce,
            ),
            Err(DerecPairingError::FingerprintCommitmentMismatch)
        ));
    }

    #[test]
    fn the_channel_key_depends_on_the_fingerprint_nonce() {
        let handshake_key = [7u8; 32];
        let a = channel_key(&handshake_key, &[0u8; 32]);
        let b = channel_key(&handshake_key, &[1u8; 32]);
        assert_ne!(a, b);
        assert_ne!(a, handshake_key);
    }

    #[test]
    fn each_contact_draws_its_own_fingerprint_nonce() {
        let (_, a) = contact_message([1u8; 32]).unwrap();
        let (_, b) = contact_message([2u8; 32]).unwrap();
        assert_ne!(a.fingerprint_nonce, b.fingerprint_nonce);
        assert_ne!(a.fingerprint_nonce, [0u8; 32]);
    }

    /// Pins both derivations so any other implementation of the protocol can
    /// check its own against the same bytes.
    #[test]
    fn commitment_and_channel_key_match_their_reference_values() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        let nonce = [0x11u8; 32];
        assert_eq!(
            hex(&fingerprint_commitment(b"mlkem", b"ecies", &nonce)),
            COMMITMENT_REFERENCE
        );
        assert_eq!(
            hex(&channel_key(&[0x22u8; 32], &nonce)),
            CHANNEL_KEY_REFERENCE
        );
    }

    const COMMITMENT_REFERENCE: &str =
        "65a2bb3a2f900e1f4c37ad40459c551c08fd74af56131c3f089dfb3306a9ff1d";
    const CHANNEL_KEY_REFERENCE: &str =
        "cea938e8f8f3ae7c3f4e4af68ee07f8018b97fd41d85d2902236525ca4191a29";

    /// Reference inputs used across the binding-hash tests. `mlkem` and `ecies`
    /// are short opaque payloads — the function treats them as raw bytes, so
    /// the exact length doesn't matter for any of the assertions.
    fn ref_inputs() -> (&'static [u8], &'static [u8], u64, u64) {
        (
            b"mlkem_encapsulation_key_bytes",
            b"ecies_public_key_bytes",
            0xCAFE_BABE_DEAD_BEEF,
            0x0102_0304_0506_0708,
        )
    }

    #[test]
    fn contact_binding_hash_is_48_bytes() {
        let (mlkem, ecies, nonce, channel_id) = ref_inputs();
        let hash = contact_binding_hash(mlkem, ecies, nonce, channel_id);
        // SHA-384 always produces a 48-byte digest. The return type already
        // enforces this; the assertion exists so this test fails loudly if
        // the helper is ever switched to a different hash function without
        // updating the signature.
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn contact_binding_hash_is_deterministic() {
        let (mlkem, ecies, nonce, channel_id) = ref_inputs();
        let a = contact_binding_hash(mlkem, ecies, nonce, channel_id);
        let b = contact_binding_hash(mlkem, ecies, nonce, channel_id);
        assert_eq!(a, b, "binding hash must be deterministic");
    }

    #[test]
    fn contact_binding_hash_is_sensitive_to_mlkem_key() {
        let (mlkem, ecies, nonce, channel_id) = ref_inputs();
        let base = contact_binding_hash(mlkem, ecies, nonce, channel_id);
        let perturbed = contact_binding_hash(b"different_mlkem_key", ecies, nonce, channel_id);
        assert_ne!(
            base, perturbed,
            "changing the mlkem key must change the hash"
        );
    }

    #[test]
    fn contact_binding_hash_is_sensitive_to_ecies_key() {
        let (mlkem, ecies, nonce, channel_id) = ref_inputs();
        let base = contact_binding_hash(mlkem, ecies, nonce, channel_id);
        let perturbed = contact_binding_hash(mlkem, b"different_ecies_key", nonce, channel_id);
        assert_ne!(
            base, perturbed,
            "changing the ecies key must change the hash"
        );
    }

    #[test]
    fn contact_binding_hash_is_sensitive_to_nonce() {
        let (mlkem, ecies, nonce, channel_id) = ref_inputs();
        let base = contact_binding_hash(mlkem, ecies, nonce, channel_id);
        let perturbed = contact_binding_hash(mlkem, ecies, nonce.wrapping_add(1), channel_id);
        assert_ne!(base, perturbed, "changing the nonce must change the hash");
    }

    #[test]
    fn contact_binding_hash_is_sensitive_to_channel_id() {
        let (mlkem, ecies, nonce, channel_id) = ref_inputs();
        let base = contact_binding_hash(mlkem, ecies, nonce, channel_id);
        let perturbed = contact_binding_hash(mlkem, ecies, nonce, channel_id.wrapping_add(1));
        assert_ne!(
            base, perturbed,
            "changing the channel_id must change the hash"
        );
    }

    /// Field order matters: swapping the mlkem and ecies key positions must
    /// produce a different digest (unless they're equal). Without this
    /// guarantee, an attacker who controls one of the published keys could
    /// craft a substitution that hashes to the same value.
    #[test]
    fn contact_binding_hash_is_sensitive_to_key_field_order() {
        let mlkem: &[u8] = b"AAAA";
        let ecies: &[u8] = b"BBBB";
        let (_, _, nonce, channel_id) = ref_inputs();
        let normal = contact_binding_hash(mlkem, ecies, nonce, channel_id);
        let swapped = contact_binding_hash(ecies, mlkem, nonce, channel_id);
        assert_ne!(
            normal, swapped,
            "swapping mlkem and ecies field order must change the hash"
        );
    }

    /// Integers must be encoded big-endian. Without that contract, a
    /// little-endian implementation on the other side of the protocol would
    /// silently produce a different digest for the same logical input.
    #[test]
    fn contact_binding_hash_encodes_integers_big_endian() {
        let (mlkem, ecies, _, _) = ref_inputs();
        let nonce: u64 = 0x0102_0304_0506_0708;
        let channel_id: u64 = 0x1112_1314_1516_1718;
        let hash = contact_binding_hash(mlkem, ecies, nonce, channel_id);

        // Recompute byte-for-byte with the documented encoding and assert
        // equality. If anyone changes the helper to write little-endian or
        // swap the integer order, this test fails immediately.
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        hasher.update(mlkem);
        hasher.update(ecies);
        hasher.update(nonce.to_be_bytes());
        hasher.update(channel_id.to_be_bytes());
        let expected: [u8; 48] = hasher.finalize().into();
        assert_eq!(hash, expected);
    }

    /// Empty key inputs are valid input — `Sha384::update(&[])` is a no-op,
    /// so the digest folds in only the two integer fields. We pin this
    /// behavior explicitly because the helper is the canonical site for
    /// the formula; if it ever rejects empty slices, callers that haven't
    /// validated key non-emptiness upstream would surface confusing errors.
    #[test]
    fn contact_binding_hash_accepts_empty_inputs() {
        let hash = contact_binding_hash(&[], &[], 0, 0);
        assert_eq!(hash.len(), 48);
    }
}
