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
//! - `pairing_mlkem`: ML-KEM (Kyber) encapsulation/decapsulation primitives.
//! - `pairing_ecies`: ECIES (Elliptic Curve Integrated Encryption Scheme) primitives.
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
//! 3. **Shared Key Derivation**: Both parties independently derive the shared key by XOR-ing secrets from ML-KEM and ECIES.
//!
//! # Functions
//! - `contact_message`: Generates a contact message and secret key material for the initiator.
//! - `pairing_request_message`: Generates a pairing request message and secret key material for the responder.
//! - `finish_pairing_responder`: Used by the responder to derive the shared key.
//! - `finish_pairing_initiator`: Used by the initiator to derive the shared key.
//!

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand_chacha::rand_core::SeedableRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod envelope;
pub mod pairing_ecies;
pub mod pairing_mlkem;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DerecPairingError {
    #[error("serialization error: {0:?}")]
    SerializationError(ark_serialize::SerializationError),

    #[error("ml-kem encapsulation failed")]
    MLKemEncapsulationError,

    #[error("ml-kem decapsulation failed")]
    MLKemDecapsulationError,

    #[error("invalid input size: expected {expected} bytes, got {got}")]
    InvalidSize { expected: usize, got: usize },
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PairingContactMessageMaterial {
    pub mlkem_encapsulation_key: Vec<u8>,
    pub ecies_public_key: Vec<u8>,
}

/// Secret key material held by the **initiator** during pairing.
///
/// Produced by [`contact_message`] and consumed by [`finish_pairing_initiator`].
/// Always holds an ML-KEM decapsulation key; never holds an ML-KEM shared secret.
///
/// The matching public components (`mlkem_encapsulation_key`, `ecies_public_key`)
/// are also retained here so that the [`CONTACT_MODE_HASHED_KEYS`][PairingContactMessageMaterial]
/// pre-pair flow can re-publish them after the contact creator has already given
/// the contact away.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct InitiatorSecretKeyMaterial {
    /// ML-KEM-1024 decapsulation key. Used in [`finish_pairing_initiator`] to recover
    /// the post-quantum shared secret from the responder's ciphertext.
    pub mlkem_decapsulation_key: Vec<u8>,
    /// ECIES secret key. Used to decrypt incoming pairing messages and to derive the
    /// ECDH component of the final shared key.
    pub ecies_secret_key: Vec<u8>,
    /// ML-KEM-1024 encapsulation key — the public counterpart of
    /// `mlkem_decapsulation_key`. Republished verbatim in the `PrePairResponse`
    /// flow when the contact was sent in `HASHED_KEYS` mode.
    pub mlkem_encapsulation_key: Vec<u8>,
    /// ECIES public key — the public counterpart of `ecies_secret_key`. Same
    /// `PrePairResponse` purpose as `mlkem_encapsulation_key`.
    pub ecies_public_key: Vec<u8>,
}

/// Secret key material held by the **responder** during pairing.
///
/// Produced by [`pairing_request_message`] and consumed by [`finish_pairing_responder`].
/// Always holds an ML-KEM shared secret; never holds a decapsulation key.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ResponderSecretKeyMaterial {
    /// ML-KEM-1024 shared secret established during encapsulation. Combined with the
    /// ECDH secret in [`finish_pairing_responder`] to derive the final shared key.
    pub mlkem_shared_secret: [u8; 32],
    /// ECIES secret key. Used to decrypt incoming pairing messages and to derive the
    /// ECDH component of the final shared key.
    pub ecies_secret_key: Vec<u8>,
}

/// Secret key material for an in-progress pairing session.
///
/// The variant encodes the local party's role:
///
/// - [`Initiator`](PairingSecretKeyMaterial::Initiator): held by the party that created the
///   contact message. Contains an ML-KEM decapsulation key; no shared secret yet.
/// - [`Responder`](PairingSecretKeyMaterial::Responder): held by the party that replied with
///   the pairing request. Contains the ML-KEM shared secret; no decapsulation key.
///
/// Both variants carry an ECIES secret key, accessible via [`ecies_secret_key`](Self::ecies_secret_key).
///
/// # Serialization
///
/// Implements [`ark_serialize::CanonicalSerialize`] / [`ark_serialize::CanonicalDeserialize`]
/// manually. The wire format is a single discriminant byte (`0` = Initiator, `1` = Responder)
/// followed by the serialized inner struct.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub enum PairingSecretKeyMaterial {
    Initiator(InitiatorSecretKeyMaterial),
    Responder(ResponderSecretKeyMaterial),
}

impl PairingSecretKeyMaterial {
    pub fn ecies_secret_key(&self) -> &[u8] {
        match self {
            Self::Initiator(m) => &m.ecies_secret_key,
            Self::Responder(m) => &m.ecies_secret_key,
        }
    }
}

impl ark_serialize::Valid for PairingSecretKeyMaterial {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        match self {
            Self::Initiator(m) => m.check(),
            Self::Responder(m) => m.check(),
        }
    }
}

impl ark_serialize::CanonicalSerialize for PairingSecretKeyMaterial {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            Self::Initiator(m) => {
                0u8.serialize_with_mode(&mut writer, compress)?;
                m.serialize_with_mode(writer, compress)
            }
            Self::Responder(m) => {
                1u8.serialize_with_mode(&mut writer, compress)?;
                m.serialize_with_mode(writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        1 + match self {
            Self::Initiator(m) => m.serialized_size(compress),
            Self::Responder(m) => m.serialized_size(compress),
        }
    }
}

impl ark_serialize::CanonicalDeserialize for PairingSecretKeyMaterial {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            0 => Ok(Self::Initiator(
                InitiatorSecretKeyMaterial::deserialize_with_mode(reader, compress, validate)?,
            )),
            1 => Ok(Self::Responder(
                ResponderSecretKeyMaterial::deserialize_with_mode(reader, compress, validate)?,
            )),
            _ => Err(ark_serialize::SerializationError::InvalidData),
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PairingRequestMessageMaterial {
    pub mlkem_ciphertext: Vec<u8>,
    pub ecies_public_key: Vec<u8>,
}

pub type PairingSharedKey = [u8; 32];

/// Generates a contact message and corresponding secret key material for the initiator in the pairing protocol.
///
/// This function performs the following steps:
/// 1. Generates a fresh ML-KEM (Kyber) keypair for post-quantum encapsulation/decapsulation.
/// 2. Generates a fresh ECIES (Elliptic Curve Integrated Encryption Scheme) keypair for classical ECDH key exchange.
/// 3. Packages the public components into a `PairingContactMessageMaterial` to be sent to the responder.
/// 4. Returns the secret components as `PairingSecretKeyMaterial` to be retained by the initiator.
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
    let mut csprng = rand_chacha::ChaCha8Rng::from_seed(entropy);
    let (dk, ek) = pairing_mlkem::generate_keypair(&mut csprng);
    let (sk, pk) = pairing_ecies::generate_key(&mut csprng).inspect_err(|_e| {
        #[cfg(feature = "logging")]
        tracing::warn!(error = %_e, "ECIES key generation failed");
    })?;

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
        },
    ))
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
    let mut csprng = rand_chacha::ChaCha8Rng::from_seed(entropy);

    let (ct, shared_key) =
        pairing_mlkem::encapsulate(&received.mlkem_encapsulation_key, &mut csprng).inspect_err(
            |_e| {
                #[cfg(feature = "logging")]
                tracing::warn!(error = %_e, "ML-KEM encapsulation failed");
            },
        )?;

    let (sk, pk) = pairing_ecies::generate_key(&mut csprng).inspect_err(|_e| {
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

/// Completes the pairing protocol for the responder and derives the final shared 256-bit key.
///
/// This function is called by the responder after generating their secret key material and receiving the
/// contact message from the initiator. It combines the post-quantum shared secret (from ML-KEM encapsulation)
/// and the classical ECDH shared secret (from ECIES) by XOR-ing them together to produce the final shared key.
///
/// # Arguments
/// * `secrets` - The `ResponderSecretKeyMaterial` held by the responder, containing the ML-KEM shared secret and ECIES secret key.
/// * `received` - The `PairingContactMessageMaterial` received from the initiator, containing the ECIES public key.
///
/// # Returns
/// - `Ok(PairingSharedKey)` containing the derived 256-bit shared key if successful.
/// - `Err(DerecPairingError)` if key derivation fails.
///
/// # Errors
/// Propagates errors from ECIES shared key derivation.
///
/// # Example
/// ```rust
/// use derec_cryptography::pairing::*;
///
/// let (contact_msg, _) = contact_message([0u8; 32]).unwrap();
/// let (request_msg, secret_keys) = pairing_request_message([0u8; 32], &contact_msg).unwrap();
/// let shared_key = finish_pairing_responder(&secret_keys, &contact_msg).unwrap();
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
) -> Result<PairingSharedKey, DerecPairingError> {
    let mlkem_shared_key = secrets.mlkem_shared_secret;

    let ecies_shared_key =
        pairing_ecies::derive_shared_key(&secrets.ecies_secret_key, &received.ecies_public_key)
            .inspect_err(|_e| {
                #[cfg(feature = "logging")]
                tracing::warn!(error = %_e, "ECIES shared key derivation failed");
            })?;

    #[cfg(feature = "logging")]
    tracing::trace!(
        mlkem_ss_len = mlkem_shared_key.len(),
        ecies_ss_len = ecies_shared_key.len(),
        shared_key_len = 32,
        "XOR combiner inputs — lengths only, no secret bytes"
    );

    let shared_key = std::array::from_fn(|i| mlkem_shared_key[i] ^ ecies_shared_key[i]);

    #[cfg(feature = "logging")]
    tracing::info!(shared_key_len = 32, "pairing complete — shared key derived");

    Ok(shared_key)
}

/// Completes the pairing protocol for the initiator and derives the final shared 256-bit key.
///
/// This function is called by the initiator after receiving the pairing request message from the responder.
/// It performs the following steps:
/// 1. Uses the stored ML-KEM decapsulation key to decapsulate the received ML-KEM ciphertext,
///    recovering the post-quantum shared secret.
/// 2. Uses the ECIES secret key and the responder's ECIES public key to derive the classical ECDH shared secret.
/// 3. Combines the two secrets by XOR-ing them together to produce the final shared key.
///
/// # Arguments
/// * `secrets` - The `InitiatorSecretKeyMaterial` held by the initiator, containing the ML-KEM decapsulation key and ECIES secret key.
/// * `received` - The `PairingRequestMessageMaterial` received from the responder, containing the ML-KEM ciphertext and ECIES public key.
///
/// # Returns
/// - `Ok(PairingSharedKey)` containing the derived 256-bit shared key if successful.
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

    let mlkem_shared_key =
        pairing_mlkem::decapsulate(&secrets.mlkem_decapsulation_key, &received.mlkem_ciphertext)
            .inspect_err(|_e| {
                #[cfg(feature = "logging")]
                tracing::warn!(error = %_e, "ML-KEM decapsulation failed");
            })?;

    let ecies_shared_key =
        pairing_ecies::derive_shared_key(&secrets.ecies_secret_key, &received.ecies_public_key)
            .inspect_err(|_e| {
                #[cfg(feature = "logging")]
                tracing::warn!(error = %_e, "ECIES shared key derivation failed");
            })?;

    #[cfg(feature = "logging")]
    tracing::trace!(
        mlkem_ss_len = mlkem_shared_key.len(),
        ecies_ss_len = ecies_shared_key.len(),
        shared_key_len = 32,
        "XOR combiner inputs — lengths only, no secret bytes"
    );

    let shared_key = std::array::from_fn(|i| mlkem_shared_key[i] ^ ecies_shared_key[i]);

    #[cfg(feature = "logging")]
    tracing::info!(shared_key_len = 32, "pairing complete — shared key derived");

    Ok(shared_key)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pairing() {
        let (bob_contact, bob_secrets) = contact_message([0u8; 32]).unwrap();
        let (alice_request, alice_secrets) =
            pairing_request_message([0u8; 32], &bob_contact).unwrap();

        let alice_shared_key = finish_pairing_responder(&alice_secrets, &bob_contact).unwrap();
        let bob_shared_key = finish_pairing_initiator(&bob_secrets, &alice_request).unwrap();

        assert_eq!(alice_shared_key, bob_shared_key);
    }

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
        assert_ne!(base, perturbed, "changing the mlkem key must change the hash");
    }

    #[test]
    fn contact_binding_hash_is_sensitive_to_ecies_key() {
        let (mlkem, ecies, nonce, channel_id) = ref_inputs();
        let base = contact_binding_hash(mlkem, ecies, nonce, channel_id);
        let perturbed = contact_binding_hash(mlkem, b"different_ecies_key", nonce, channel_id);
        assert_ne!(base, perturbed, "changing the ecies key must change the hash");
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
        assert_ne!(base, perturbed, "changing the channel_id must change the hash");
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
