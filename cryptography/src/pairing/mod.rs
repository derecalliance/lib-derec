// SPDX-License-Identifier: Apache-2.0

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
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct InitiatorSecretKeyMaterial {
    /// ML-KEM-1024 decapsulation key. Used in [`finish_pairing_initiator`] to recover
    /// the post-quantum shared secret from the responder's ciphertext.
    pub mlkem_decapsulation_key: Vec<u8>,
    /// ECIES secret key. Used to decrypt incoming pairing messages and to derive the
    /// ECDH component of the final shared key.
    pub ecies_secret_key: Vec<u8>,
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
            mlkem_encapsulation_key: ek,
            ecies_public_key: pk,
        },
        InitiatorSecretKeyMaterial {
            mlkem_decapsulation_key: dk,
            ecies_secret_key: sk,
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
}
