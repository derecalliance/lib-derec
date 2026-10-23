// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The pairing protocol's message and key-material types.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PairingContactMessageMaterial {
    pub mlkem_encapsulation_key: Vec<u8>,
    pub ecies_public_key: Vec<u8>,
}

/// Secret key material held by the **initiator** during pairing.
///
/// Produced by [`contact_message`](super::contact_message) and consumed by [`finish_pairing_initiator`](super::finish_pairing_initiator).
/// Always holds an ML-KEM decapsulation key; never holds an ML-KEM shared secret.
///
/// The matching public components (`mlkem_encapsulation_key`, `ecies_public_key`)
/// are also retained here so that the [`CONTACT_MODE_HASHED_KEYS`][PairingContactMessageMaterial]
/// pre-pair flow can re-publish them after the contact creator has already given
/// the contact away.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct InitiatorSecretKeyMaterial {
    /// ML-KEM-1024 decapsulation key. Used in [`finish_pairing_initiator`](super::finish_pairing_initiator) to recover
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
/// Produced by [`pairing_request_message`](super::pairing_request_message) and consumed by [`finish_pairing_responder`](super::finish_pairing_responder).
/// Always holds an ML-KEM shared secret; never holds a decapsulation key.
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ResponderSecretKeyMaterial {
    /// ML-KEM-1024 shared secret established during encapsulation. Combined with the
    /// ECDH secret in [`finish_pairing_responder`](super::finish_pairing_responder) to derive the final shared key.
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

/// The 32-byte secret an ML-KEM encapsulation produces and its decapsulation
/// recovers — see [`super::mlkem`].
pub type SharedSecret = [u8; 32];
