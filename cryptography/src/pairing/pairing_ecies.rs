// SPDX-License-Identifier: Apache-2.0

//! This module provides cryptographic primitives for key establishment using
//! Elliptic Curve Integrated Encryption Scheme (ECIES) operations over secp256k1.

use ark_ec::*;
use ark_ff::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use sha2::*;

use super::DerecPairingError;

/// Generates a new secp256k1 keypair for use with ECIES.
///
/// # Arguments
///
/// * `rng` - A mutable reference to a random number generator implementing the `Rng` trait.
///
/// # Returns a `Result` containing, on success, the following tuple:
/// - The secret key as a vector of bytes (uncompressed serialization).
/// - The public key as a vector of bytes (uncompressed serialization).
///
pub fn generate_key<R: Rng>(rng: &mut R) -> Result<(Vec<u8>, Vec<u8>), DerecPairingError> {
    let sk = ark_secp256k1::Fr::rand(rng);
    let pk = ark_secp256k1::Affine::generator() * sk;

    let mut sk_bytes = Vec::new();
    sk.serialize_uncompressed(&mut sk_bytes)
        .map_err(DerecPairingError::SerializationError)?;

    let mut pk_bytes = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes)
        .map_err(DerecPairingError::SerializationError)?;

    Ok((sk_bytes, pk_bytes))
}

/// Derives a shared secret key using Elliptic Curve Diffie-Hellman (ECDH) over secp256k1.
///
/// This function computes a shared secret by multiplying the provided secret key (`sk`)
/// with the provided public key (`pk`) on the secp256k1 curve. The resulting point is
/// serialized and hashed with SHA-256 to produce a 32-byte shared key suitable for use
/// as a symmetric encryption key.
///
/// # Arguments
///
/// * `sk` - A byte slice containing the secret key in uncompressed serialization format.
/// * `pk` - A byte slice containing the public key in uncompressed serialization format.
///
/// # Returns a `Result` containing, on success, the following:
/// a 32-byte array representing the derived shared key.
///
pub fn derive_shared_key(sk: &[u8], pk: &[u8]) -> Result<[u8; 32], DerecPairingError> {
    let sk = ark_secp256k1::Fr::deserialize_uncompressed(sk)
        .map_err(DerecPairingError::SerializationError)?;
    let pk = ark_secp256k1::Affine::deserialize_uncompressed(pk)
        .map_err(DerecPairingError::SerializationError)?;

    let shared_key = pk * sk;

    let mut shared_key_bytes = Vec::new();
    shared_key
        .serialize_uncompressed(&mut shared_key_bytes)
        .map_err(DerecPairingError::SerializationError)?;

    let mut hasher = sha2::Sha256::new();
    hasher.update(shared_key_bytes);
    Ok(hasher.finalize().into())
}
