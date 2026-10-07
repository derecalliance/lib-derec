// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use ml_kem::ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Encapsulate, Generate, KeyExport, Seed};
use rand::CryptoRng;

use super::DerecPairingError;

pub const ENCAPSULATION_KEY_SIZE_IN_BYTES: usize = 1568;
/// Size of a decapsulation key in its seed form, the form [`generate_keypair`]
/// produces.
pub const DECAPSULATION_KEY_SIZE_IN_BYTES: usize = 64;
/// Size of a decapsulation key in the FIPS 203 expanded form, which releases
/// before 0.0.8 produced and stored.
///
/// [`decapsulate`] still accepts it so pairings started before 0.0.8 can
/// complete.
#[deprecated(
    since = "0.0.8",
    note = "expanded decapsulation keys are accepted only for pairings started before 0.0.8; removed at 0.0.13"
)]
pub const EXPANDED_DECAPSULATION_KEY_SIZE_IN_BYTES: usize = 3168;
pub const CIPHERTEXT_SIZE_IN_BYTES: usize = 1568;

pub type SharedSecret = [u8; 32];

/// Generates a new ML-KEM-1024 key pair.
///
/// The decapsulation key is returned as its 64-byte seed
/// ([`DECAPSULATION_KEY_SIZE_IN_BYTES`]), from which [`decapsulate`] rebuilds
/// the full key.
///
/// # Arguments
///
/// * `rng` - A mutable reference to a cryptographically secure random number generator.
///
/// # Returns
///
/// A tuple containing:
/// - The decapsulation key as a `Vec<u8>`.
/// - The encapsulation key as a `Vec<u8>`.
///
pub fn generate_keypair<R: CryptoRng + ?Sized>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    let dk = DecapsulationKey::generate_from_rng(rng);
    let seed = dk.to_bytes();
    let ek_bytes = dk.encapsulation_key().to_bytes();
    (seed.to_vec(), ek_bytes.to_vec())
}

/// Performs ML-KEM-1024 key encapsulation using the provided encapsulation key.
///
/// This function takes an encoded encapsulation key and a cryptographically secure random number generator,
/// and produces a ciphertext along with a shared secret. The ciphertext can be sent to the holder of the
/// corresponding decapsulation key, who can then recover the same shared secret.
///
/// # Arguments
///
/// * `ek_encoded` - The encoded encapsulation key as a byte slice or compatible type.
///   Must be exactly [`ENCAPSULATION_KEY_SIZE_IN_BYTES`] (1568) bytes.
/// * `rng` - A mutable reference to a cryptographically secure random number generator.
///
/// # Returns
///
/// A tuple containing:
/// - The ciphertext as a `Vec<u8>`.
/// - The shared secret as a `[u8; 32]`.
///
/// # Errors
///
/// Returns [`DerecPairingError::InvalidSize`] if `ek_encoded` is not exactly
/// [`ENCAPSULATION_KEY_SIZE_IN_BYTES`] bytes, or [`DerecPairingError::MLKemEncapsulationError`]
/// if the bytes are not a valid encapsulation key.
///
pub fn encapsulate<R: CryptoRng + ?Sized>(
    ek_encoded: impl AsRef<[u8]>,
    rng: &mut R,
) -> Result<(Vec<u8>, SharedSecret), DerecPairingError> {
    let input = ek_encoded.as_ref();
    let ek_bytes: [u8; ENCAPSULATION_KEY_SIZE_IN_BYTES] =
        input
            .try_into()
            .map_err(|_| DerecPairingError::InvalidSize {
                expected: ENCAPSULATION_KEY_SIZE_IN_BYTES,
                got: input.len(),
            })?;
    let ek = EncapsulationKey::new(&ek_bytes.into())
        .map_err(|_| DerecPairingError::MLKemEncapsulationError)?;

    let (ct, k_send) = ek.encapsulate_with_rng(rng);

    Ok((ct.to_vec(), k_send.into()))
}

/// Performs ML-KEM-1024 key decapsulation using the provided decapsulation key and ciphertext.
///
/// This function takes an encoded decapsulation key and a ciphertext, and recovers the shared secret
/// that was established during encapsulation. The ciphertext must have been generated using the
/// corresponding encapsulation key.
///
/// # Arguments
///
/// * `dk_encoded` - The decapsulation key as produced by [`generate_keypair`]: its
///   [`DECAPSULATION_KEY_SIZE_IN_BYTES`] (64) byte seed. A key in the expanded form
///   (3168 bytes), stored by a release before 0.0.8, is also accepted until 0.0.13.
/// * `ctxt` - The ciphertext as a byte slice or compatible type.
///   Must be exactly [`CIPHERTEXT_SIZE_IN_BYTES`] (1568) bytes.
///
/// # Returns
///
/// The shared secret as a `[u8; 32]`.
///
/// # Errors
///
/// Returns [`DerecPairingError::InvalidSize`] if `dk_encoded` is neither a seed nor an
/// expanded key, or `ctxt` is not exactly [`CIPHERTEXT_SIZE_IN_BYTES`] bytes.
/// Returns [`DerecPairingError::MLKemDecapsulationError`] if `dk_encoded` is an expanded
/// key that fails validation.
///
pub fn decapsulate(
    dk_encoded: impl AsRef<[u8]>,
    ctxt: impl AsRef<[u8]>,
) -> Result<SharedSecret, DerecPairingError> {
    let dk_input = dk_encoded.as_ref();
    let dk = match Seed::try_from(dk_input) {
        Ok(seed) => DecapsulationKey::from_seed(seed),
        Err(_) => from_expanded(dk_input)?,
    };

    let ct_input = ctxt.as_ref();
    let ct_array = Ciphertext::try_from(ct_input).map_err(|_| DerecPairingError::InvalidSize {
        expected: CIPHERTEXT_SIZE_IN_BYTES,
        got: ct_input.len(),
    })?;

    Ok(dk.decapsulate(&ct_array).into())
}

/// Rebuilds a decapsulation key stored in the expanded form by a release before 0.0.8.
#[allow(deprecated)]
fn from_expanded(bytes: &[u8]) -> Result<DecapsulationKey, DerecPairingError> {
    use ml_kem::ExpandedKeyEncoding;

    let expanded: [u8; EXPANDED_DECAPSULATION_KEY_SIZE_IN_BYTES] =
        bytes
            .try_into()
            .map_err(|_| DerecPairingError::InvalidSize {
                expected: DECAPSULATION_KEY_SIZE_IN_BYTES,
                got: bytes.len(),
            })?;

    #[cfg(feature = "logging")]
    tracing::warn!(
        "decapsulating an ML-KEM key stored in the expanded form before 0.0.8; \
         support for it is removed at 0.0.13"
    );

    DecapsulationKey::from_expanded_bytes(&expanded.into())
        .map_err(|_| DerecPairingError::MLKemDecapsulationError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        generate_keypair(&mut crate::random::os_rng())
    }

    #[test]
    fn test_encap_decap() {
        let mut rng = crate::random::os_rng();
        let (dk, ek) = keypair();
        let (ct, k_send) = encapsulate(&ek, &mut rng).unwrap();
        let k_recv = decapsulate(&dk, &ct).unwrap();
        assert_eq!(k_send, k_recv);
    }

    #[test]
    fn test_encapsulate_wrong_key_size_too_short() {
        let short_key = vec![0u8; ENCAPSULATION_KEY_SIZE_IN_BYTES - 1];
        let err = encapsulate(&short_key, &mut crate::random::os_rng())
            .expect_err("should fail with wrong-sized encapsulation key");
        assert!(
            matches!(
                err,
                DerecPairingError::InvalidSize {
                    expected: ENCAPSULATION_KEY_SIZE_IN_BYTES,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_encapsulate_wrong_key_size_too_long() {
        let long_key = vec![0u8; ENCAPSULATION_KEY_SIZE_IN_BYTES + 1];
        let err = encapsulate(&long_key, &mut crate::random::os_rng())
            .expect_err("should fail with oversized encapsulation key");
        assert!(matches!(
            err,
            DerecPairingError::InvalidSize {
                expected: ENCAPSULATION_KEY_SIZE_IN_BYTES,
                got,
            } if got == ENCAPSULATION_KEY_SIZE_IN_BYTES + 1
        ));
    }

    #[test]
    fn test_decapsulate_wrong_dk_size() {
        let (_, ek) = keypair();
        let (ct, _) = encapsulate(&ek, &mut crate::random::os_rng()).unwrap();

        let bad_dk = vec![0u8; DECAPSULATION_KEY_SIZE_IN_BYTES - 10];
        let err =
            decapsulate(&bad_dk, &ct).expect_err("should fail with wrong-sized decapsulation key");
        assert!(matches!(
            err,
            DerecPairingError::InvalidSize {
                expected: DECAPSULATION_KEY_SIZE_IN_BYTES,
                ..
            }
        ));
    }

    #[test]
    fn test_decapsulate_wrong_ciphertext_size() {
        let (dk, _) = keypair();
        let bad_ct = vec![0u8; CIPHERTEXT_SIZE_IN_BYTES + 5];
        let err = decapsulate(&dk, &bad_ct).expect_err("should fail with wrong-sized ciphertext");
        assert!(matches!(
            err,
            DerecPairingError::InvalidSize {
                expected: CIPHERTEXT_SIZE_IN_BYTES,
                got,
            } if got == CIPHERTEXT_SIZE_IN_BYTES + 5
        ));
    }

    #[test]
    fn test_decapsulate_wrong_ciphertext_returns_invalid_size_before_dk_check() {
        // Both inputs wrong — dk check runs first, should report dk size error.
        let bad_dk = vec![0u8; 1];
        let bad_ct = vec![0u8; 1];
        let err = decapsulate(&bad_dk, &bad_ct).expect_err("should fail");
        assert!(matches!(
            err,
            DerecPairingError::InvalidSize {
                expected: DECAPSULATION_KEY_SIZE_IN_BYTES,
                got: 1,
            }
        ));
    }

    #[test]
    fn test_invalid_size_error_message() {
        let err = DerecPairingError::InvalidSize {
            expected: 1568,
            got: 10,
        };
        assert_eq!(
            err.to_string(),
            "invalid input size: expected 1568 bytes, got 10"
        );
    }
}
