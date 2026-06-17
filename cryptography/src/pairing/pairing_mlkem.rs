// SPDX-License-Identifier: Apache-2.0

use kem::{Decapsulate, Encapsulate};
use ml_kem::array::ArrayN;
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params, kem};
use rand_core::CryptoRngCore;

use super::DerecPairingError;

type MlKem1024DecapsulationKey = kem::DecapsulationKey<MlKem1024Params>;
type MlKem1024EncapsulationKey = kem::EncapsulationKey<MlKem1024Params>;

pub const ENCAPSULATION_KEY_SIZE_IN_BYTES: usize = 1568;
pub const DECAPSULATION_KEY_SIZE_IN_BYTES: usize = 3168;
pub const CIPHERTEXT_SIZE_IN_BYTES: usize = 1568;

pub type SharedSecret = [u8; 32];

/// Generates a new ML-KEM-1024 key pair.
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
pub fn generate_keypair<R: CryptoRngCore>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    // Generate a (decapsulation key, encapsulation key) pair
    let (dk, ek) = MlKem1024::generate(rng);
    let ek_bytes = ek.as_bytes();
    let dk_bytes = dk.as_bytes();
    (dk_bytes.to_vec(), ek_bytes.to_vec())
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
/// if encapsulation fails.
///
pub fn encapsulate<R: CryptoRngCore>(
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
    let ek = MlKem1024EncapsulationKey::from_bytes(&ek_bytes.into());

    let (ct, k_send) = ek
        .encapsulate(rng)
        .map_err(|_| DerecPairingError::MLKemEncapsulationError)?;

    Ok((ct.0.to_vec(), k_send.0))
}

/// Performs ML-KEM-1024 key decapsulation using the provided decapsulation key and ciphertext.
///
/// This function takes an encoded decapsulation key and a ciphertext, and recovers the shared secret
/// that was established during encapsulation. The ciphertext must have been generated using the
/// corresponding encapsulation key.
///
/// # Arguments
///
/// * `dk_encoded` - The encoded decapsulation key as a byte slice or compatible type.
///   Must be exactly [`DECAPSULATION_KEY_SIZE_IN_BYTES`] (3168) bytes.
/// * `ctxt` - The ciphertext as a byte slice or compatible type.
///   Must be exactly [`CIPHERTEXT_SIZE_IN_BYTES`] (1568) bytes.
///
/// # Returns
///
/// The shared secret as a `[u8; 32]`.
///
/// # Errors
///
/// Returns [`DerecPairingError::InvalidSize`] if `dk_encoded` is not exactly
/// [`DECAPSULATION_KEY_SIZE_IN_BYTES`] bytes or `ctxt` is not exactly [`CIPHERTEXT_SIZE_IN_BYTES`] bytes.
/// Returns [`DerecPairingError::MLKemDecapsulationError`] if decapsulation fails.
///
pub fn decapsulate(
    dk_encoded: impl AsRef<[u8]>,
    ctxt: impl AsRef<[u8]>,
) -> Result<SharedSecret, DerecPairingError> {
    let dk_input = dk_encoded.as_ref();
    let dk_bytes: [u8; DECAPSULATION_KEY_SIZE_IN_BYTES] =
        dk_input
            .try_into()
            .map_err(|_| DerecPairingError::InvalidSize {
                expected: DECAPSULATION_KEY_SIZE_IN_BYTES,
                got: dk_input.len(),
            })?;
    let dk = MlKem1024DecapsulationKey::from_bytes(&dk_bytes.into());

    let ct_input = ctxt.as_ref();
    let ct_array = ArrayN::<u8, CIPHERTEXT_SIZE_IN_BYTES>::try_from(ct_input).map_err(|_| {
        DerecPairingError::InvalidSize {
            expected: CIPHERTEXT_SIZE_IN_BYTES,
            got: ct_input.len(),
        }
    })?;

    let k_recv = dk
        .decapsulate(&ct_array)
        .map_err(|_| DerecPairingError::MLKemDecapsulationError)?;

    Ok(k_recv.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        generate_keypair(&mut rand::thread_rng())
    }

    #[test]
    fn test_encap_decap() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = keypair();
        let (ct, k_send) = encapsulate(&ek, &mut rng).unwrap();
        let k_recv = decapsulate(&dk, &ct).unwrap();
        assert_eq!(k_send, k_recv);
    }

    #[test]
    fn test_encapsulate_wrong_key_size_too_short() {
        let short_key = vec![0u8; ENCAPSULATION_KEY_SIZE_IN_BYTES - 1];
        let err = encapsulate(&short_key, &mut rand::thread_rng())
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
        let err = encapsulate(&long_key, &mut rand::thread_rng())
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
        let (ct, _) = encapsulate(&ek, &mut rand::thread_rng()).unwrap();

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
