// SPDX-License-Identifier: Apache-2.0

use kem::{Decapsulate, Encapsulate};
use ml_kem::array::ArrayN;
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params, kem};
use rand_core::CryptoRngCore;

use super::DerecPairingError;

type MlKem1024DecapsulationKey = kem::DecapsulationKey<MlKem1024Params>;
type MlKem1024EncapsulationKey = kem::EncapsulationKey<MlKem1024Params>;

/// Size in bytes of the `EncapsulationKey`.
pub const ENCAPSULATION_KEY_SIZE: usize = 1568;
/// Size in bytes of the `DecapsulationKey`.
pub const DECAPSULATION_KEY_SIZE: usize = 3168;
/// Size in bytes of the `Ciphertext`.
pub const CIPHERTEXT_SIZE: usize = 1568;

/// Shared secret key.
pub type SharedSecret = [u8; 32];

/// Generates a new ML-KEM-1024 key pair for encapsulation and decapsulation.
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
pub fn generate_encapsulation_key<R: CryptoRngCore>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
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
/// * `rng` - A mutable reference to a cryptographically secure random number generator.
///
/// # Returns
///
/// A tuple containing:
/// - The ciphertext as a `Vec<u8>`.
/// - The shared secret as a `[u8; 32]`.
///
pub fn encapsulate<R: CryptoRngCore>(
    ek_encoded: impl AsRef<[u8]>,
    rng: &mut R,
) -> Result<(Vec<u8>, SharedSecret), DerecPairingError> {
    let ek = MlKem1024EncapsulationKey::from_bytes(
        &as_array::<ENCAPSULATION_KEY_SIZE>(ek_encoded)
            .unwrap()
            .into(),
    );

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
/// * `ctxt` - The ciphertext as a byte slice or compatible type.
///
/// # Returns
///
/// The shared secret as a `[u8; 32]`.
///
pub fn decapsulate(
    dk_encoded: impl AsRef<[u8]>,
    ctxt: impl AsRef<[u8]>,
) -> Result<SharedSecret, DerecPairingError> {
    let dk = MlKem1024DecapsulationKey::from_bytes(
        &as_array::<DECAPSULATION_KEY_SIZE>(dk_encoded)
            .unwrap()
            .into(),
    );

    let k_recv = dk
        .decapsulate(&ArrayN::<u8, CIPHERTEXT_SIZE>::try_from(ctxt.as_ref()).unwrap())
        .map_err(|_| DerecPairingError::MLKemDecapsulationError)?;

    Ok(k_recv.0)
}

fn as_array<const N: usize>(input: impl AsRef<[u8]>) -> Option<[u8; N]> {
    if input.as_ref().len() != N {
        None
    } else {
        let mut array = [0u8; N];
        array.copy_from_slice(input.as_ref());
        Some(array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encap_decap() {
        let mut rng = rand::thread_rng();
        let (dk, ek) = generate_encapsulation_key(&mut rng);
        let (ct, k_send) = encapsulate(&ek, &mut rng).unwrap();
        let k_recv = decapsulate(&dk, &ct).unwrap();
        assert_eq!(k_send, k_recv);
    }
}
