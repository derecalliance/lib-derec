// SPDX-License-Identifier: Apache-2.0

//! # Replica Fingerprint
//!
//! Derives a 16-digit decimal fingerprint from a 32-byte AES-256 shared key.
//!
//! The fingerprint is used during Replica pairing to let both devices display
//! the same code so the user can visually confirm they are pairing with the
//! correct peer (similar to Bluetooth pairing).
//!
//! ## Algorithm
//!
//! 1. Compute `H = SHA-256(K)` where `K` is the 32-byte shared key.
//! 2. Split `H` into 16 consecutive 2-byte chunks.
//! 3. Interpret each chunk as a big-endian `u16`, then compute `digit = value % 10`.
//! 4. Format the 16 digits as `XXXX-XXXX-XXXX-XXXX`.

use sha2::{Digest, Sha256};

/// Derives a formatted fingerprint string from a 32-byte shared key.
///
/// Returns a `String` in the format `"XXXX-XXXX-XXXX-XXXX"` where each `X`
/// is a decimal digit derived from the SHA-256 hash of the key.
/// Derives a formatted fingerprint from a 32-byte shared key.
///
/// Returns a `String` in the format `"XXXX-XXXX-XXXX-XXXX"` where each `X`
/// is a decimal digit derived from the SHA-256 hash of the key.
pub fn fingerprint(shared_key: &[u8; 32]) -> String {
    let digits = compute_digits(shared_key);
    format!(
        "{}{}{}{}-{}{}{}{}-{}{}{}{}-{}{}{}{}",
        digits[0], digits[1], digits[2], digits[3],
        digits[4], digits[5], digits[6], digits[7],
        digits[8], digits[9], digits[10], digits[11],
        digits[12], digits[13], digits[14], digits[15],
    )
}

fn compute_digits(shared_key: &[u8; 32]) -> [u8; 16] {
    let hash = Sha256::digest(shared_key);
    let mut digits = [0u8; 16];

    for (i, chunk) in hash.chunks_exact(2).enumerate() {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]);
        digits[i] = (value % 10) as u8;
    }

    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_format() {
        let key = [0x42u8; 32];
        let fp = fingerprint(&key);
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.chars().filter(|&c| c == '-').count(), 3);
        for c in fp.chars() {
            assert!(c.is_ascii_digit() || c == '-');
        }
    }

    #[test]
    fn test_fingerprint_is_deterministic() {
        let key = [0x07u8; 32];
        assert_eq!(fingerprint(&key), fingerprint(&key));
    }

    #[test]
    fn test_different_keys_produce_different_fingerprints() {
        let a = fingerprint(&[0x01u8; 32]);
        let b = fingerprint(&[0x02u8; 32]);
        assert_ne!(a, b);
    }
}
