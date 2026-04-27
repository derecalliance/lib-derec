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
//!
//! Formatting the 16 digits into `XXXX-XXXX-XXXX-XXXX` is a protocol-layer
//! concern handled by `derec_library::protocol::format_fingerprint`.

use sha2::{Digest, Sha256};

/// Derives the raw 16-digit decimal fingerprint from a 32-byte shared key.
///
/// Each element of the returned array is a single decimal digit (`0..=9`).
/// For display formatting (`XXXX-XXXX-XXXX-XXXX`), use
/// `derec_library::protocol::format_fingerprint`.
pub fn fingerprint_digits(shared_key: &[u8; 32]) -> [u8; 16] {
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
    fn test_fingerprint_digits_length_and_range() {
        let key = [0x42u8; 32];
        let digits = fingerprint_digits(&key);
        assert_eq!(digits.len(), 16);
        for &d in &digits {
            assert!(d < 10, "digit {d} out of range");
        }
    }

    #[test]
    fn test_fingerprint_digits_is_deterministic() {
        let key = [0x07u8; 32];
        assert_eq!(fingerprint_digits(&key), fingerprint_digits(&key));
    }

    #[test]
    fn test_different_keys_produce_different_digits() {
        let a = fingerprint_digits(&[0x01u8; 32]);
        let b = fingerprint_digits(&[0x02u8; 32]);
        assert_ne!(a, b);
    }
}
