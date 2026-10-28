// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use sha2::{Digest, Sha256};

use super::{DerecVSSError, VSSShare, verify, λ};

// this function will be used to detect one of several possible errors:
// 1. inconsistent ciphertexts; 2. inconsistent commitments; 3. corrupted shares
pub fn detect_error(shares: &Vec<VSSShare>) -> Option<DerecVSSError> {
    // let's grab the ciphertext and commitment from some share
    // and check that all other shares have the same values
    let commitment = &shares[0].commitment;
    let encrypted_secret = &shares[0].encrypted_secret;

    for share in shares {
        if &share.commitment != commitment {
            return Some(DerecVSSError::InconsistentCommitments);
        }

        if &share.encrypted_secret != encrypted_secret {
            return Some(DerecVSSError::InconsistentCiphertexts);
        }

        // the shares agree on the root, so each must open to it
        if !verify(share) {
            return Some(DerecVSSError::CorruptShares);
        }
    }

    // none indicates no error detected
    None
}

// produces 4λ bits, where λ = 256
pub fn random_oracle(msg: &[u8], rand: &[u8], tag: &[u8]) -> [u8; 4 * λ] {
    let mut output: [u8; 4 * λ] = [0; 4 * λ];

    for i in 0..4 {
        // create a Sha256 object
        let mut hasher = Sha256::new();
        // H(msg || rand || tag)
        hasher.update(msg);
        hasher.update(rand);
        hasher.update(tag);
        hasher.update([i as u8; 1]); //counter as hash input

        // read hash digest and consume hasher
        let hash = hasher.finalize();
        output[i * λ..(i + 1) * λ].copy_from_slice(&hash);
    }

    output
}

#[cfg(test)]
mod tests {
    use crate::vss;
    use rand::Rng as _;

    #[test]
    fn test_vss_correctness() {
        // test if recovery on shares produces the shared secret

        let mut rng = crate::random::os_rng();

        let mut rand = [0u8; 32];
        rng.fill_bytes(&mut rand);

        let mut msg: [u8; 1024] = [0u8; 1024];
        rng.fill_bytes(&mut msg);

        let shares = vss::share(3, &[1; 5], &msg, &rand).unwrap();
        let recovered = vss::recover(&shares).unwrap();

        assert_eq!(msg, recovered[..]);
    }
}
