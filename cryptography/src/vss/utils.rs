// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use rand::CryptoRng;
use sha2::{Digest, Sha256};

use super::{DerecVSSError, MERKLE_TREE_DEPTH, Subshare, VSSShare, subshares_are_well_formed, λ};

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

        // now verify the Merkle path; it must reach from a leaf to the root
        if share.merkle_path.len() != MERKLE_TREE_DEPTH as usize {
            return Some(DerecVSSError::CorruptShares);
        }

        if !subshares_are_well_formed(&share.subshares) {
            return Some(DerecVSSError::CorruptShares);
        }

        // first compute hash of this share
        let mut on_path_hash = leaf_hash_pub(&share.subshares);

        for (is_left, node_hash) in share.merkle_path.iter() {
            on_path_hash = if *is_left {
                //sibling is on the left
                intermediate_hash(node_hash, &on_path_hash)
            } else {
                intermediate_hash(&on_path_hash, node_hash)
            }
        }

        //on_path_hash should equal the merkle root
        if &on_path_hash != commitment {
            return Some(DerecVSSError::CorruptShares);
        }
    }

    // none indicates no error detected
    None
}

// builds a 2-ary merkle tree with one leaf per share, each leaf
// committing to that share's subshare list. We will specify a depth
// of the tree, even though we may not have that many shares. This
// is to avoid leaking the number of shares to the attacker.
pub fn build_merkle_tree<R: CryptoRng + ?Sized>(
    shares: &[Vec<Subshare>],
    depth: u32,
    rng: &mut R,
) -> Vec<Vec<u8>> {
    // merkle tree nodes are of type Vec<u8>,
    // though we know their size to be 32 bytes (SHA-256 output)
    let merkle_tree_size = (2_u32.pow(depth + 1) - 1) as usize;
    let mut merkle_nodes: Vec<Vec<u8>> = Vec::new();
    //allocate space up front
    merkle_nodes.resize(merkle_tree_size, Vec::new());

    // let us compute the leaf nodes first
    // note that we want a complete binary tree,
    // so we pad with dummy (garbage) elements
    let num_leaf_nodes = 2_u32.pow(depth) as usize;
    for i in 0..num_leaf_nodes {
        // root node is labelled 1; so, node labels go from 1 to 2^(depth + 1) - 1
        let node_label = num_leaf_nodes + i;
        if i < shares.len() {
            // hash the share's subshares; node root's label starts at 1
            merkle_nodes[node_label - 1] = leaf_hash_pub(&shares[i]);
        } else {
            // fill unused slots with leaf hashes of random bytes
            let mut rand = [0u8; 32];
            rng.fill_bytes(&mut rand);

            merkle_nodes[node_label - 1] = leaf_hash_pub(&[Subshare {
                x: rand.to_vec(),
                y: Vec::new(),
            }]);
        }
    }

    //let us now compute the intermediate nodes of the merkle tree
    for height in (0..depth).rev() {
        //from depth - 1 down to 0
        let lo = 2_u32.pow(height) as usize;
        let hi = (2_u32.pow(height + 1) - 1) as usize;

        for node_label in lo..(hi + 1) {
            // from lo to hi
            let left_child_label = node_label * 2;
            let right_child_label = left_child_label + 1;

            //hash (left_child || right_child)
            merkle_nodes[node_label - 1] = intermediate_hash(
                &merkle_nodes[left_child_label - 1],
                &merkle_nodes[right_child_label - 1],
            );
        }
    }

    merkle_nodes
}

// extract merkle proofs for first n leaves in a merkle tree of input depth
pub fn extract_merkle_proofs(tree: &[Vec<u8>], depth: u32, n: u64) -> Vec<Vec<(bool, Vec<u8>)>> {
    assert!(
        (tree.len() + 1) > 2 && ((tree.len() + 1) & (tree.len())) == 0,
        "merkle tree not a complete binary tree"
    );

    // even nodes' siblings are odd nodes, and vice versa
    let other_label = |x: usize| -> usize { if x.is_multiple_of(2) { x + 1 } else { x - 1 } };
    let is_left = |x: usize| -> bool { x.is_multiple_of(2) };

    let mut output: Vec<Vec<(bool, Vec<u8>)>> = Vec::new();

    let lo = tree.len() / 2 + 1; //label of lo node (e.g. 8)
    let hi = lo + (n as usize) - 1; // label of lo node (e.g. 15 if n = 8)

    // rust ranges are exclusive on the hi end
    for label in lo..(hi + 1) {
        // the merkle path should have depth number of nodes
        let mut current_label = label;
        let mut merkle_path: Vec<(bool, Vec<u8>)> = Vec::new();

        for _ in 0..depth {
            let sibling_label = other_label(current_label);
            merkle_path.push((is_left(sibling_label), tree[sibling_label - 1].clone()));
            current_label /= 2;
        }

        output.push(merkle_path);
    }

    output
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

/// Public entry point for leaf hashing used by [`super::verify`].
///
/// A leaf commits to a share's subshares, in order:
///
/// ```text
/// SHA-256(0x00 ‖ u64_be(k) ‖ for each subshare: u64_be(len(x)) ‖ x ‖ u64_be(len(y)) ‖ y)
/// ```
///
/// where `k` is the number of subshares. The `0x00` tag keeps leaf hashes apart
/// from internal-node hashes, so an internal node cannot be presented as a
/// share, and the count and lengths fix where every coordinate begins and ends.
pub fn leaf_hash_pub(subshares: &[Subshare]) -> Vec<u8> {
    let len: usize = subshares.iter().map(|p| 16 + p.x.len() + p.y.len()).sum();
    let mut hasher_input = Vec::with_capacity(1 + 8 + len);
    hasher_input.push(0x00);
    hasher_input.extend_from_slice(&(subshares.len() as u64).to_be_bytes());
    for subshare in subshares {
        hasher_input.extend_from_slice(&(subshare.x.len() as u64).to_be_bytes());
        hasher_input.extend_from_slice(&subshare.x);
        hasher_input.extend_from_slice(&(subshare.y.len() as u64).to_be_bytes());
        hasher_input.extend_from_slice(&subshare.y);
    }
    compute_sha256_hash(&hasher_input)
}

/// Public entry point for intermediate hashing used by [`super::verify`].
///
/// An internal node is `SHA-256(0x02 ‖ left ‖ right)`; the `0x02` tag keeps it
/// apart from leaf hashes.
pub fn intermediate_hash_pub(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher_input = Vec::with_capacity(1 + left.len() + right.len());
    hasher_input.push(0x02);
    hasher_input.extend_from_slice(left);
    hasher_input.extend_from_slice(right);
    compute_sha256_hash(&hasher_input)
}

fn intermediate_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    intermediate_hash_pub(left, right)
}

fn compute_sha256_hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_merkle_tree_correctness() {
        let mut rng = crate::random::os_rng();

        let mut seed1 = [0u8; 32];
        rng.fill_bytes(&mut seed1);

        let mut seed2 = [0u8; 32];
        rng.fill_bytes(&mut seed2);

        let mut msg: [u8; 1024] = [0u8; 1024];
        rng.fill_bytes(&mut msg);

        let shares = vss::share(5, &[1; 7], &msg, &seed1).unwrap();
        let leaves: Vec<Vec<Subshare>> = shares.iter().map(|s| s.subshares.clone()).collect();
        let merkle_tree = build_merkle_tree(&leaves, 3, &mut crate::random::os_rng());
        assert_merkle_tree_wff(&merkle_tree);
    }

    #[test]
    fn test_padding_leaves_are_leaf_hashes() {
        use rand::SeedableRng as _;
        use rand::rngs::ChaCha20Rng;

        let depth = 2;
        let leaves = vec![vec![subshare(&[1u8; 32], &[2u8; 32])]];
        let tree = build_merkle_tree(&leaves, depth, &mut ChaCha20Rng::from_seed([7u8; 32]));

        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let num_leaf_nodes = 2_usize.pow(depth);
        for i in leaves.len()..num_leaf_nodes {
            let mut rand = [0u8; 32];
            rng.fill_bytes(&mut rand);
            assert_eq!(
                tree[num_leaf_nodes + i - 1],
                leaf_hash_pub(&[subshare(&rand, &[])])
            );
        }
    }

    #[test]
    fn test_leaf_and_intermediate_hashes_are_domain_separated() {
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        assert_ne!(
            leaf_hash_pub(&[subshare(&left, &right)]),
            intermediate_hash_pub(&left, &right)
        );
    }

    #[test]
    fn test_leaf_hash_binds_the_split_between_x_and_y() {
        assert_ne!(
            leaf_hash_pub(&[subshare(b"ab", b"c")]),
            leaf_hash_pub(&[subshare(b"a", b"bc")])
        );
    }

    #[test]
    fn test_leaf_hash_binds_the_split_between_subshares() {
        assert_ne!(
            leaf_hash_pub(&[subshare(b"a", b"bc"), subshare(b"d", b"e")]),
            leaf_hash_pub(&[subshare(b"a", b"b"), subshare(b"cd", b"e")])
        );
    }

    #[test]
    fn test_leaf_hash_binds_subshare_order() {
        assert_ne!(
            leaf_hash_pub(&[subshare(b"a", b"b"), subshare(b"c", b"d")]),
            leaf_hash_pub(&[subshare(b"c", b"d"), subshare(b"a", b"b")])
        );
    }

    #[test]
    fn test_leaf_hash_encoding() {
        let mut expected = vec![0x00];
        expected.extend_from_slice(&2u64.to_be_bytes());
        for (x, y) in [(&b"ab"[..], &b"c"[..]), (&b"d"[..], &b""[..])] {
            expected.extend_from_slice(&(x.len() as u64).to_be_bytes());
            expected.extend_from_slice(x);
            expected.extend_from_slice(&(y.len() as u64).to_be_bytes());
            expected.extend_from_slice(y);
        }
        assert_eq!(
            leaf_hash_pub(&[subshare(b"ab", b"c"), subshare(b"d", b"")]),
            compute_sha256_hash(&expected)
        );
    }

    fn subshare(x: &[u8], y: &[u8]) -> Subshare {
        Subshare {
            x: x.to_vec(),
            y: y.to_vec(),
        }
    }

    fn assert_merkle_tree_wff(tree: &[Vec<u8>]) {
        let n = tree.len() + 1; // n must be a power of 2
        assert!(
            n > 2 && (n & (n - 1)) == 0,
            "merkle tree not a complete binary tree"
        );
        let mut hi = n / 2 - 1; //label of hi node (e.g. 7)
        let mut lo = hi.div_ceil(2); // label of lo node (e.g. 4)

        loop {
            for node_label in lo..(hi + 1) {
                //we subtract 1 because root nodes are labelled 1 onwards
                let left_idx = node_label * 2 - 1;
                let right_idx = left_idx + 1;
                let expected_hash = intermediate_hash(&tree[left_idx], &tree[right_idx]);

                assert_eq!(&expected_hash, &tree[node_label - 1]);
            }

            //set the new lo and hi
            lo /= 2;
            hi /= 2;

            if lo == hi {
                return;
            } // we got to the root node
        }
    }
}
