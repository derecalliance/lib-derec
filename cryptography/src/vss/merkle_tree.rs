// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use rand::CryptoRng;
use sha2::{Digest, Sha256};

use super::Subshare;
use super::types::MerklePath;

/// Levels below the root. Every tree has `2^MERKLE_TREE_DEPTH` leaves and every
/// proof has exactly this many siblings, whatever the number of shares.
pub const MERKLE_TREE_DEPTH: u32 = 7;

/// Commits to `leaves` (one per share) under a single tree, returning the root
/// and, in the same order as `leaves`, each leaf's proof. Unused leaf slots are
/// padded from `rng`, so the root does not reveal how many shares there are.
pub fn commit<R: CryptoRng + ?Sized>(
    leaves: &[Vec<Subshare>],
    rng: &mut R,
) -> (Vec<u8>, Vec<MerklePath>) {
    let tree = build(leaves, rng);
    let proofs = extract_proofs(&tree, leaves.len() as u64);
    (tree[0].clone(), proofs)
}

/// The root a share's subshares open to along `path`, each step hashing the
/// running value with the sibling on the side the step names.
pub fn root_from_path(subshares: &[Subshare], path: &[(bool, Vec<u8>)]) -> Vec<u8> {
    let mut on_path_hash = leaf_hash(subshares);
    for (is_left, sibling) in path {
        on_path_hash = if *is_left {
            node_hash(sibling, &on_path_hash)
        } else {
            node_hash(&on_path_hash, sibling)
        };
    }
    on_path_hash
}
/// A leaf commits to a share's subshares, in order:
///
/// ```text
/// SHA-256(0x00 ‖ u64_be(k) ‖ for each subshare: u64_be(len(x)) ‖ x ‖ u64_be(len(y)) ‖ y)
/// ```
///
/// where `k` is the number of subshares. The `0x00` tag keeps leaf hashes apart
/// from internal-node hashes, so an internal node cannot be presented as a
/// share, and the count and lengths fix where every coordinate begins and ends.
pub fn leaf_hash(subshares: &[Subshare]) -> Vec<u8> {
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
// builds a 2-ary merkle tree with one leaf per share, each leaf
// committing to that share's subshare list. The tree always has
// MERKLE_TREE_DEPTH levels, even though we may not have that many
// shares. This is to avoid leaking the number of shares to the attacker.
fn build<R: CryptoRng + ?Sized>(shares: &[Vec<Subshare>], rng: &mut R) -> Vec<Vec<u8>> {
    // merkle tree nodes are of type Vec<u8>,
    // though we know their size to be 32 bytes (SHA-256 output)
    let merkle_tree_size = (2_u32.pow(MERKLE_TREE_DEPTH + 1) - 1) as usize;
    let mut merkle_nodes: Vec<Vec<u8>> = Vec::new();
    //allocate space up front
    merkle_nodes.resize(merkle_tree_size, Vec::new());

    // let us compute the leaf nodes first
    // note that we want a complete binary tree,
    // so we pad with dummy (garbage) elements
    let num_leaf_nodes = 2_u32.pow(MERKLE_TREE_DEPTH) as usize;
    for i in 0..num_leaf_nodes {
        // root node is labelled 1; so, node labels go from 1 to 2^(MERKLE_TREE_DEPTH + 1) - 1
        let node_label = num_leaf_nodes + i;
        if i < shares.len() {
            // hash the share's subshares; node root's label starts at 1
            merkle_nodes[node_label - 1] = leaf_hash(&shares[i]);
        } else {
            // fill unused slots with leaf hashes of random bytes
            let mut rand = [0u8; 32];
            rng.fill_bytes(&mut rand);

            merkle_nodes[node_label - 1] = leaf_hash(&[Subshare {
                x: rand.to_vec(),
                y: Vec::new(),
            }]);
        }
    }

    //let us now compute the intermediate nodes of the merkle tree
    for height in (0..MERKLE_TREE_DEPTH).rev() {
        //from MERKLE_TREE_DEPTH - 1 down to 0
        let lo = 2_u32.pow(height) as usize;
        let hi = (2_u32.pow(height + 1) - 1) as usize;

        for node_label in lo..(hi + 1) {
            // from lo to hi
            let left_child_label = node_label * 2;
            let right_child_label = left_child_label + 1;

            //hash (left_child || right_child)
            merkle_nodes[node_label - 1] = node_hash(
                &merkle_nodes[left_child_label - 1],
                &merkle_nodes[right_child_label - 1],
            );
        }
    }

    merkle_nodes
}
// extract merkle proofs for first n leaves in a merkle tree of MERKLE_TREE_DEPTH
fn extract_proofs(tree: &[Vec<u8>], n: u64) -> Vec<MerklePath> {
    assert!(
        (tree.len() + 1) > 2 && ((tree.len() + 1) & (tree.len())) == 0,
        "merkle tree not a complete binary tree"
    );

    // even nodes' siblings are odd nodes, and vice versa
    let other_label = |x: usize| -> usize { if x.is_multiple_of(2) { x + 1 } else { x - 1 } };
    let is_left = |x: usize| -> bool { x.is_multiple_of(2) };

    let mut output: Vec<MerklePath> = Vec::new();

    let lo = tree.len() / 2 + 1; //label of lo node (e.g. 8)
    let hi = lo + (n as usize) - 1; // label of lo node (e.g. 15 if n = 8)

    // rust ranges are exclusive on the hi end
    for label in lo..(hi + 1) {
        // the merkle path should have MERKLE_TREE_DEPTH nodes
        let mut current_label = label;
        let mut merkle_path: MerklePath = Vec::new();

        for _ in 0..MERKLE_TREE_DEPTH {
            let sibling_label = other_label(current_label);
            merkle_path.push((is_left(sibling_label), tree[sibling_label - 1].clone()));
            current_label /= 2;
        }

        output.push(merkle_path);
    }

    output
}

/// An internal node is `SHA-256(0x02 ‖ left ‖ right)`; the `0x02` tag keeps it
/// apart from leaf hashes.
fn node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher_input = Vec::with_capacity(1 + left.len() + right.len());
    hasher_input.push(0x02);
    hasher_input.extend_from_slice(left);
    hasher_input.extend_from_slice(right);
    compute_sha256_hash(&hasher_input)
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
        let merkle_tree = build(&leaves, &mut crate::random::os_rng());
        assert_merkle_tree_wff(&merkle_tree);
    }

    #[test]
    fn test_padding_leaves_are_leaf_hashes() {
        use rand::SeedableRng as _;
        use rand::rngs::ChaCha20Rng;

        let leaves = vec![vec![subshare(&[1u8; 32], &[2u8; 32])]];
        let tree = build(&leaves, &mut ChaCha20Rng::from_seed([7u8; 32]));

        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let num_leaf_nodes = 2_usize.pow(MERKLE_TREE_DEPTH);
        for i in leaves.len()..num_leaf_nodes {
            let mut rand = [0u8; 32];
            rng.fill_bytes(&mut rand);
            assert_eq!(
                tree[num_leaf_nodes + i - 1],
                leaf_hash(&[subshare(&rand, &[])])
            );
        }
    }

    #[test]
    fn test_leaf_and_node_hashes_are_domain_separated() {
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        assert_ne!(
            leaf_hash(&[subshare(&left, &right)]),
            node_hash(&left, &right)
        );
    }

    #[test]
    fn test_leaf_hash_binds_the_split_between_x_and_y() {
        assert_ne!(
            leaf_hash(&[subshare(b"ab", b"c")]),
            leaf_hash(&[subshare(b"a", b"bc")])
        );
    }

    #[test]
    fn test_leaf_hash_binds_the_split_between_subshares() {
        assert_ne!(
            leaf_hash(&[subshare(b"a", b"bc"), subshare(b"d", b"e")]),
            leaf_hash(&[subshare(b"a", b"b"), subshare(b"cd", b"e")])
        );
    }

    #[test]
    fn test_leaf_hash_binds_subshare_order() {
        assert_ne!(
            leaf_hash(&[subshare(b"a", b"b"), subshare(b"c", b"d")]),
            leaf_hash(&[subshare(b"c", b"d"), subshare(b"a", b"b")])
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
            leaf_hash(&[subshare(b"ab", b"c"), subshare(b"d", b"")]),
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
                let expected_hash = node_hash(&tree[left_idx], &tree[right_idx]);

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
