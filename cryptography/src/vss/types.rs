// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The shares a split produces and the material it is derived from.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::λ;

/// One subshare: a Shamir `(x, y)` pair with `y = f(x)`, each coordinate a serialized field element.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Subshare {
    /// The x-coordinate; it identifies the subshare.
    pub x: Vec<u8>,
    /// The y-coordinate, `f(x)`.
    pub y: Vec<u8>,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VSSShare {
    /// The subshares this share carries, in the order the Merkle leaf commits to.
    pub subshares: Vec<Subshare>,
    /// AES encryption of the secret message
    pub encrypted_secret: Vec<u8>,
    /// Merkle-root commitment to all shares
    pub commitment: Vec<u8>,
    /// bottom-up Merkle authentication path.
    /// The `bool` denotes `is_left`, while the `Vec<u8>` is the SHA-256 hash.
    pub merkle_path: Vec<(bool, Vec<u8>)>,
}

/// A leaf's proof: its siblings from the leaf up to the root, each flagged
/// `true` when the sibling is the left child.
pub(super) type MerklePath = Vec<(bool, Vec<u8>)>;

/// What [`share`](super::share) derives from the message and entropy, each `λ` bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct SplitMaterial {
    /// The AES-256-GCM key that encrypts the message and is itself split.
    pub(super) key: [u8; λ],
    pub(super) nonce: [u8; λ],
    /// Seeds the Shamir polynomial and its x-coordinates.
    pub(super) subshare_seed: [u8; λ],
    /// Seeds the Merkle tree's padding leaves.
    pub(super) padding_seed: [u8; λ],
}
