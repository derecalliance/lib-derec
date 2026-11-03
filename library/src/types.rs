// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! # Cross-layer shared types
//!
//! Types used by both the primitives layer and the protocol layer. Anything
//! that's "post-pairing" or orchestrator-specific lives under
//! [`crate::protocol::types`] instead.
//!
//! ## Channel identifiers
//!
//! A [`ChannelId`] uniquely identifies the secure communication channel between
//! an Owner and a Helper for a given pairing instance.
//!
//! The identifier is derived deterministically during the pairing process from
//! the initial `ContactMessage`. Because both parties compute it from the same
//! contact data, the resulting identifier is **symmetric** — both the Owner and
//! the Helper obtain the same value without additional coordination.

/// Identifier of the secure communication channel between an Owner and a Helper.
///
/// A `ChannelId` is established during the pairing flow and uniquely identifies
/// the communication channel associated with a specific `(Owner, Helper, SecretId)`
/// relationship.
///
/// In the DeRec protocol, the `ChannelId` is deterministically derived from the
/// hash of the initial `ContactMessage`. Because both parties compute it from the
/// same contact data, the resulting identifier is **symmetric**, meaning that the
/// Owner and the Helper independently derive the same `ChannelId`.
///
/// This identifier is used internally by the library to associate protocol state
/// and messages with the correct peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct ChannelId(pub u64);

impl From<u64> for ChannelId {
    fn from(value: u64) -> Self {
        ChannelId(value)
    }
}

impl From<ChannelId> for u64 {
    fn from(value: ChannelId) -> Self {
        value.0
    }
}

impl PartialEq<u64> for ChannelId {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

/// A channel paired with the number of subshares it receives (its weight).
pub type WeightedChannel = (ChannelId, u32);

/// Stable per-device identity of a replica within a group.
///
/// Distinct from [`ChannelId`], which identifies a *channel*: every member of a
/// replica group shares one channel, so only this value tells them apart. It is
/// the primary key of a member row.
///
/// Assigned by the application, never minted or authenticated by the protocol.
/// It must be unique within a group and stable across restarts — a device that
/// regenerates its id becomes a different member, and its old entry is orphaned.
///
/// `0` is reserved: it is the absent-value sentinel on the wire, so a member
/// claiming it would be indistinguishable from one that never announced an
/// identity. [`TryFrom`] enforces this, which is the one deliberate divergence
/// from [`ChannelId`]'s infallible conversion — no construction path can
/// produce a zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct ReplicaId(pub u64);

impl TryFrom<u64> for ReplicaId {
    type Error = crate::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == 0 {
            return Err(crate::Error::InvalidInput(
                "replica_id 0 is reserved as the absent-value sentinel",
            ));
        }
        Ok(ReplicaId(value))
    }
}

impl From<ReplicaId> for u64 {
    fn from(value: ReplicaId) -> Self {
        value.0
    }
}

impl PartialEq<u64> for ReplicaId {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl std::fmt::Display for ReplicaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 32-byte symmetric key shared between an Owner and a Helper after pairing.
///
/// A `SharedKey` is established during the pairing flow and used to encrypt
/// and authenticate all subsequent protocol messages on the associated channel.
///
/// The bytes are wiped from memory when the key is dropped. The type is not
/// `Copy`, so a copy of the key exists only where [`Clone::clone`] makes one.
/// `Debug` prints no key material, and `==` compares in constant time.
///
/// Build one from its bytes with [`SharedKey::new`], `From<[u8; 32]>` or
/// `TryFrom<&[u8]>`, and read them with [`SharedKey::as_bytes`]: those are the only ways the bytes
/// cross into or out of the type, which is where a store or a binding moves
/// them.
///
/// With the `serde` feature, it serializes exactly as the `[u8; 32]` it wraps,
/// so a key persisted through serde reads back unchanged.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct SharedKey([u8; 32]);

impl SharedKey {
    /// Wrap the key's 32 bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key's 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for SharedKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<&[u8]> for SharedKey {
    type Error = std::array::TryFromSliceError;

    /// Read a key from bytes that must be exactly 32 long.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(bytes).map(Self)
    }
}

impl PartialEq for SharedKey {
    fn eq(&self, other: &Self) -> bool {
        subtle::ConstantTimeEq::ct_eq(&self.0[..], &other.0[..]).into()
    }
}

impl Eq for SharedKey {}

impl std::fmt::Debug for SharedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedKey(<redacted>)")
    }
}

/// A channel key together with its epoch, the key's position in the
/// channel's key chain.
///
/// A channel starts at epoch 0 under the key pairing established. When the
/// owner rotates keys, the chain moves forward one epoch at a time:
/// K₍ₑ₊₁₎ = `HMAC-SHA256(Kₑ, "derec channel key v1" ‖ be32(e+1))`. The chain
/// only runs forward, so a key does not reveal the ones before it.
///
/// Every channel envelope carries the epoch of the key that encrypted it in
/// `DeRecMessage.sequence`, which tells the receiver which key opens it.
/// Encrypting under a `ChannelKey` stamps that epoch, so key and epoch cannot
/// drift apart in the envelope. Build a key with [`ChannelKey::new`] from a
/// key and the epoch it belongs to, and move it forward with
/// [`ChannelKey::derive`]; a key paired with the wrong epoch produces
/// envelopes the peer cannot open.
///
/// `Debug` prints no key material.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChannelKey {
    pub(crate) epoch: u32,
    pub(crate) key: SharedKey,
}

impl ChannelKey {
    /// The most epochs [`ChannelKey::derive`] moves a key in one call. It
    /// matches how far a party following the protocol derives to open a
    /// message, which bounds the work a forged `sequence` can cause.
    pub const MAX_DERIVE_STEPS: u32 = crate::protocol::FORWARD_JUMP_LIMIT;

    /// Pair `key` with the epoch it belongs to. A freshly paired channel's
    /// key is at epoch 0.
    pub const fn new(epoch: u32, key: SharedKey) -> Self {
        Self { epoch, key }
    }

    /// The key's epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The key itself.
    pub fn key(&self) -> &SharedKey {
        &self.key
    }

    /// The key at `epoch`, derived forward from this one.
    ///
    /// # Errors
    ///
    /// [`crate::Error::InvalidInput`] if `epoch` is below this key's epoch,
    /// since the chain does not run backward, or more than
    /// [`ChannelKey::MAX_DERIVE_STEPS`] above it.
    pub fn derive(&self, epoch: u32) -> crate::Result<ChannelKey> {
        let Some(steps) = epoch.checked_sub(self.epoch) else {
            return Err(crate::Error::InvalidInput(
                "a channel key derives forward only",
            ));
        };
        if steps > Self::MAX_DERIVE_STEPS {
            return Err(crate::Error::InvalidInput(
                "a channel key derives at most MAX_DERIVE_STEPS epochs at once",
            ));
        }
        Ok(ChannelKey {
            epoch,
            key: crate::protocol::derive_key(&self.key, self.epoch, epoch),
        })
    }
}

#[cfg(test)]
mod replica_id_tests {
    use super::ReplicaId;

    /// `0` is the wire's absent-value sentinel, so a member can never claim
    /// it — otherwise it would be indistinguishable from a member that
    /// announced no identity at all.
    #[test]
    fn zero_is_rejected() {
        assert!(ReplicaId::try_from(0u64).is_err());
    }

    #[test]
    fn non_zero_round_trips() {
        let id = ReplicaId::try_from(1002u64).expect("1002 is a valid replica id");
        assert_eq!(u64::from(id), 1002);
        assert_eq!(id, 1002u64);
    }
}

#[cfg(test)]
mod shared_key_tests {
    use super::SharedKey;

    /// The key is wiped when it is dropped.
    #[test]
    fn a_key_is_zeroized_on_drop() {
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<SharedKey>();
    }

    /// `Debug` prints no key byte.
    #[test]
    fn debug_prints_no_key_material() {
        let rendered = format!("{:?}", SharedKey::new([0xAB; 32]));
        assert_eq!(rendered, "SharedKey(<redacted>)");
    }

    /// Keys compare by their bytes.
    #[test]
    fn keys_compare_by_their_bytes() {
        assert_eq!(SharedKey::new([1; 32]), SharedKey::from([1; 32]));
        let mut other = [1; 32];
        other[31] = 2;
        assert_ne!(SharedKey::new([1; 32]), SharedKey::new(other));
    }

    /// Only exactly 32 bytes read as a key.
    #[test]
    fn a_key_is_read_only_from_32_bytes() {
        assert_eq!(
            SharedKey::try_from([7u8; 32].as_slice()).expect("32 bytes"),
            SharedKey::new([7; 32])
        );
        assert!(SharedKey::try_from([7u8; 31].as_slice()).is_err());
        assert!(SharedKey::try_from([7u8; 33].as_slice()).is_err());
    }

    /// A key serializes exactly as the `[u8; 32]` it wraps, so a key stored
    /// through serde before the type existed reads back unchanged.
    #[cfg(feature = "serde")]
    #[test]
    fn a_key_serializes_as_its_bytes() {
        let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
        let as_array = serde_json::to_string(&bytes).expect("serialize array");
        let as_key = serde_json::to_string(&SharedKey::new(bytes)).expect("serialize key");
        assert_eq!(as_key, as_array);
        let read: SharedKey = serde_json::from_str(&as_array).expect("deserialize");
        assert_eq!(read, SharedKey::new(bytes));
    }
}

#[cfg(test)]
mod channel_key_tests {
    use super::{ChannelKey, SharedKey};

    const K0: ChannelKey = ChannelKey::new(0, SharedKey::new([3u8; 32]));

    /// Deriving one epoch at a time and deriving straight to the target
    /// reach the same key: the chain has one key per epoch.
    #[test]
    fn derive_walks_the_chain_one_epoch_at_a_time() {
        let mut stepped = K0.clone();
        for epoch in 1..=5 {
            stepped = stepped.derive(epoch).expect("one step forward");
        }
        let direct = K0.derive(5).expect("five steps forward");

        assert_eq!(direct, stepped);
        assert_eq!(direct.epoch(), 5);
        assert_ne!(direct.key(), K0.key());
    }

    #[test]
    fn derive_to_its_own_epoch_is_the_same_key() {
        assert_eq!(K0.derive(0).expect("no steps"), K0);
    }

    #[test]
    fn derive_refuses_an_earlier_epoch() {
        let k3 = K0.derive(3).expect("forward");
        assert!(matches!(k3.derive(2), Err(crate::Error::InvalidInput(_))));
    }

    #[test]
    fn derive_is_bounded_by_max_derive_steps() {
        assert!(K0.derive(ChannelKey::MAX_DERIVE_STEPS).is_ok());
        assert!(matches!(
            K0.derive(ChannelKey::MAX_DERIVE_STEPS + 1),
            Err(crate::Error::InvalidInput(_))
        ));
    }

    #[test]
    fn debug_prints_no_key_material() {
        let rendered = format!("{:?}", ChannelKey::new(4, SharedKey::new([0xAB; 32])));
        assert!(!rendered.contains("171") && !rendered.to_lowercase().contains("ab, "));
        assert!(rendered.contains("epoch: 4"));
    }
}
