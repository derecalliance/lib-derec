// SPDX-License-Identifier: Apache-2.0

//! # Shared Types
//!
//! This module contains types that are shared across multiple DeRec protocol
//! flows implemented by this library (pairing, sharing, verification, and
//! recovery).
//!
//! These types represent identifiers or structures that must remain consistent
//! across the different modules in order to maintain protocol correctness.
//!
//! ## Channel identifiers
//!
//! A `ChannelId` uniquely identifies the secure communication channel between
//! an Owner and a Helper for a given pairing instance.
//!
//! The identifier is derived deterministically during the pairing process from
//! the initial `ContactMessage`. Because both parties compute it from the same
//! contact data, the resulting identifier is **symmetric** — both the Owner and
//! the Helper obtain the same value without additional coordination.
//!
//! Once established, the `ChannelId` is used by the library to associate:
//!
//! - protocol state
//! - stored shares
//! - verification messages
//! - recovery interactions
//!
//! with the correct peer relationship.

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
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
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
