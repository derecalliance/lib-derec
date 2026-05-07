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

/// 32-byte symmetric key shared between an Owner and a Helper after pairing.
///
/// A `SharedKey` is established during the pairing flow and used to encrypt
/// and authenticate all subsequent protocol messages on the associated channel.
pub type SharedKey = [u8; 32];

/// Selects which channels to target for a discovery request.
#[derive(Debug, Clone)]
pub enum Target {
    /// Send to all paired channels (most common case).
    All,
    /// Send to a single channel.
    Single(ChannelId),
    /// Send to a specific set of channels.
    Many(Vec<ChannelId>),
}

// Post-pairing representation of a peer relationship. A `ContactMessage` is
// relevant only during pairing (it carries ephemeral keys and nonces). Once
// pairing completes the only fields that matter are the channel ID, the
// peer's transport endpoint, and an optional human-readable name.

/// Status of a channel in the protocol lifecycle.
///
/// Replica channels start as `Pending` after pairing completes and transition
/// to `Paired` once fingerprint verification succeeds. Helper/Owner channels
/// are `Paired` immediately after pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelStatus {
    /// Channel is awaiting fingerprint verification (replica only).
    Pending,
    /// Channel is fully paired and ready for protocol messages.
    Paired,
}

/// A channel — the post-pairing representation of a peer.
///
/// Stored by [`DeRecChannelStore`](crate::protocol::DeRecChannelStore) and
/// returned by its `channels()` method.
#[derive(Clone, Debug)]
pub struct Channel {
    /// Unique identifier for this channel.
    pub id: ChannelId,
    /// The peer's transport endpoint.
    pub transport: derec_proto::TransportProtocol,
    /// Human-readable name for the peer (may be empty).
    pub name: String,
    /// Lifecycle status. Messages on `Pending` channels are ignored.
    pub status: ChannelStatus,
    /// Unix timestamp (seconds) when the channel was created.
    pub created_at: u64,
}

/// Per-helper metadata stored inside the secret bag for recovery.
///
/// Each entry records the pairing state of a Helper so that recovery can
/// re-establish communication channels without external configuration.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HelperInfo {
    /// Unique channel identifier assigned during pairing.
    #[prost(uint64, tag = "1")]
    pub channel_id: u64,
    /// The Helper's message endpoint URI.
    #[prost(string, tag = "2")]
    pub transport_uri: ::prost::alloc::string::String,
    /// Human-readable memo for the Helper.
    #[prost(string, tag = "3")]
    pub name: ::prost::alloc::string::String,
    /// Symmetric key negotiated during pairing (32 bytes).
    #[prost(bytes = "vec", tag = "4")]
    pub shared_key: ::prost::alloc::vec::Vec<u8>,
}

/// A single user-facing secret within the bag.
///
/// The Owner can store multiple logical secrets (credentials, keys, notes)
/// inside a single secret bag. Each `UserSecret` is independently
/// identifiable so the application can present, add, or remove individual
/// entries while the protocol treats the entire bag as one opaque blob.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UserSecret {
    /// Application-defined identifier.
    #[prost(bytes = "vec", tag = "1")]
    pub id: ::prost::alloc::vec::Vec<u8>,
    /// Human-readable label.
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    /// Raw secret bytes.
    #[prost(bytes = "vec", tag = "3")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}

/// The secret bag — serialized into `DeRecSecret.secret_data`.
///
/// This is the actual payload that gets protobuf-encoded, then placed into
/// the `secret_data` bytes field of the canonical `DeRecSecret` protobuf
/// message before encryption and distribution.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SecretContainer {
    /// Snapshot of all paired Helpers at the time of distribution.
    #[prost(message, repeated, tag = "1")]
    pub helpers: ::prost::alloc::vec::Vec<HelperInfo>,
    /// The user-facing secrets the Owner wishes to protect.
    #[prost(message, repeated, tag = "2")]
    pub secrets: ::prost::alloc::vec::Vec<UserSecret>,
}
