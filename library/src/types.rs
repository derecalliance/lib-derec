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
    /// Application-level identity metadata for the peer on this channel.
    ///
    /// Free-form key/value pairs — the protocol treats this as opaque and
    /// never inspects keys or values. Anything an app wants to remember
    /// about *who* is on the other end (display name, account id, avatar
    /// URI, ...) lives here. App-level identity logic (e.g. auto-linking
    /// by display name) reads from this map; the protocol does not.
    ///
    /// On the initiator side, this is whatever the caller supplied when
    /// starting [`DeRecFlow::Pairing`](crate::protocol::DeRecFlow::Pairing).
    /// On the responder side, it is the peer's own `communication_info`
    /// extracted from the wire pair-request — the same map that surfaces
    /// in [`DeRecEvent::PairingCompleted::peer_communication_info`](crate::protocol::DeRecEvent::PairingCompleted).
    pub communication_info: std::collections::HashMap<String, String>,
    /// Lifecycle status. Messages on `Pending` channels are ignored.
    pub status: ChannelStatus,
    /// Unix timestamp (seconds) when the channel was created.
    pub created_at: u64,
    /// This node's role on this channel, fixed at pairing time.
    ///
    /// The orchestrator enforces flow directionality against this value: an
    /// `Owner` may initiate `ProtectSecret` / `VerifyShares` / `Discovery` /
    /// `RecoverSecret`; a `Helper` may not. Inbound messages are gated the
    /// other way around — a `StoreShareRequest` is only honored on a channel
    /// where this node is the `Helper`, and so on.
    pub role: derec_proto::SenderKind,
    /// The peer's replica identity, populated only when `role` is
    /// `ReplicaSource` or `ReplicaDestination`.
    ///
    /// Extracted from the peer's `derec.replica_id` entry in
    /// `CommunicationInfo` during the pair handshake (see #53). `None`
    /// on Helper/Owner channels and as a defensive default on
    /// freshly-paired Replica channels where the peer did not advertise
    /// one.
    pub replica_id: Option<u64>,
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
    /// Symmetric key negotiated during pairing (32 bytes).
    #[prost(bytes = "vec", tag = "4")]
    pub shared_key: ::prost::alloc::vec::Vec<u8>,
    /// App-level identity metadata for this helper. Free-form key/value
    /// pairs — the protocol treats it as opaque, never inspects keys or
    /// values, and copies it verbatim from
    /// [`Channel::communication_info`](Channel) at protect-time. A recovering
    /// owner who decodes the bag can use this to recognise each helper
    /// (e.g. by a `"name"` key the app set on pairing).
    ///
    /// **Wire stability**: the now-removed `name: String` was previously at
    /// tag 3. Using tag 5 lets prost silently drop the old `name` field
    /// when decoding legacy bags (empty `communication_info`), and lets
    /// older codebases silently drop this new field when decoding new
    /// bags. Degraded but not broken in either direction.
    #[prost(map = "string, string", tag = "5")]
    pub communication_info: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        ::prost::alloc::string::String,
    >,
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

/// Per-replica metadata stored inside the secret bag — mirrors
/// [`HelperInfo`] but for the replica role and carries the extra
/// `replica_id` + `sender_kind` fields needed by the replica recovery
/// model.
///
/// **Recovery transitivity**: the `shared_key` here is the symmetric key
/// the Source negotiated with this Destination during pairing. A
/// Destination that later needs to act on the Source's behalf (e.g. fetch
/// a fresher copy from another Destination) uses these `shared_key`s to
/// authenticate as the Source toward its peers. Any Destination is
/// effectively a recovery delegate for the Source.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplicaInfo {
    /// Channel identifier the Source uses to address this peer.
    #[prost(uint64, tag = "1")]
    pub channel_id: u64,
    /// The peer's message endpoint URI.
    #[prost(string, tag = "2")]
    pub transport_uri: ::prost::alloc::string::String,
    /// Symmetric key negotiated during the pair handshake (32 bytes).
    #[prost(bytes = "vec", tag = "3")]
    pub shared_key: ::prost::alloc::vec::Vec<u8>,
    /// App-level identity metadata for this peer. Same opacity contract
    /// as [`HelperInfo::communication_info`].
    #[prost(map = "string, string", tag = "4")]
    pub communication_info: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        ::prost::alloc::string::String,
    >,
    /// The peer's `replica_id` — global stable identity of the replica
    /// device, separate from the per-channel `channel_id`.
    #[prost(uint64, tag = "5")]
    pub replica_id: u64,
    /// Raw `SenderKind` value the peer played in this pair (typically
    /// `REPLICA_SOURCE` or `REPLICA_DESTINATION`). Carried for future
    /// conflict-resolution flows; not used by the protocol layer today.
    #[prost(int32, tag = "6")]
    pub sender_kind: i32,
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
    /// Snapshot of all paired Replica Destinations at the time of
    /// distribution. Always populated regardless of whether the
    /// distribution had any destination targets — provides a stable
    /// shape for the bag across all paths.
    #[prost(message, repeated, tag = "3")]
    pub replicas: ::prost::alloc::vec::Vec<ReplicaInfo>,
    /// The `replica_id` of the device that created or last updated this
    /// version of the bag. Used by Destinations to attribute origin and
    /// will drive future conflict-resolution logic.
    #[prost(uint64, tag = "4")]
    pub owner_replica_id: u64,
}

/// A single helper's share of the current secret bag — wire-pairs a
/// `channel_id` with the serialized `CommittedDeRecShare` bytes that
/// were sent to that helper. Part of [`ReplicaSecretPayload`].
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChannelShare {
    /// Channel id of the helper that holds this share.
    #[prost(uint64, tag = "1")]
    pub channel_id: u64,
    /// Serialized `CommittedDeRecShare` bytes — the same payload the
    /// helper received in their `StoreShareRequest`.
    #[prost(bytes = "vec", tag = "2")]
    pub committed_share: ::prost::alloc::vec::Vec<u8>,
}

/// The composite payload sent to each Replica Destination on a
/// `ProtectSecret` round. Carries the full vault (`SecretContainer`)
/// plus the map of `(channel_id → committed_share)` for the same round,
/// so the Destination can recover via either path — read the vault
/// directly, or contact each helper using `secret.helpers[i].shared_key`
/// and request their stored share.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplicaSecretPayload {
    /// The full secret bag the Source is committing to this version.
    #[prost(message, optional, tag = "1")]
    pub secret: ::core::option::Option<SecretContainer>,
    /// One entry per helper that received a VSS share on this round.
    #[prost(message, repeated, tag = "2")]
    pub shares: ::prost::alloc::vec::Vec<ChannelShare>,
}
