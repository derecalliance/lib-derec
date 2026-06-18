// SPDX-License-Identifier: Apache-2.0

//! Protocol-layer types.
//!
//! Everything in this module is "post-pairing" — the channel and store
//! shapes the orchestrator manages once a pair handshake completes. The
//! primitives layer never touches these (it operates on raw wire bytes
//! and the cross-layer [`crate::types::ChannelId`] / [`crate::types::SharedKey`]
//! aliases).
//!
//! Re-exported at [`crate::protocol`] for ergonomic access, so callers
//! can write `use derec_library::protocol::Channel;` rather than
//! `use derec_library::protocol::types::Channel;`.

use crate::types::ChannelId;
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::ContactMessage;
use serde::{Deserialize, Serialize};

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

/// Status of a channel in the protocol lifecycle.
///
/// Replica channels start as `Pending` after pairing completes and transition
/// to `Paired` once fingerprint verification succeeds. Helper/Owner channels
/// are `Paired` immediately after pairing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ChannelStatus {
    /// Channel is awaiting fingerprint verification (replica only).
    Pending,
    /// Channel is fully paired and ready for protocol messages.
    #[default]
    Paired,
}

/// A channel — the post-pairing representation of a peer.
///
/// Stored by [`crate::protocol::DeRecChannelStore`] and returned by its
/// `channels()` method.
///
/// `Serialize` / `Deserialize` are derived for the FFI and WASM bridges,
/// which ship channels to host languages as JSON over the language
/// boundary. Library consumers writing a Rust `DeRecChannelStore` see
/// only the typed value and never observe the serde representation;
/// the wire format is not part of the public API and may change
/// independently. `#[serde(default)]` annotations let bridges decode
/// legacy bytes that predate later-added fields without erroring.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// starting [`crate::protocol::DeRecFlow::Pairing`]. On the responder
    /// side, it is the peer's own `communication_info` extracted from the
    /// wire pair-request — the same map that surfaces in
    /// [`crate::protocol::DeRecEvent::PairingCompleted::peer_communication_info`].
    #[serde(default)]
    pub communication_info: std::collections::HashMap<String, String>,
    /// Lifecycle status. Messages on `Pending` channels are ignored.
    #[serde(default)]
    pub status: ChannelStatus,
    /// Unix timestamp (seconds) when the channel was created.
    #[serde(default)]
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
    /// `CommunicationInfo` during the pair handshake. `None` on
    /// Helper/Owner channels and as a defensive default on
    /// freshly-paired Replica channels where the peer did not advertise
    /// one.
    #[serde(default)]
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
    /// values, and copies it verbatim from [`Channel::communication_info`]
    /// at protect-time. A recovering owner who decodes the bag can use
    /// this to recognise each helper (e.g. by a `"name"` key the app set
    /// on pairing).
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

/// Snapshot of the user-facing secret contents persisted by
/// [`crate::protocol::DeRecUserSecretStore`] for one `secret_id`.
///
/// Written every time the application calls
/// `start(FlowKind::ProtectSecret)`; read by the pair-completion
/// auto-publish hook so a freshly-paired Helper or Replica receives the
/// current state without an explicit re-publish from the app.
#[derive(Clone, Debug, PartialEq)]
pub struct UserSecrets {
    /// Secret version this snapshot represents. Monotonically increasing
    /// per `secret_id` — the protocol bumps it on every publish.
    pub version: u32,
    /// User-facing secret entries. Same wire shape as
    /// [`Secret::secrets`].
    pub secrets: Vec<UserSecret>,
    /// Optional human-readable label for this version, forwarded to
    /// helpers in `StoreShareRequest.description`.
    pub description: Option<String>,
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

/// The protocol's `secret` — serialized into `DeRecSecret.secret_data`.
///
/// This is the actual payload that gets protobuf-encoded, then placed into
/// the `secret_data` bytes field of the canonical `DeRecSecret` protobuf
/// message before encryption and distribution. Matches the DeRec
/// specification's `secret` term (distinct from a `UserSecret` entry,
/// which is one application-defined item *inside* this struct).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Secret {
    /// Snapshot of all paired Helpers at the time of distribution.
    #[prost(message, repeated, tag = "1")]
    pub helpers: ::prost::alloc::vec::Vec<HelperInfo>,
    /// The user-facing secrets the Owner wishes to protect.
    #[prost(message, repeated, tag = "2")]
    pub secrets: ::prost::alloc::vec::Vec<UserSecret>,
    /// Snapshot of all paired Replica Destinations at the time of
    /// distribution. Always populated regardless of whether the
    /// distribution had any destination targets — provides a stable
    /// shape across all paths.
    #[prost(message, repeated, tag = "3")]
    pub replicas: ::prost::alloc::vec::Vec<ReplicaInfo>,
    /// The `replica_id` of the device that created or last updated this
    /// version of the secret. Used by Destinations to attribute origin
    /// and will drive future conflict-resolution logic.
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
/// `ProtectSecret` round. Carries the full [`Secret`] plus the map of
/// `(channel_id → committed_share)` for the same round, so the
/// Destination can recover via either path — read the secret directly,
/// or contact each helper using `secret.helpers[i].shared_key` and
/// request their stored share.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplicaSecretPayload {
    /// The full secret the Source is committing to this version.
    #[prost(message, optional, tag = "1")]
    pub secret: ::core::option::Option<Secret>,
    /// One entry per helper that received a VSS share on this round.
    #[prost(message, repeated, tag = "2")]
    pub shares: ::prost::alloc::vec::Vec<ChannelShare>,
}

/// Kind of secret material stored by [`crate::protocol::DeRecSecretStore`].
///
/// Each variant has its own lifecycle (see per-variant docs). Used as the
/// `kind` argument to [`crate::protocol::DeRecSecretStore::load`] and
/// [`crate::protocol::DeRecSecretStore::remove`]; on
/// [`crate::protocol::DeRecSecretStore::save`] the kind is inferred from
/// the [`SecretValue`] variant and need not be passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// The post-pairing symmetric channel key (see [`SecretValue::SharedKey`]).
    SharedKey = 0,
    /// The ephemeral ECIES / ML-KEM key material used during pairing.
    PairingSecret = 1,
    /// The initiator's [`ContactMessage`] stored transiently between
    /// `start` and pairing completion. Removed once the shared key
    /// is derived.
    PairingContact = 2,
}

/// How [`crate::protocol::DeRecSecretStore::load_many`] handles channels
/// with no stored secret of the requested [`SecretKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingPolicy {
    /// Silently drop missing channels from the returned vector.
    ///
    /// Use when missing entries are an expected outcome — e.g. a `Target::Many`
    /// list that mixes paired and unpaired channels.
    Skip,
    /// Return [`crate::protocol::SecretStoreError::MissingEntries`] carrying
    /// the channel ids that had no entry.
    ///
    /// Use when every input id is expected to have an entry — e.g. after
    /// filtering to channels already known to
    /// [`crate::protocol::DeRecChannelStore`]. A miss signals a cross-store
    /// invariant violation.
    Fail,
}

/// The payload returned by [`crate::protocol::DeRecSecretStore::load`] and
/// passed to [`crate::protocol::DeRecSecretStore::save`].
///
/// Variants are 1:1 with [`SecretKind`].
pub enum SecretValue {
    /// The post-pairing symmetric channel key. Established by pairing and used
    /// to authenticate and encrypt every subsequent message on the channel.
    SharedKey(crate::types::SharedKey),
    /// The ephemeral ECIES / ML-KEM key pair created by `start` and consumed
    /// when the pairing response arrives. Removed once the shared key is
    /// derived.
    PairingSecret(PairingSecretKeyMaterial),
    /// The initiator's [`ContactMessage`], needed by
    /// [`crate::primitives::pairing::response::process`] to derive the shared
    /// key. Ephemeral — removed after pairing completes.
    PairingContact(ContactMessage),
}

/// A single stored share entry, fully self-describing.
#[derive(Debug, Clone)]
pub struct Share {
    /// Numeric identifier of the secret this share belongs to.
    pub secret_id: u64,
    /// Version number of the secret.
    pub version: u32,
    /// Stable per-device identifier of the replica that produced this
    /// share, copied from
    /// [`derec_proto::StoreShareRequestMessage::replica_id`] when the
    /// helper persisted the write.
    ///
    /// `None` when the writer was a non-replica `Owner`. `Some(id)` when
    /// the writer was `ReplicaSource`. Two distinct replicas may produce
    /// the same `(secret_id, channel_id, version)` independently
    /// — see [`crate::protocol::DeRecShareStore::save`] for the
    /// conceptual storage key and the disambiguation contract.
    pub replica_id: Option<u64>,
    /// Opaque protobuf bytes — see [`crate::protocol::DeRecShareStore`] for
    /// the per-side format.
    pub bytes: Vec<u8>,
}

