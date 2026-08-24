// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The `Secret` data model: the roster, user secrets, and replica group that
//! make up a recoverable secret. These are `prost` messages; their recoverable
//! JSON encoding lives in the sibling `codec`/`versions` modules.

/// Per-helper metadata stored inside the secret for recovery.
///
/// Each entry records the pairing state of a Helper so that recovery can
/// re-establish communication channels without external configuration.
/// In the recoverable JSON encoding (see [`crate::protocol::types::secret`]), `shared_key` serializes as
/// base64 and `channel_id` as a decimal string.
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
    /// values, and copies it verbatim from [`crate::protocol::types::HelperChannel::communication_info`]
    /// at protect-time. A recovering owner who decodes the secret can use
    /// this to recognise each helper (e.g. by a `"name"` key the app set
    /// on pairing).
    ///
    /// **Wire stability**: the now-removed `name: String` was previously at
    /// tag 3. Using tag 5 lets prost silently drop the old `name` field
    /// when decoding legacy encoded secrets (empty `communication_info`), and lets
    /// older codebases silently drop this new field when decoding newly
    /// encoded secrets. Degraded but not broken in either direction.
    #[prost(map = "string, string", tag = "5")]
    pub communication_info:
        ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
}

/// A single user-facing secret within the [`Secret`].
///
/// The Owner can store multiple logical secrets (credentials, keys, notes)
/// inside a single [`Secret`]. Each `UserSecret` is independently
/// identifiable so the application can present, add, or remove individual
/// entries while the protocol treats the entire [`Secret`] as one opaque blob.
/// In the recoverable JSON encoding (see [`crate::protocol::types::secret`]), `id` and `data` serialize as
/// base64.
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

/// One member of the replica group, as carried inside the [`Secret`].
///
/// Mirrors [`crate::protocol::types::ReplicaMember`] minus the group-level
/// fields: `channel_id` and the group key live on [`Replicas`], because every
/// member shares them. In the recoverable JSON encoding (see
/// [`crate::protocol::types::secret`]) `replica_id` serializes as a decimal
/// string and `role` as its variant name.
///
/// The roster is **absolute**: `role` is what this member is within the group,
/// not what it is relative to whoever is reading. A device that has only paired
/// and not yet hydrated may hold a provisional role for its admitter; the
/// roster overwrites it. See [`crate::protocol::types::ReplicaRole`].
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplicaInfo {
    /// The member's `replica_id` — its global stable identity, and the key it
    /// is stored under.
    #[prost(uint64, tag = "1")]
    pub replica_id: u64,
    /// The member's message endpoint URI.
    #[prost(string, tag = "2")]
    pub transport_uri: ::prost::alloc::string::String,
    /// The member's [`crate::protocol::types::ReplicaRole`] discriminant.
    /// Exactly one member of a group carries `Source`.
    #[prost(int32, tag = "3")]
    pub role: i32,
    /// App-level identity metadata for this member. Same opacity contract
    /// as [`HelperInfo::communication_info`].
    #[prost(map = "string, string", tag = "4")]
    pub communication_info:
        ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
}

/// The protocol's `secret` — serialized into `DeRecSecret.secret_data`.
///
/// This struct is the recoverable secret. Its wire form placed into
/// the `secret_data` bytes field of the canonical `DeRecSecret` protobuf
/// message is gzip-compressed JSON, not protobuf — see
/// [`crate::protocol::types::secret`] for the
/// normative field-level encoding and the mandatory JSON → gzip pipeline.
/// (The struct also derives `prost::Message` because the same data model
/// is nested, unchanged and still protobuf-encoded, inside
/// [`crate::protocol::types::ReplicaSecretPayload`] for replica synchronization.)
/// Matches the DeRec specification's `secret` term (distinct from a
/// `UserSecret` entry, which is one application-defined item *inside*
/// this struct).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Secret {
    /// Snapshot of all paired Helpers at the time of distribution.
    #[prost(message, repeated, tag = "1")]
    pub helpers: ::prost::alloc::vec::Vec<HelperInfo>,
    /// The user-facing secrets the Owner wishes to protect.
    #[prost(message, repeated, tag = "2")]
    pub secrets: ::prost::alloc::vec::Vec<UserSecret>,
    /// Replica composite: the destination peers, the per-helper share
    /// map, and the group key. `None` when this `secret_id` has no
    /// replica setup. See [`Replicas`] for field semantics.
    #[prost(message, optional, tag = "3")]
    pub replicas: ::core::option::Option<Replicas>,
}

/// The replica group carried inside [`Secret`] — the full member roster plus
/// the two things every member shares: one `channel_id` and one group key.
///
/// The roster includes the **source and the reader itself**. A group whose
/// members cannot name themselves is not reconstructible from the payload, so
/// omitting any member — including the writer — is a defect, not an
/// optimization.
///
/// The per-helper share map is *not* part of this composite: VSS
/// shares are derived from the encoded `Secret` (see
/// [`crate::protocol::types::secret`]) and so
/// cannot be embedded inside the `Secret` itself. The wire-level share map
/// rides on [`crate::protocol::types::ReplicaSecretPayload`] alongside the encoded `Secret`
/// instead.
///
/// `shared_key` must be 32 bytes when [`Self::members`] is
/// non-empty. The library enforces this invariant on the producer
/// side during sharing round construction and on the consumer side in
/// [`crate::protocol::DeRecProtocol::restore`].
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Replicas {
    /// Every member of the group, including the source and the writer.
    #[prost(message, repeated, tag = "1")]
    pub members: ::prost::alloc::vec::Vec<ReplicaInfo>,
    /// 32-byte replica group key.
    #[prost(bytes = "vec", tag = "2")]
    pub shared_key: ::prost::alloc::vec::Vec<u8>,
    /// The one channel every member is addressed on.
    #[prost(uint64, tag = "3")]
    pub channel_id: u64,
}
