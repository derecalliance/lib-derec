// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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

use crate::types::{ChannelId, ReplicaId};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::ContactMessage;
#[cfg(any(feature = "serde", target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::Zeroizing;

pub mod secret;
#[cfg(any(feature = "serde", target_arch = "wasm32"))]
pub mod state_record;

pub use secret::{HelperInfo, ReplicaInfo, Replicas, Secret, UserSecret};
#[cfg(any(feature = "serde", target_arch = "wasm32"))]
pub use state_record::{ReplicaDiscoveryReport, StateItemRecord, StateKeyRecord};

/// Selects which channels a flow targets.
#[derive(Debug, Clone)]
pub enum Target {
    /// Send to all paired channels (most common case).
    All,
    /// Send to a single channel.
    Single(ChannelId),
    /// Send to a specific set of channels.
    Many(Vec<ChannelId>),
}

impl Target {
    /// Narrow this target to the channels in `known`.
    ///
    /// A caller may name a channel this device never paired on, or one that
    /// has since been unpaired. Those ids are **dropped, not refused**: a
    /// target asks to reach whoever is reachable, and one stale id should
    /// not fail a fan-out to everyone else. A caller that needs to know an
    /// id went nowhere compares the returned length against what it asked
    /// for.
    ///
    /// Ordering differs by variant, deliberately:
    ///
    /// - [`Target::All`] and [`Target::Single`] follow `known`, which is the
    ///   order the channel store returned.
    /// - [`Target::Many`] follows the order the **caller** listed, so an
    ///   application that ranks its helpers keeps that ranking.
    pub fn filter(self, known: &[ChannelId]) -> Vec<ChannelId> {
        match self {
            Target::All => known.to_vec(),
            Target::Single(id) => known.iter().copied().filter(|k| *k == id).collect(),
            Target::Many(ids) => ids.into_iter().filter(|id| known.contains(id)).collect(),
        }
    }

    /// The ids this target names, for [`ChannelFilter::ids`]. Empty for
    /// [`Target::All`], which names none and so restricts nothing.
    ///
    /// Narrowing the listing by these does not replace [`Self::filter`]: the
    /// store decides which of them exist, `filter` decides the order they come
    /// back in.
    pub fn ids(&self) -> Vec<ChannelId> {
        match self {
            Target::All => Vec::new(),
            Target::Single(id) => vec![*id],
            Target::Many(ids) => ids.clone(),
        }
    }
}

/// Status of a channel in the protocol lifecycle.
///
/// A channel starts as `Pending` after pairing completes and transitions to
/// `Paired` once fingerprint verification succeeds. Two cases take that path:
///
/// - **Replica channels**, always. Admitting a second device to the group is
///   a human decision.
/// - **[`derec_proto::ContactMode::NoKeys`] channels**, whatever the kind.
///   That mode inlines neither the keys nor a commitment to them, so nothing
///   binds what the scanner received over the plaintext `PrePair` leg to the
///   contact delivered out of band. The fingerprint, derived from the
///   established shared key, is the only check that detects a substituted
///   key — it is to `NoKeys` what `contact_binding_hash` is to
///   [`derec_proto::ContactMode::HashedKeys`].
///
/// Helper/Owner channels paired over
/// [`derec_proto::ContactMode::InlineKeys`] or
/// [`derec_proto::ContactMode::HashedKeys`] are `Paired` immediately: the
/// contact carried the keys, or a commitment already verified against them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(Serialize, Deserialize)
)]
pub enum ChannelStatus {
    /// Channel is awaiting out-of-band fingerprint confirmation: every
    /// replica pairing, and every
    /// [`derec_proto::ContactMode::NoKeys`] pairing. Not a publish target,
    /// not a recovery source, and inbound messages on it are ignored.
    Pending,
    /// Channel is fully paired and ready for protocol messages.
    #[default]
    Paired,
    /// Replica member only: told to leave, awaiting the version that
    /// completes its removal. Never set on a helper channel.
    Unpairing,
}

/// Policy governing automatic removal of expired `Pending` channels.
///
/// [`crate::protocol::DeRecProtocol::process`] consults this on every
/// call. It does not affect
/// [`crate::protocol::DeRecProtocol::remove_expired_channels`], which
/// always sweeps at the threshold it is given — that is what makes
/// [`Self::Disabled`] mean "the application drives cleanup itself"
/// rather than "cleanup never happens".
///
/// Configured via
/// [`crate::protocol::types::Timeouts::expired_channels`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(Serialize, Deserialize)
)]
pub enum ExpiredChannelCleanup {
    /// No automatic sweep during `process()`. The application drives
    /// cleanup itself via
    /// [`crate::protocol::DeRecProtocol::remove_expired_channels`].
    Disabled,
    /// `process()` removes `Pending` channels older than this.
    Enabled { timeout_in_secs: u64 },
}

impl Default for ExpiredChannelCleanup {
    fn default() -> Self {
        Self::Enabled {
            timeout_in_secs: 300,
        }
    }
}

/// How long the protocol waits on each thing it can be kept waiting by.
///
/// These were one knob until it became clear they answer different questions.
/// [`inbound_message`](Self::inbound_message) is a **security** boundary — it
/// bounds how stale a message may be and still be accepted, so it has to
/// tolerate transport latency and clock skew. The other three are **liveness**
/// budgets: how long to keep hoping a peer will answer before giving up on it.
/// A value that suits one is wrong for the others, and collapsing them meant
/// tightening the replay window every time someone wanted rounds to settle
/// faster.
///
/// Unspecified fields keep their default:
///
/// ```
/// use derec_library::protocol::types::Timeouts;
/// use std::time::Duration;
///
/// let timeouts = Timeouts {
///     sharing_round: Duration::from_secs(30),
///     ..Default::default()
/// };
/// assert_eq!(timeouts.sharing_round, Duration::from_secs(30));
/// assert_eq!(timeouts.inbound_message, Duration::from_secs(300));
/// ```
///
/// # Granularity
///
/// **One second is the smallest effective unit.** Wire timestamps
/// (protobuf `Timestamp.seconds`) carry whole seconds only, so ages can be
/// measured no finer. Sub-second precision is truncated and any value below
/// one second is clamped to one, so an accidental [`Duration::ZERO`] cannot
/// silently disable a timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// Staleness boundary for **inbound envelopes**: any message whose
    /// timestamp is older than this is discarded on receipt, whatever the
    /// flow. This is the replay-defence window.
    ///
    /// Lower is not safer in any simple sense. The protocol is
    /// transport-agnostic — a store-and-forward transport, a phone that was
    /// offline, or a peer whose clock is a minute out all produce legitimately
    /// old messages, and this value is what decides whether they are refused.
    ///
    /// Default: **300 seconds**.
    pub inbound_message: Duration,
    /// How long a publishing round waits for a peer that has not answered.
    /// On expiry the silent helpers are failed, the silent members are
    /// reported behind, and the round closes.
    ///
    /// This is what bounds how long
    /// [`DeRecEvent::SharingComplete`](crate::protocol::events::DeRecEvent::SharingComplete)
    /// can be delayed by one unreachable peer, so it is the one to shorten if
    /// a stalled round should surface quickly.
    ///
    /// Default: **60 seconds**.
    pub sharing_round: Duration,
    /// How long to wait for a peer to acknowledge an unpair before dropping
    /// the local channel state anyway. Expiry only discards local state; the
    /// unpair itself was already sent.
    ///
    /// Default: **60 seconds**.
    pub unpair_ack: Duration,
    /// When to remove a channel still awaiting out-of-band fingerprint
    /// confirmation — every replica pairing, and every
    /// [`derec_proto::ContactMode::NoKeys`] pairing.
    ///
    /// Unlike the others this can be [`ExpiredChannelCleanup::Disabled`],
    /// leaving the sweep to the application. The budget is a **human** one:
    /// someone comparing a fingerprint out of band, possibly over the phone.
    /// Shortening it below a minute or so will strand real pairings.
    ///
    /// Default: `Enabled { timeout_in_secs: 300 }`.
    pub expired_channels: ExpiredChannelCleanup,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            inbound_message: Duration::from_secs(300),
            sharing_round: Duration::from_secs(60),
            unpair_ack: Duration::from_secs(60),
            expired_channels: ExpiredChannelCleanup::default(),
        }
    }
}

impl ExpiredChannelCleanup {
    /// Enable automatic cleanup with the given timeout.
    ///
    /// Performs no validation. A zero is clamped to one second by
    /// [`crate::protocol::types::Timeouts::expired_channels`],
    /// the single normalization point.
    pub fn from_secs(secs: u64) -> Self {
        Self::Enabled {
            timeout_in_secs: secs,
        }
    }

    /// Build a policy from the flat `(enabled, timeout_in_secs)` pair the
    /// FFI and WASM layers carry. When `enabled` is `false` the timeout is
    /// ignored and the result is [`Self::Disabled`].
    ///
    /// This is the marshalling seam for the SDKs: they forward both values
    /// verbatim and this function decides what they mean, so the rule is
    /// written and tested once rather than in every binding.
    pub fn new(enabled: bool, timeout_in_secs: u64) -> Self {
        if enabled {
            Self::Enabled { timeout_in_secs }
        } else {
            Self::Disabled
        }
    }
}

/// Which side of a replica pairing a member holds for one secret.
///
/// Exactly one member of a group is the [`Source`](Self::Source). This is a
/// property of *membership*, not of a channel: all members share one channel,
/// so the channel cannot carry it.
///
/// The value is **absolute**: every member records the same role for a given
/// peer, regardless of who is reading. One exception is bounded and
/// self-correcting — between pairing and the first sync, a joiner holds the
/// role its admitter presented (a device admitting a new member pairs as
/// `ReplicaSource` whether or not it is the group's source). The first roster
/// it hydrates overwrites that provisional value, after which the group again
/// names exactly one source. Nothing acts on the roles in that window: the
/// joiner cannot publish before it has a snapshot.
///
/// Serialization is unconditional rather than feature-gated: the role rides
/// inside the recoverable secret (see [`crate::protocol::types::secret`]),
/// which every build must encode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReplicaRole {
    /// Originated the secret. Exactly one member per group.
    Source,
    /// Holds a mirrored copy.
    Destination,
}

impl ReplicaRole {
    /// The role the peer holds, given this one.
    pub fn counterparty(self) -> Self {
        match self {
            ReplicaRole::Source => ReplicaRole::Destination,
            ReplicaRole::Destination => ReplicaRole::Source,
        }
    }

    /// Map from the discriminant carried by [`ReplicaInfo::role`], or `None`
    /// if it names no known role.
    ///
    /// [`ReplicaInfo::role`]: crate::protocol::types::ReplicaInfo::role
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            v if v == ReplicaRole::Source as i32 => Some(ReplicaRole::Source),
            v if v == ReplicaRole::Destination as i32 => Some(ReplicaRole::Destination),
            _ => None,
        }
    }

    /// Map from the wire `SenderKind`, or `None` for non-replica kinds.
    pub fn from_sender_kind(kind: derec_proto::SenderKind) -> Option<Self> {
        match kind {
            derec_proto::SenderKind::ReplicaSource => Some(ReplicaRole::Source),
            derec_proto::SenderKind::ReplicaDestination => Some(ReplicaRole::Destination),
            _ => None,
        }
    }

    /// Map to the wire `SenderKind`.
    pub fn to_sender_kind(self) -> derec_proto::SenderKind {
        match self {
            ReplicaRole::Source => derec_proto::SenderKind::ReplicaSource,
            ReplicaRole::Destination => derec_proto::SenderKind::ReplicaDestination,
        }
    }
}

/// A channel to a single helper, or to the owner from a helper's side.
///
/// Keyed by `(secret_id, channel_id)`. Also the record written while an
/// owner-helper pairing is still in flight — that flow is unchanged.
#[derive(Clone, Debug)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(Serialize, Deserialize)
)]
pub struct HelperChannel {
    pub channel_id: ChannelId,
    /// Every endpoint this peer advertised, in the order it offered them.
    ///
    /// The library never ranks these — it filters them through
    /// [`TransportPolicy`](crate::transport::TransportPolicy) and hands the
    /// survivors to [`DeRecTransport::send`](crate::protocol::DeRecTransport),
    /// which is the application's to choose among and fail over between.
    ///
    /// # Upgrading from a pre-0.0.3 channel store
    ///
    /// This replaced a single `transport` field, so a stored record written
    /// by an older build no longer deserializes. That is deliberate: the
    /// field carries no `serde(default)`, so a stale row fails loudly with
    /// a missing-field error instead of quietly yielding a channel with no
    /// endpoints — a peer that looks paired and is unreachable is worse than
    /// one that refuses to load. Applications own channel-store persistence;
    /// migrating a stored row means wrapping its `transport` object in an
    /// array.
    pub transports: Vec<derec_proto::TransportProtocol>,
    #[cfg_attr(any(feature = "serde", target_arch = "wasm32"), serde(default))]
    pub communication_info: std::collections::HashMap<String, String>,
    /// The **peer's** role: `Owner` when this node is the helper, `Helper`
    /// when this node is the owner.
    pub peer_role: derec_proto::SenderKind,
    #[cfg_attr(any(feature = "serde", target_arch = "wasm32"), serde(default))]
    pub status: ChannelStatus,
    #[cfg_attr(any(feature = "serde", target_arch = "wasm32"), serde(default))]
    pub created_at: u64,
}

/// One member of a replica group, including this device itself.
///
/// Keyed by `(secret_id, replica_id)`. Every member shares one `channel_id`,
/// so the channel cannot be the key. Storing this device's own row is what
/// makes the roster reconstructible from stores alone.
///
/// An initiating device writes its **own** row when it starts a replica
/// pairing — it knows its identity and role then, and the peer's role is the
/// counterpart. The peer's row follows once the response announces its id.
#[derive(Clone, Debug)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(Serialize, Deserialize)
)]
pub struct ReplicaMember {
    /// The group channel. Identical for every member.
    pub channel_id: ChannelId,
    /// This member's identity — the primary key within the group.
    pub replica_id: ReplicaId,
    /// Every endpoint this member advertised. See
    /// [`HelperChannel::transports`] for the ordering and compatibility
    /// contract.
    pub transports: Vec<derec_proto::TransportProtocol>,
    #[cfg_attr(any(feature = "serde", target_arch = "wasm32"), serde(default))]
    pub communication_info: std::collections::HashMap<String, String>,
    pub role: ReplicaRole,
    #[cfg_attr(any(feature = "serde", target_arch = "wasm32"), serde(default))]
    pub status: ChannelStatus,
    #[cfg_attr(any(feature = "serde", target_arch = "wasm32"), serde(default))]
    pub created_at: u64,
}

/// Addresses a single record in [`crate::protocol::DeRecChannelStore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelQuery {
    Helper {
        channel_id: ChannelId,
    },
    Replica {
        channel_id: ChannelId,
        replica_id: ReplicaId,
    },
}

impl ChannelQuery {
    pub fn channel_id(&self) -> ChannelId {
        match self {
            ChannelQuery::Helper { channel_id } => *channel_id,
            ChannelQuery::Replica { channel_id, .. } => *channel_id,
        }
    }
}

/// Narrows a listing from [`crate::protocol::DeRecChannelStore`].
///
/// Every field is a *restriction*, and every field's empty value means "do not
/// restrict on this" — so [`Default`] selects everything and is equivalent to
/// an unfiltered listing. Restrictions combine with AND, and `exclude` is
/// applied last, overriding `ids`.
///
/// # Apply it in the query, but the library re-checks
///
/// Applying the filter is the store's job precisely because the store is where
/// it can be pushed into a query — a `WHERE` clause, a key-condition
/// expression — instead of transferring rows the caller will discard. That
/// transfer is what the filter exists to avoid: it costs bandwidth everywhere,
/// and on a metered backing such as DynamoDB, which bills by bytes read, it
/// costs money.
///
/// **A store that ignores it is slow, not wrong.** The protocol acts on the
/// rows a listing returns — deleting some, flagging the member a by-id filter
/// named — so it re-applies the filter to every listing before using it, and
/// drops anything the filter excluded. That backstop matters most where the
/// signature cannot enforce itself: TypeScript accepts a function of fewer
/// parameters where more are declared, so a store written before this
/// parameter existed satisfies the current interface and compiles without a
/// diagnostic.
///
/// **It is a one-way guarantee, and not a validation of your store.** Dropping
/// rows can enforce an upper bound — nothing excluded gets through — but it
/// cannot recover a row you omitted. A store that returns *fewer* rows than
/// the filter selects is still wrong, and wrong in a way nothing here can
/// detect: the protocol simply fails to act. Applying the filter faithfully
/// remains the store's job; the library only declines to trust the result.
///
/// The listing methods state which record field each of `status`, `role` and
/// the id fields refers to.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(Serialize, Deserialize),
    serde(
        default,
        bound = "Role: Serialize + serde::de::DeserializeOwned, Id: Serialize + serde::de::DeserializeOwned"
    )
)]
pub struct ChannelFilter<Role, Id> {
    /// Restrict to these ids. Empty selects every record.
    pub ids: Vec<Id>,
    /// Restrict to these statuses. Empty selects any status.
    pub status: Vec<ChannelStatus>,
    /// Restrict to this role. `None` selects any role.
    pub role: Option<Role>,
    /// Omit these ids, applied after `ids`. Empty omits nothing.
    pub exclude: Vec<Id>,
}

impl<Role, Id> Default for ChannelFilter<Role, Id> {
    fn default() -> Self {
        Self {
            ids: Vec::new(),
            status: Vec::new(),
            role: None,
            exclude: Vec::new(),
        }
    }
}

impl<Role: PartialEq, Id: PartialEq> ChannelFilter<Role, Id> {
    /// Whether a record with these attributes survives the filter.
    ///
    /// A store whose backing cannot express the restrictions as a query can
    /// list and call this, which is correct but transfers the rows the filter
    /// was meant to leave behind.
    pub fn matches(&self, id: &Id, status: ChannelStatus, role: &Role) -> bool {
        (self.ids.is_empty() || self.ids.contains(id))
            && (self.status.is_empty() || self.status.contains(&status))
            && self.role.as_ref().is_none_or(|wanted| wanted == role)
            && !self.exclude.contains(id)
    }
}

/// Narrows [`crate::protocol::DeRecChannelStore::replicas`].
///
/// Ids are [`ReplicaMember::replica_id`] and the role is
/// [`ReplicaMember::role`].
pub type ReplicaFilter = ChannelFilter<ReplicaRole, ReplicaId>;

/// Narrows [`crate::protocol::DeRecChannelStore::helpers`].
///
/// Ids are [`HelperChannel::channel_id`] and the role is the **peer's**
/// [`HelperChannel::peer_role`].
pub type HelperFilter = ChannelFilter<derec_proto::SenderKind, ChannelId>;

/// A record returned by [`crate::protocol::DeRecChannelStore::load`].
#[derive(Clone, Debug)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(Serialize, Deserialize)
)]
pub enum ChannelRecord {
    Helper(HelperChannel),
    Replica(ReplicaMember),
}

impl ChannelRecord {
    pub fn channel_id(&self) -> ChannelId {
        match self {
            ChannelRecord::Helper(h) => h.channel_id,
            ChannelRecord::Replica(r) => r.channel_id,
        }
    }
    pub fn status(&self) -> ChannelStatus {
        match self {
            ChannelRecord::Helper(h) => h.status,
            ChannelRecord::Replica(r) => r.status,
        }
    }
    /// Every endpoint the peer advertised, in the order it offered them.
    ///
    /// Never empty for a recorded channel: the library refuses to record a
    /// peer whose endpoints were all filtered away.
    pub fn transports(&self) -> &[derec_proto::TransportProtocol] {
        match self {
            ChannelRecord::Helper(h) => &h.transports,
            ChannelRecord::Replica(r) => &r.transports,
        }
    }
    pub fn communication_info(&self) -> &std::collections::HashMap<String, String> {
        match self {
            ChannelRecord::Helper(h) => &h.communication_info,
            ChannelRecord::Replica(r) => &r.communication_info,
        }
    }
    pub fn as_helper(&self) -> Option<&HelperChannel> {
        match self {
            ChannelRecord::Helper(h) => Some(h),
            _ => None,
        }
    }
    pub fn as_replica(&self) -> Option<&ReplicaMember> {
        match self {
            ChannelRecord::Replica(r) => Some(r),
            _ => None,
        }
    }
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
    /// Owner-side cached replica composite for this version, populated
    /// after the VSS split completes. Lets the Owner resume future
    /// `ProtectSecret` rounds without re-deriving share material, and
    /// surfaces under [`Secret::replicas`] on the next snapshot rebuild.
    /// `None` when this `secret_id` has no replica setup (or before
    /// the first sharing round commits).
    pub replicas: Option<Replicas>,
}

/// A single helper's share of the current secret — wire-pairs a
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
///
/// # Group-key handover
///
/// All replica channels for a given `secret_id` converge on a single
/// symmetric "group" key. The `shared_key` field carries that group key
/// inside the encrypted payload **only** when the sender knows the
/// receiver doesn't have it yet — i.e. on the first round to a newly
/// paired Destination. Both sides swap their stored channel key
/// (`(secret_id, channel_id)` in [`crate::protocol::DeRecSecretStore`])
/// from the per-pair ephemeral handshake key to the group key:
///
/// - **Sender**: swap immediately after the request envelope is sent.
///   The ack response from the new joiner will already be encrypted
///   with the group key.
/// - **Receiver**: swap before encrypting the ack response, so the
///   ack uses the group key and matches what the sender expects.
///
/// On the first-ever replica pair, the group key is implicitly the
/// pair-handshake key — `shared_key` is left empty, no swap happens,
/// and the channel-key entry both sides already saved is the group key.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReplicaSecretPayload {
    /// The full secret the sender is committing to this version.
    #[prost(message, optional, tag = "1")]
    pub secret: ::core::option::Option<Secret>,
    /// One entry per helper that received a VSS share on this round.
    #[prost(message, repeated, tag = "2")]
    pub shares: ::prost::alloc::vec::Vec<ChannelShare>,
    /// 32-byte replica-group key. Present only on the first-sync round
    /// to a newly-paired Destination; empty on every subsequent round
    /// (since the receiving channel already holds the group key) and
    /// empty when the receiving Destination is the very first pair for
    /// this `secret_id` (the pair-handshake key is implicitly the group
    /// key). See type-level docs for the swap protocol.
    #[prost(bytes = "vec", tag = "3")]
    pub shared_key: ::prost::alloc::vec::Vec<u8>,
}

/// Kind of secret material stored by [`crate::protocol::DeRecSecretStore`].
///
/// Each variant has its own lifecycle (see per-variant docs). Used as the
/// `kind` argument to [`crate::protocol::DeRecSecretStore::load`] and
/// [`crate::protocol::DeRecSecretStore::remove`]; on
/// [`crate::protocol::DeRecSecretStore::save`] the kind is inferred from
/// the [`SecretValue`] variant and need not be passed.
///
/// # Discriminant stability
///
/// **The numeric values below are stable and safe to persist.** They will
/// not be renumbered, and new variants are appended rather than inserted.
///
/// This is a guarantee, not an implementation detail, because store
/// implementations legitimately need a compact tag for the secret they are
/// writing and `kind as u8` is the obvious one to reach for. A deployed
/// store's rows outlive any single version of this crate, so renumbering
/// would silently reinterpret data already at rest — and two of the three
/// variants carry variable-length payloads, so a swapped tag decodes into a
/// plausible wrong value rather than failing.
///
/// Note that [`SecretValue`]'s serde representation carries no such
/// guarantee (see its docs). Persisting the discriminant plus your own
/// payload encoding is the supported way to store secret material durably.
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

/// Opaque, serialized pairing key material as held by
/// [`crate::protocol::DeRecSecretStore`] under [`SecretValue::PairingSecret`].
///
/// This is the store-boundary form of the ephemeral key pair the pairing
/// handshake produces. The protocol deliberately exposes it as an opaque
/// byte blob rather than a cryptographic type, so a store implementation can
/// persist and reload it without depending on `derec-cryptography` or any
/// serialization framework: call [`as_bytes`](Self::as_bytes) to obtain the
/// bytes to persist on `save`, and hand the same bytes back to
/// [`from_bytes`](Self::from_bytes) on `load`.
///
/// The byte layout is a library-internal detail, is not part of the public
/// API, and may change between versions; treat the blob as opaque and never
/// interpret it.
///
/// The bytes are held in [`zeroize::Zeroizing`] so the plaintext key material
/// is wiped from memory on drop.
#[derive(Clone)]
pub struct PairingKeyMaterial(Zeroizing<Vec<u8>>);

impl PairingKeyMaterial {
    /// Wrap raw bytes previously obtained from [`as_bytes`](Self::as_bytes)
    /// and persisted by a store.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The opaque bytes to persist. Round-trips through
    /// [`from_bytes`](Self::from_bytes).
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Serialize live pairing secret key material into the store-boundary
    /// form.
    ///
    /// Library-internal: the pairing handlers call this before handing the
    /// value to the secret store, keeping the `ark-serialize` encoding an
    /// implementation detail that never crosses the public API.
    pub(crate) fn from_secret(material: &PairingSecretKeyMaterial) -> Self {
        use ark_serialize::CanonicalSerialize as _;
        let mut buf = Vec::with_capacity(material.compressed_size());
        material
            .serialize_compressed(&mut buf)
            .expect("ark serialization of PairingSecretKeyMaterial is infallible");
        Self(Zeroizing::new(buf))
    }

    /// Reconstruct live pairing secret key material from the store-boundary
    /// form.
    ///
    /// Library-internal: the pairing handlers call this after loading the
    /// value from the secret store. A decode failure means the persisted
    /// bytes were corrupted or truncated, which is an internal invariant
    /// violation rather than valid caller input.
    pub(crate) fn to_secret(&self) -> crate::Result<PairingSecretKeyMaterial> {
        use ark_serialize::CanonicalDeserialize as _;
        PairingSecretKeyMaterial::deserialize_compressed(self.0.as_slice())
            .map_err(|_| crate::Error::Invariant("stored PairingSecret bytes failed to decode"))
    }
}

#[cfg(feature = "serde")]
impl Serialize for PairingKeyMaterial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PairingKeyMaterial {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Self(Zeroizing::new(bytes)))
    }
}

/// Serde adapter for the prost [`ContactMessage`] carried by
/// [`SecretValue::PairingContact`]. prost messages have no native serde
/// support, so the value is (de)serialized through its canonical protobuf
/// byte encoding.
#[cfg(feature = "serde")]
mod contact_serde {
    use super::ContactMessage;
    use prost::Message as _;
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};

    pub(super) fn serialize<S>(contact: &ContactMessage, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        contact.encode_to_vec().serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<ContactMessage, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        ContactMessage::decode(bytes.as_slice()).map_err(serde::de::Error::custom)
    }
}

/// The payload returned by [`crate::protocol::DeRecSecretStore::load`] and
/// passed to [`crate::protocol::DeRecSecretStore::save`].
///
/// Variants are 1:1 with [`SecretKind`].
///
/// With the `serde` feature enabled, `Serialize` / `Deserialize` are
/// derived so a store implementation can persist an entry with any serde
/// format instead of hand-rolling a codec. This is an alternative to the
/// byte-level accessors on the individual payloads (e.g.
/// [`PairingKeyMaterial::as_bytes`] / [`PairingKeyMaterial::from_bytes`]);
/// implementors pick whichever fits their backend, and consumers that do
/// not use serde pay no dependency for it. The serde wire format is not
/// part of the public API and may change independently.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SecretValue {
    /// The post-pairing symmetric channel key. Established by pairing and used
    /// to authenticate and encrypt every subsequent message on the channel.
    SharedKey(crate::types::SharedKey),
    /// The ephemeral ECIES / ML-KEM key material created by `start` and
    /// consumed when the pairing response arrives. Removed once the shared
    /// key is derived. Held as an opaque [`PairingKeyMaterial`] blob so
    /// store implementors never touch a cryptography primitive.
    PairingSecret(PairingKeyMaterial),
    /// The initiator's [`ContactMessage`], needed by
    /// [`crate::primitives::pairing::response::process`] to derive the shared
    /// key. Ephemeral — removed after pairing completes.
    PairingContact(#[cfg_attr(feature = "serde", serde(with = "contact_serde"))] ContactMessage),
}

/// Tag identifying which kind of in-flight orchestrator state an entry in
/// [`crate::protocol::DeRecStateStore`] holds. Used by
/// [`crate::protocol::DeRecStateStore::load_all`] to filter by category.
///
/// # Discriminant stability
///
/// The same guarantee as [`SecretKind`]: these values are stable, safe to
/// persist, and new variants are appended rather than inserted. A durable
/// state store needs a column to filter `load_all` by, and this is it.
///
/// The values are written out explicitly for that reason. Left implicit they
/// would still *have* numbers — ones every reader would have to count out by
/// hand, and that a reordering would change without touching a single digit
/// in this file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StateKind {
    /// Outstanding [`derec_proto::VerifyShareRequestMessage`], one per
    /// channel. Load-bearing for the replay-defence binding gate.
    PendingVerification = 0,
    /// Recovery accumulator, one per `(recovered secret_id, version)`
    /// within a partition. Holds every
    /// [`derec_proto::GetShareResponseMessage`] received so far for that
    /// reconstruction target. See [`StateKey::PendingRecovery`] on why
    /// the recovered id is distinct from the partitioning one.
    PendingRecovery = 1,
    /// Outstanding unpair acknowledgement, one per channel. Carries the
    /// `started_at` unix-seconds timestamp so the orchestrator can time
    /// out unresponsive peers.
    PendingUnpair = 2,
    /// Active sharing round, one row per in-flight version. Several can be
    /// open at once: publishes are started by the pair-completion hook and by
    /// the promotion inside `verify_fingerprint`, not only by
    /// `start(ProtectSecret)`. Holds the per-channel tallies (`pending` /
    /// `confirmed` / `failed`), the per-member tallies, and the `started_at`
    /// timestamp used to time out unresponsive peers.
    SharingRound = 3,
    /// Active replica catch-up. At most one entry exists per `secret_id`
    /// (a new `start(ReplicaDiscovery)` overwrites any prior one). Holds the
    /// versions members have reported so far, so the asker can pick the
    /// member holding the newest state once every peer has answered.
    PendingReplicaDiscovery = 4,
}

/// Secondary-key selector identifying a single row within a given
/// [`StateKind`] under a `secret_id`. Passed to
/// [`crate::protocol::DeRecStateStore::load`] and
/// [`crate::protocol::DeRecStateStore::remove`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StateKey {
    /// Row is scoped to one channel.
    PendingVerification { channel_id: ChannelId },
    /// Row is scoped to one reconstruction target.
    ///
    /// `secret_id` is the secret *being recovered*, which is not
    /// necessarily the `secret_id` naming the partition this row lives
    /// in: a recovering device runs an ephemeral instance whose own id
    /// owns the partition, while the target belongs to the wire. Keying
    /// on it lets one instance recover several secrets concurrently at
    /// the same version without their accumulators colliding.
    PendingRecovery { secret_id: u64, version: u32 },
    /// Row is scoped to one channel.
    PendingUnpair { channel_id: ChannelId },
    /// At most one row per `secret_id`. No secondary key.
    PendingReplicaDiscovery,
    /// Row is scoped to one publishing round, identified by the version it
    /// distributes.
    ///
    /// Keying on the version is load-bearing rather than cosmetic. Rounds are
    /// not started only by `start(ProtectSecret)`: the pair-completion hook
    /// and the promotion inside `verify_fingerprint` both publish, and both
    /// run while handling an *inbound* message. A single unkeyed row meant a
    /// round started that way silently replaced one already in flight, after
    /// which neither completed — responses for the replaced round arrived
    /// against state that no longer existed, and no `SharingComplete` was
    /// emitted for either. An application could not prevent this, because it
    /// cannot see the library's round state. Distinct versions now accumulate
    /// independently.
    SharingRound { version: u32 },
}

impl StateKey {
    /// The [`StateKind`] this key selects. Used by store implementations
    /// that persist rows in a `(secret_id, kind, secondary_key)` schema.
    pub fn kind(&self) -> StateKind {
        match self {
            StateKey::PendingVerification { .. } => StateKind::PendingVerification,
            StateKey::PendingRecovery { .. } => StateKind::PendingRecovery,
            StateKey::PendingUnpair { .. } => StateKind::PendingUnpair,
            StateKey::PendingReplicaDiscovery => StateKind::PendingReplicaDiscovery,
            StateKey::SharingRound { .. } => StateKind::SharingRound,
        }
    }
}

/// The payload of one row in the [`crate::protocol::DeRecStateStore`].
///
/// # Write pattern
///
/// The library treats [`crate::protocol::DeRecStateStore::save`] as
/// **full-replacement upsert** — there is no per-item merge or append
/// semantic at the store level. Accumulator-style state
/// ([`StateItem::PendingRecovery`] and [`StateItem::SharingRound`]) grows
/// via load-modify-save cycles from the library. Backends do not need to
/// implement any append primitive; a naive replace-on-save is correct.
#[derive(Debug, Clone)]
pub enum StateItem {
    /// The full outstanding [`derec_proto::VerifyShareRequestMessage`] the
    /// orchestrator sent for this channel. Retained so the corresponding
    /// inbound [`derec_proto::VerifyShareResponseMessage`] can be validated
    /// against the exact `(nonce, secret_id, version)` triple that was
    /// minted at request time.
    ///
    /// Overwritten in place by a subsequent `save` for the same
    /// `(secret_id, channel_id)`; the most recent challenge wins.
    PendingVerification {
        channel_id: ChannelId,
        request: derec_proto::VerifyShareRequestMessage,
    },

    /// Accumulator for one in-progress recovery target.
    ///
    /// The library writes this variant one share at a time as each inbound
    /// [`derec_proto::GetShareResponseMessage`] arrives. The write sequence
    /// under a single `(recovered secret_id, version)` is:
    ///
    /// 1. First response arrives. Library calls `save` with a `shares`
    ///    vector containing exactly one element.
    /// 2. Second response arrives. Library `load`s the accumulator,
    ///    appends the new share to the returned Vec, and `save`s the
    ///    grown Vec back.
    /// 3. …repeat until threshold. On threshold met, library `remove`s
    ///    the accumulator.
    ///
    /// Implementations MUST accept `shares` vectors of any length,
    /// including one. Every `save` replaces the stored value in place
    /// with the caller-supplied Vec; no append primitive is required.
    ///
    /// # Concurrency
    ///
    /// See [`crate::protocol::DeRecStateStore`] for the multi-instance
    /// concurrency contract. Concurrent inbound shares racing on the same
    /// accumulator will clobber each other via a naive load-modify-save;
    /// the application layer is responsible for serializing concurrent
    /// `process()` calls that touch the same `(recovered secret_id,
    /// version)` if this matters. Recoveries of *different* secrets do
    /// not contend: they occupy separate rows even at the same version.
    PendingRecovery {
        /// The secret being recovered. See
        /// [`StateKey::PendingRecovery`] — this is a wire-level id and
        /// may differ from the `secret_id` partitioning the row.
        secret_id: u64,
        version: u32,
        shares: Vec<derec_proto::GetShareResponseMessage>,
    },

    /// Outstanding unpair acknowledgement window. `started_at` is the
    /// unix-seconds timestamp stamped when the request was sent; the
    /// orchestrator sweeps expired entries via
    /// [`crate::protocol::DeRecStateStore::load_all`].
    PendingUnpair {
        channel_id: ChannelId,
        started_at: u64,
    },

    /// Active sharing round, keyed by the version it distributes. Created by
    /// a publish — `start(ProtectSecret)`, the pair-completion hook, or the
    /// promotion inside `verify_fingerprint` — and cleared by the orchestrator
    /// once every targeted peer has responded (confirmed, rejected, or timed
    /// out). Rounds at different versions are independent and settle
    /// separately; one never displaces another.
    ///
    /// `pending` / `confirmed` / `failed` partition the round's target
    /// channels; the union is invariant across the round's lifetime.
    /// `started_at` is the unix-seconds timestamp used to time out
    /// unresponsive helpers.
    /// An in-flight replica catch-up: the versions members have reported so
    /// far, plus the asker's own, so the winner can be chosen once every peer
    /// has answered or timed out.
    PendingReplicaDiscovery {
        /// The version the asker held when the check started.
        local_version: u32,
        /// Members asked that have not yet answered.
        pending: std::collections::HashSet<ReplicaId>,
        /// Versions reported so far, by member.
        reported: std::collections::HashMap<ReplicaId, u32>,
        started_at: u64,
    },
    /// An in-flight publishing round. Boxed because it is by far the largest
    /// variant, and every other `StateItem` would otherwise be padded to its
    /// size.
    SharingRound(Box<SharingRoundState>),
}

/// The accounting for one in-flight publishing round.
///
/// The two populations are tracked separately and by different keys — helpers
/// by [`ChannelId`], members by [`ReplicaId`]. A single set keyed on
/// `ChannelId` cannot express the replica leg at all: every member shares the
/// group channel, so they would collapse into one entry and the first answer
/// would settle the round for the whole group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharingRoundState {
    pub version: u32,
    /// Helpers written to that have not yet answered.
    pub pending: std::collections::HashSet<ChannelId>,
    /// Helpers that confirmed storage.
    pub confirmed: std::collections::HashSet<ChannelId>,
    /// Helpers that rejected or timed out.
    pub failed: std::collections::HashSet<ChannelId>,
    /// Members written to that have not yet answered.
    pub pending_replicas: std::collections::HashSet<ReplicaId>,
    /// Members that acknowledged.
    pub synced_replicas: std::collections::HashSet<ReplicaId>,
    /// Members that refused, timed out, or could not be reached.
    pub behind_replicas: std::collections::HashSet<ReplicaId>,
    pub started_at: u64,
}

impl StateItem {
    /// The [`StateKind`] this item is an instance of.
    pub fn kind(&self) -> StateKind {
        match self {
            StateItem::PendingVerification { .. } => StateKind::PendingVerification,
            StateItem::PendingRecovery { .. } => StateKind::PendingRecovery,
            StateItem::PendingUnpair { .. } => StateKind::PendingUnpair,
            StateItem::PendingReplicaDiscovery { .. } => StateKind::PendingReplicaDiscovery,
            StateItem::SharingRound(_) => StateKind::SharingRound,
        }
    }

    /// The [`StateKey`] identifying this item within its `(secret_id, kind)`
    /// partition. Convenience so callers don't have to hand-construct a
    /// key that matches the payload.
    pub fn key(&self) -> StateKey {
        match self {
            StateItem::PendingVerification { channel_id, .. } => StateKey::PendingVerification {
                channel_id: *channel_id,
            },
            StateItem::PendingRecovery {
                secret_id, version, ..
            } => StateKey::PendingRecovery {
                secret_id: *secret_id,
                version: *version,
            },
            StateItem::PendingUnpair { channel_id, .. } => StateKey::PendingUnpair {
                channel_id: *channel_id,
            },
            StateItem::PendingReplicaDiscovery { .. } => StateKey::PendingReplicaDiscovery,
            StateItem::SharingRound(round) => StateKey::SharingRound {
                version: round.version,
            },
        }
    }
}

/// A single stored share entry, fully self-describing.
#[derive(Debug, Clone)]
pub struct Share {
    /// Numeric identifier of the secret this share belongs to.
    pub secret_id: u64,
    /// Version number of the secret.
    pub version: u32,
    /// Opaque protobuf bytes — see [`crate::protocol::DeRecShareStore`] for
    /// the per-side format.
    pub bytes: Vec<u8>,
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    /// Every `SecretValue` variant round-trips through serde — the path a
    /// store implementation takes when it opts for serde over the
    /// byte-level accessors. Exercises the custom `PairingKeyMaterial`
    /// impls and the prost `ContactMessage` adapter.
    #[test]
    fn secret_value_serde_round_trips_all_variants() {
        let cases = [
            SecretValue::SharedKey([7u8; 32]),
            SecretValue::PairingSecret(PairingKeyMaterial::from_bytes(vec![1, 2, 3, 4, 5])),
            SecretValue::PairingContact(ContactMessage {
                nonce: 42,
                ..Default::default()
            }),
        ];

        for value in cases {
            let json = serde_json::to_vec(&value).expect("serialize");
            let decoded: SecretValue = serde_json::from_slice(&json).expect("deserialize");
            match (&value, &decoded) {
                (SecretValue::SharedKey(a), SecretValue::SharedKey(b)) => assert_eq!(a, b),
                (SecretValue::PairingSecret(a), SecretValue::PairingSecret(b)) => {
                    assert_eq!(a.as_bytes(), b.as_bytes())
                }
                (SecretValue::PairingContact(a), SecretValue::PairingContact(b)) => {
                    assert_eq!(a, b)
                }
                _ => panic!("variant changed across serde round-trip"),
            }
        }
    }

    /// The serde form and the `from_bytes`/`as_bytes` form describe the
    /// same opaque blob, so a value serialized one way decodes the other.
    #[test]
    fn pairing_key_material_serde_matches_byte_accessors() {
        let material = PairingKeyMaterial::from_bytes(vec![9, 8, 7, 6]);
        let json = serde_json::to_vec(&material).expect("serialize");
        let decoded: PairingKeyMaterial = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(material.as_bytes(), decoded.as_bytes());
    }
}

#[cfg(test)]
mod persisted_discriminant_tests {
    //! Pins the discriminants callers are told they may store.
    //!
    //! `library/tests/enum_fixture.rs` also checks these, but it checks them
    //! against `enums.json` — a file that gets updated as part of responding
    //! to the failure. Reorder an enum, run the suite, update the fixture the
    //! message points you at, and it goes green with every deployed database
    //! now misreading its own rows.
    //!
    //! These assertions name the numbers directly, so there is nothing to
    //! update but the assertion itself. Changing one is then a deliberate act
    //! with this comment attached to it, which is the whole point: renumbering
    //! is not forbidden, it is just never something to do by accident.
    //!
    //! If you are here because one of these failed: appending a variant is
    //! fine and needs a new line below. Renumbering an existing one breaks
    //! data at rest in every deployment that has stored it, and no migration
    //! runs on our side to fix it.

    use super::{SecretKind, StateKind};

    #[test]
    fn secret_kind_discriminants_are_unchanged() {
        assert_eq!(SecretKind::SharedKey as u8, 0);
        assert_eq!(SecretKind::PairingSecret as u8, 1);
        assert_eq!(SecretKind::PairingContact as u8, 2);
    }

    #[test]
    fn state_kind_discriminants_are_unchanged() {
        assert_eq!(StateKind::PendingVerification as u8, 0);
        assert_eq!(StateKind::PendingRecovery as u8, 1);
        assert_eq!(StateKind::PendingUnpair as u8, 2);
        assert_eq!(StateKind::SharingRound as u8, 3);
        assert_eq!(StateKind::PendingReplicaDiscovery as u8, 4);
    }
}

#[cfg(test)]
mod expired_channel_cleanup_tests {
    use super::ExpiredChannelCleanup;

    /// Constructors do not validate — normalization is the builder's job,
    /// so a zero survives construction intact.
    #[test]
    fn from_secs_does_not_clamp() {
        assert_eq!(
            ExpiredChannelCleanup::from_secs(0),
            ExpiredChannelCleanup::Enabled { timeout_in_secs: 0 }
        );
    }

    #[test]
    fn from_secs_preserves_value() {
        assert_eq!(
            ExpiredChannelCleanup::from_secs(900),
            ExpiredChannelCleanup::Enabled {
                timeout_in_secs: 900
            }
        );
    }

    /// The marshalling seam: a disabled policy discards its timeout here,
    /// in Rust, so no SDK has to make that decision.
    #[test]
    fn new_disabled_discards_timeout() {
        assert_eq!(
            ExpiredChannelCleanup::new(false, 900),
            ExpiredChannelCleanup::Disabled
        );
    }

    #[test]
    fn new_enabled_keeps_timeout() {
        assert_eq!(
            ExpiredChannelCleanup::new(true, 900),
            ExpiredChannelCleanup::Enabled {
                timeout_in_secs: 900
            }
        );
    }

    #[test]
    fn default_matches_historical_behaviour() {
        assert_eq!(
            ExpiredChannelCleanup::default(),
            ExpiredChannelCleanup::Enabled {
                timeout_in_secs: 300
            }
        );
    }
}

#[cfg(test)]
mod target_filter_tests {
    use super::*;

    fn ids(raw: &[u64]) -> Vec<ChannelId> {
        raw.iter().copied().map(ChannelId).collect()
    }

    /// `All` is every paired channel, in the order the store returned them.
    ///
    /// Order is asserted rather than membership: it decides the order a
    /// fan-out dispatches in, and therefore the order of the events an
    /// application sees back.
    #[test]
    fn all_keeps_every_known_channel_in_store_order() {
        let known = ids(&[30, 10, 20]);
        assert_eq!(Target::All.filter(&known), known);
    }

    #[test]
    fn single_yields_the_channel_when_it_is_known() {
        let known = ids(&[30, 10, 20]);
        assert_eq!(Target::Single(ChannelId(10)).filter(&known), ids(&[10]));
    }

    /// A caller may name a channel this device never paired on, or one that
    /// has since been unpaired. It is dropped rather than refused.
    #[test]
    fn single_yields_nothing_when_the_channel_is_unknown() {
        let known = ids(&[30, 10, 20]);
        assert!(Target::Single(ChannelId(99)).filter(&known).is_empty());
    }

    /// `Many` follows the **caller's** order, not the store's, so an
    /// application that ranks its helpers keeps that ranking.
    #[test]
    fn many_keeps_the_callers_order() {
        let known = ids(&[30, 10, 20]);
        assert_eq!(
            Target::Many(ids(&[20, 30])).filter(&known),
            ids(&[20, 30]),
            "the requested order must survive, not be re-sorted into store order"
        );
    }

    /// One stale id must not fail the fan-out to everyone else.
    #[test]
    fn many_drops_unknown_ids_and_keeps_the_rest() {
        let known = ids(&[30, 10, 20]);
        assert_eq!(
            Target::Many(ids(&[10, 99, 20])).filter(&known),
            ids(&[10, 20])
        );
    }

    #[test]
    fn a_target_naming_only_unknown_channels_yields_nothing() {
        let known = ids(&[30, 10, 20]);
        assert!(Target::Many(ids(&[98, 99])).filter(&known).is_empty());
    }

    /// A device with no paired channels reaches nobody, whatever it asked for.
    #[test]
    fn nothing_is_reachable_when_no_channel_is_known() {
        assert!(Target::All.filter(&[]).is_empty());
        assert!(Target::Single(ChannelId(10)).filter(&[]).is_empty());
        assert!(Target::Many(ids(&[10, 20])).filter(&[]).is_empty());
    }

    /// A duplicate in the request is not de-duplicated: the caller asked for
    /// it twice and the fan-out honours that literally.
    #[test]
    fn many_does_not_deduplicate_the_request() {
        let known = ids(&[10, 20]);
        assert_eq!(Target::Many(ids(&[10, 10])).filter(&known), ids(&[10, 10]));
    }
}

#[cfg(test)]
mod channel_filter_tests {
    use super::*;
    use crate::types::ReplicaId;

    fn member(
        id: u64,
        status: ChannelStatus,
        role: ReplicaRole,
    ) -> (ReplicaId, ChannelStatus, ReplicaRole) {
        (ReplicaId(id), status, role)
    }

    /// The contract every field rests on: empty means "do not restrict".
    /// A store that reads `ids: []` as "no rows" instead of "all rows"
    /// silently returns nothing, and the flow above it does nothing at all.
    #[test]
    fn a_default_filter_admits_everything() {
        let filter = ReplicaFilter::default();
        let (id, status, role) = member(1, ChannelStatus::Pending, ReplicaRole::Destination);
        assert!(filter.matches(&id, status, &role));
    }

    #[test]
    fn ids_restrict_to_the_listed_members() {
        let filter = ReplicaFilter {
            ids: vec![ReplicaId(1), ReplicaId(2)],
            ..Default::default()
        };
        for id in [1, 2] {
            let (id, status, role) = member(id, ChannelStatus::Paired, ReplicaRole::Source);
            assert!(filter.matches(&id, status, &role));
        }
        let (id, status, role) = member(3, ChannelStatus::Paired, ReplicaRole::Source);
        assert!(!filter.matches(&id, status, &role));
    }

    /// The status list is an allow-list, not a single value: the sharing
    /// flow needs `Paired` *and* `Unpairing` on one listing, because a
    /// departing member learns its removal completed by receiving the
    /// version that omits it.
    #[test]
    fn status_is_an_allow_list() {
        let filter = ReplicaFilter {
            status: vec![ChannelStatus::Paired, ChannelStatus::Unpairing],
            ..Default::default()
        };
        for status in [ChannelStatus::Paired, ChannelStatus::Unpairing] {
            let (id, status, role) = member(1, status, ReplicaRole::Destination);
            assert!(filter.matches(&id, status, &role));
        }
        let (id, status, role) = member(1, ChannelStatus::Pending, ReplicaRole::Destination);
        assert!(!filter.matches(&id, status, &role));
    }

    #[test]
    fn role_restricts_when_set_and_admits_when_none() {
        let filter = ReplicaFilter {
            role: Some(ReplicaRole::Destination),
            ..Default::default()
        };
        let (id, status, role) = member(1, ChannelStatus::Paired, ReplicaRole::Destination);
        assert!(filter.matches(&id, status, &role));
        let (id, status, role) = member(1, ChannelStatus::Paired, ReplicaRole::Source);
        assert!(!filter.matches(&id, status, &role));

        let any = ReplicaFilter::default();
        assert!(any.matches(&id, status, &role));
    }

    /// Six flows exclude this device's own row, which `replicas()` returns
    /// deliberately so the group stays reconstructible from the stores.
    #[test]
    fn exclude_omits_the_named_members() {
        let filter = ReplicaFilter {
            exclude: vec![ReplicaId(7)],
            ..Default::default()
        };
        let (id, status, role) = member(7, ChannelStatus::Paired, ReplicaRole::Source);
        assert!(!filter.matches(&id, status, &role));
        let (id, status, role) = member(8, ChannelStatus::Paired, ReplicaRole::Source);
        assert!(filter.matches(&id, status, &role));
    }

    /// `exclude` is applied after `ids`, so naming the same member in both
    /// omits it rather than admitting it. Stated because the successor pick
    /// and the fan-out filters compose these two fields on one call.
    #[test]
    fn exclude_overrides_ids() {
        let filter = ReplicaFilter {
            ids: vec![ReplicaId(1), ReplicaId(2)],
            exclude: vec![ReplicaId(2)],
            ..Default::default()
        };
        let (id, status, role) = member(1, ChannelStatus::Paired, ReplicaRole::Source);
        assert!(filter.matches(&id, status, &role));
        let (id, status, role) = member(2, ChannelStatus::Paired, ReplicaRole::Source);
        assert!(!filter.matches(&id, status, &role));
    }

    #[test]
    fn restrictions_combine_with_and() {
        let filter = ReplicaFilter {
            status: vec![ChannelStatus::Paired],
            role: Some(ReplicaRole::Destination),
            exclude: vec![ReplicaId(9)],
            ..Default::default()
        };
        let (id, status, role) = member(1, ChannelStatus::Paired, ReplicaRole::Destination);
        assert!(filter.matches(&id, status, &role));

        // Each of the three, violated on its own.
        let (id, status, role) = member(1, ChannelStatus::Pending, ReplicaRole::Destination);
        assert!(!filter.matches(&id, status, &role));
        let (id, status, role) = member(1, ChannelStatus::Paired, ReplicaRole::Source);
        assert!(!filter.matches(&id, status, &role));
        let (id, status, role) = member(9, ChannelStatus::Paired, ReplicaRole::Destination);
        assert!(!filter.matches(&id, status, &role));
    }

    /// The helper alias carries the peer's `SenderKind`, not a `ReplicaRole`
    /// — the two listings differ in that one type, which is why the filter
    /// is generic over it.
    #[test]
    fn the_helper_alias_filters_on_sender_kind() {
        let filter = HelperFilter {
            role: Some(derec_proto::SenderKind::Helper),
            ..Default::default()
        };
        assert!(filter.matches(
            &ChannelId(1),
            ChannelStatus::Paired,
            &derec_proto::SenderKind::Helper
        ));
        assert!(!filter.matches(
            &ChannelId(1),
            ChannelStatus::Paired,
            &derec_proto::SenderKind::Owner
        ));
    }
}
