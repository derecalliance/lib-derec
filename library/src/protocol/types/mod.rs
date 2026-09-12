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
    derive(Serialize, Deserialize),
    serde(
        into = "channel_wire::HelperChannelWire",
        try_from = "channel_wire::HelperChannelWire"
    )
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
    /// # Reading a pre-0.0.3 stored record
    ///
    /// This replaced a single `transport` field. A record written by an older
    /// build still loads: the deserializer accepts either spelling and lifts
    /// a lone `transport` object into a one-element list, so no application
    /// has to migrate a schema the library defines. See
    /// [`CHANNEL_RECORD_SCHEMA_VERSION`].
    ///
    /// What is *not* accepted is a record naming no endpoint at all — absent
    /// under both spellings, or present and empty. Defaulting those to an
    /// empty list would yield a channel that looks paired and is unreachable,
    /// which is worse than one that refuses to load, so they stay a loud
    /// deserialization error.
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
    derive(Serialize, Deserialize),
    serde(
        into = "channel_wire::ReplicaMemberWire",
        try_from = "channel_wire::ReplicaMemberWire"
    )
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

/// Schema version stamped onto every channel record this build writes.
///
/// Applications persist [`HelperChannel`] and [`ReplicaMember`] as opaque
/// blobs whose shape the *library* owns, so a field change here is a
/// migration the application cannot write without knowing a schema it does
/// not define. The marker is what lets the library do that migration itself:
/// a reader can tell a record apart by the shape it was written in rather
/// than by guessing from which fields happen to be present.
///
/// A record written before the marker existed deserializes as version 0 and
/// is upgraded on read. A record claiming a version *newer* than this build
/// understands is refused, because the alternative is silently dropping
/// fields this build cannot see and writing the truncated result back.
///
/// The value tracks the release that last changed the shape, not the release
/// that is current: it moved to 3 when `transport` became `transports`, and
/// stays there until the next shape change.
///
/// Declared unconditionally, unlike the serde impls that stamp it: the SDK
/// bridges mirror this number in their own encoders, and a constant they must
/// agree with should not appear and disappear with a feature flag.
pub const CHANNEL_RECORD_SCHEMA_VERSION: u8 = 3;

/// Stored-format compatibility for the two channel records.
///
/// [`HelperChannel`] and [`ReplicaMember`] route both serde directions
/// through the shadow structs here, which is what lets one stored shape be
/// read and a different one written. Two properties make it worth the
/// indirection:
///
/// - The conversion is a plain `TryFrom`, so an error message can say what is
///   wrong with a record rather than surfacing serde's field-level default.
/// - The two spellings are distinct *fields* rather than one field with an
///   `untagged` shape, so nothing here needs `deserialize_any`. Applications
///   own this persistence and the library does not dictate their format; an
///   `untagged` enum would have silently ruled out every non-self-describing
///   one.
#[cfg(any(feature = "serde", target_arch = "wasm32"))]
mod channel_wire {
    use super::{
        CHANNEL_RECORD_SCHEMA_VERSION, ChannelId, ChannelStatus, HelperChannel, ReplicaId,
        ReplicaMember, ReplicaRole,
    };
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    /// Resolve the two endpoint spellings into the one this build uses.
    ///
    /// `transports` wins when both are present. A migration script that adds
    /// the list without deleting the superseded object is doing the sane
    /// thing, and refusing it would punish the more careful migration.
    fn endpoints(
        transport: Option<derec_proto::TransportProtocol>,
        transports: Option<Vec<derec_proto::TransportProtocol>>,
        record: &'static str,
    ) -> Result<Vec<derec_proto::TransportProtocol>, String> {
        let resolved = match (transports, transport) {
            (Some(list), _) => list,
            (None, Some(one)) => vec![one],
            (None, None) => {
                return Err(format!(
                    "{record} names no transport endpoint: neither `transports` nor the \
                     pre-0.0.3 `transport` is present. A channel record with no endpoint \
                     describes a peer that looks paired and cannot be reached"
                ));
            }
        };
        if resolved.is_empty() {
            return Err(format!(
                "{record} has an empty `transports` list. A recorded channel always has at \
                 least one endpoint — the library refuses to record a peer whose endpoints \
                 were all filtered away"
            ));
        }
        Ok(resolved)
    }

    /// Refuse a record written by a build that knew a shape this one does not.
    fn check_version(schema_version: u8, record: &'static str) -> Result<(), String> {
        if schema_version > CHANNEL_RECORD_SCHEMA_VERSION {
            return Err(format!(
                "{record} was written with schema version {schema_version}, but this build \
                 understands at most {CHANNEL_RECORD_SCHEMA_VERSION}. Reading it would drop \
                 the fields this build cannot see, and writing the record back would make \
                 that loss permanent"
            ));
        }
        Ok(())
    }

    #[derive(Serialize, Deserialize)]
    pub struct HelperChannelWire {
        #[serde(default)]
        schema_version: u8,
        channel_id: ChannelId,
        /// Pre-0.0.3 spelling. Read, never written.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<derec_proto::TransportProtocol>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transports: Option<Vec<derec_proto::TransportProtocol>>,
        #[serde(default)]
        communication_info: HashMap<String, String>,
        peer_role: derec_proto::SenderKind,
        #[serde(default)]
        status: ChannelStatus,
        #[serde(default)]
        created_at: u64,
    }

    impl From<HelperChannel> for HelperChannelWire {
        fn from(value: HelperChannel) -> Self {
            Self {
                schema_version: CHANNEL_RECORD_SCHEMA_VERSION,
                channel_id: value.channel_id,
                transport: None,
                transports: Some(value.transports),
                communication_info: value.communication_info,
                peer_role: value.peer_role,
                status: value.status,
                created_at: value.created_at,
            }
        }
    }

    impl TryFrom<HelperChannelWire> for HelperChannel {
        type Error = String;

        fn try_from(wire: HelperChannelWire) -> Result<Self, Self::Error> {
            check_version(wire.schema_version, "HelperChannel")?;
            Ok(Self {
                channel_id: wire.channel_id,
                transports: endpoints(wire.transport, wire.transports, "HelperChannel")?,
                communication_info: wire.communication_info,
                peer_role: wire.peer_role,
                status: wire.status,
                created_at: wire.created_at,
            })
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct ReplicaMemberWire {
        #[serde(default)]
        schema_version: u8,
        channel_id: ChannelId,
        replica_id: ReplicaId,
        /// Pre-0.0.3 spelling. Read, never written.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<derec_proto::TransportProtocol>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transports: Option<Vec<derec_proto::TransportProtocol>>,
        #[serde(default)]
        communication_info: HashMap<String, String>,
        role: ReplicaRole,
        #[serde(default)]
        status: ChannelStatus,
        #[serde(default)]
        created_at: u64,
    }

    impl From<ReplicaMember> for ReplicaMemberWire {
        fn from(value: ReplicaMember) -> Self {
            Self {
                schema_version: CHANNEL_RECORD_SCHEMA_VERSION,
                channel_id: value.channel_id,
                replica_id: value.replica_id,
                transport: None,
                transports: Some(value.transports),
                communication_info: value.communication_info,
                role: value.role,
                status: value.status,
                created_at: value.created_at,
            }
        }
    }

    impl TryFrom<ReplicaMemberWire> for ReplicaMember {
        type Error = String;

        fn try_from(wire: ReplicaMemberWire) -> Result<Self, Self::Error> {
            check_version(wire.schema_version, "ReplicaMember")?;
            Ok(Self {
                channel_id: wire.channel_id,
                replica_id: wire.replica_id,
                transports: endpoints(wire.transport, wire.transports, "ReplicaMember")?,
                communication_info: wire.communication_info,
                role: wire.role,
                status: wire.status,
                created_at: wire.created_at,
            })
        }
    }
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
/// # Returning everything is correct
///
/// **Ignoring the filter entirely and returning every record under the
/// `secret_id` is a correct implementation**, and the one to write unless
/// there is a measured reason not to. The protocol re-applies the filter to
/// whatever a listing returns and drops anything it excludes, so a superset is
/// trimmed to exactly the right set before anything acts on it.
///
/// # Pushing it into the query is an optimization you opt into
///
/// A store *may* translate the filter into a `WHERE` clause or a key-condition
/// expression and return only the matching rows. That saves transferring rows
/// the caller would discard, which costs bandwidth everywhere and real money
/// on a metered backing such as DynamoDB, which bills by bytes read.
///
/// It also moves this type's semantics into a query language by hand, and the
/// error that matters is asymmetric. The library's re-check is a **one-way**
/// guarantee: dropping rows can enforce an upper bound, so returning too
/// *many* costs only the transfer. It cannot recover a row that was never
/// returned. A pushdown that selects too *few* is wrong in a way nothing here
/// can detect — no exception, no event, no log line. The protocol simply fails
/// to act, and what that looks like is a share that was never published.
///
/// So treat pushdown as a performance claim about your own query, and verify
/// it: `fixtures/channel_filter.json` is a table of
/// `(records, filter, expected)` cases covering the clauses that are easy to
/// get subtly wrong — empty-means-unrestricted per field, `role` as an
/// optional, and `exclude` applied *after* `ids`. Every binding's test suite
/// drives it, and a store that pushes down should be driven through it too.
///
/// [`ChannelFilter::matches`] is the same predicate the library re-checks
/// with, exported so a store that cannot express the filter as a query can
/// apply it in memory without re-deriving the rules.
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

/// The stored shape of a channel record, which applications persist and the
/// library owns.
///
/// These assert against **JSON text**, not against a round trip. A round trip
/// only proves this build agrees with itself; it says nothing about the record
/// an older build wrote, which is the compatibility that actually matters here
/// and the one that had no coverage when `transport` became `transports`.
#[cfg(all(test, feature = "serde"))]
mod channel_record_format_tests {
    use super::*;

    fn endpoint(uri: &str) -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: uri.to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    /// Exactly what a pre-0.0.3 build wrote: a singular `transport` object and
    /// no schema marker.
    const LEGACY_HELPER: &str = r#"{
        "channel_id": 42,
        "transport": { "uri": "https://helper.example/derec", "protocol": 0 },
        "peer_role": "Helper",
        "status": "Paired",
        "created_at": 1700000000
    }"#;

    #[test]
    fn a_pre_0_0_3_helper_record_still_loads() {
        let decoded: HelperChannel =
            serde_json::from_str(LEGACY_HELPER).expect("a record written before the list shape");

        assert_eq!(
            decoded.transports.len(),
            1,
            "the singular `transport` is lifted into a one-element list"
        );
        assert_eq!(decoded.transports[0].uri, "https://helper.example/derec");
        assert_eq!(decoded.channel_id, ChannelId(42));
        assert_eq!(decoded.status, ChannelStatus::Paired);
    }

    #[test]
    fn a_pre_0_0_3_replica_record_still_loads() {
        let legacy = r#"{
            "channel_id": 9,
            "replica_id": 3,
            "transport": { "uri": "https://member.example/derec", "protocol": 0 },
            "role": "Source"
        }"#;

        let decoded: ReplicaMember = serde_json::from_str(legacy).expect("legacy replica row");

        assert_eq!(decoded.transports.len(), 1);
        assert_eq!(decoded.transports[0].uri, "https://member.example/derec");
        assert_eq!(decoded.replica_id, ReplicaId(3));
    }

    /// The loud-failure property the `transport` -> `transports` change was
    /// made to keep. Defaulting these to an empty list would produce a channel
    /// that looks paired and can never be reached.
    #[test]
    fn a_record_naming_no_endpoint_is_refused() {
        let no_endpoint = r#"{ "channel_id": 42, "peer_role": "Helper" }"#;
        let err = serde_json::from_str::<HelperChannel>(no_endpoint)
            .expect_err("a record with neither spelling must not default to no endpoints");
        assert!(
            err.to_string().contains("names no transport endpoint"),
            "the error has to say what is wrong with the record: {err}"
        );

        let empty_list = r#"{ "channel_id": 42, "transports": [], "peer_role": "Helper" }"#;
        let err = serde_json::from_str::<HelperChannel>(empty_list)
            .expect_err("an explicitly empty list is as unreachable as an absent one");
        assert!(
            err.to_string().contains("empty `transports`"),
            "the error has to distinguish empty from absent: {err}"
        );
    }

    /// A record from a build that knew a shape this one does not must not be
    /// read and written back with the unknown fields silently dropped.
    #[test]
    fn a_newer_schema_version_is_refused() {
        let from_the_future = format!(
            r#"{{
                "schema_version": {},
                "channel_id": 42,
                "transports": [{{ "uri": "https://helper.example/derec", "protocol": 0 }}],
                "peer_role": "Helper"
            }}"#,
            CHANNEL_RECORD_SCHEMA_VERSION + 1
        );

        let err = serde_json::from_str::<HelperChannel>(&from_the_future)
            .expect_err("a future schema version must be refused, not truncated");
        assert!(
            err.to_string().contains("understands at most"),
            "the error has to name the version gap: {err}"
        );
    }

    /// Both spellings present is what a careful migration leaves behind — it
    /// added the list without deleting what it replaced.
    #[test]
    fn the_list_wins_when_both_spellings_are_present() {
        let both = r#"{
            "channel_id": 42,
            "transport": { "uri": "https://stale.example/derec", "protocol": 0 },
            "transports": [
                { "uri": "https://current.example/derec", "protocol": 0 },
                { "uri": "grpcs://current.example:443", "protocol": 1 }
            ],
            "peer_role": "Helper"
        }"#;

        let decoded: HelperChannel = serde_json::from_str(both).expect("both spellings present");

        assert_eq!(decoded.transports.len(), 2, "the list is authoritative");
        assert_eq!(decoded.transports[0].uri, "https://current.example/derec");
    }

    /// What this build writes, asserted against the serialized text: the
    /// marker is stamped, the list is the only endpoint spelling emitted, and
    /// the superseded one is never written back.
    #[test]
    fn a_written_record_carries_the_marker_and_only_the_list() {
        let record = HelperChannel {
            channel_id: ChannelId(42),
            transports: vec![endpoint("https://helper.example/derec")],
            communication_info: std::collections::HashMap::new(),
            peer_role: derec_proto::SenderKind::Helper,
            status: ChannelStatus::Paired,
            created_at: 1_700_000_000,
        };

        let json: serde_json::Value =
            serde_json::to_value(&record).expect("a channel record serializes");

        assert_eq!(
            json["schema_version"],
            serde_json::json!(CHANNEL_RECORD_SCHEMA_VERSION),
            "every record this build writes is stamped"
        );
        assert!(json["transports"].is_array());
        assert!(
            json.get("transport").is_none(),
            "the pre-0.0.3 spelling is read, never written: {json}"
        );

        // The exact text, not just the fields: the Go and .NET bridges
        // rebuild this JSON from their own structs rather than passing the
        // bytes through, and their encoders are ordered hand-written mirrors
        // of this one. Asserting the string is what makes a field added here
        // — or reordered — fail on the Rust side too, instead of only in a
        // hand-written SDK expectation that nothing cross-checks.
        assert_eq!(
            serde_json::to_string(&record).expect("serializes"),
            r#"{"schema_version":3,"channel_id":42,"transports":[{"uri":"https://helper.example/derec","protocol":0}],"communication_info":{},"peer_role":"Helper","status":"Paired","created_at":1700000000}"#
        );
    }

    /// A record written by this build reads back identically, and a record
    /// upgraded from the legacy shape is indistinguishable from one written
    /// natively once it has been through a save.
    #[test]
    fn an_upgraded_record_is_stable_once_rewritten() {
        let upgraded: HelperChannel =
            serde_json::from_str(LEGACY_HELPER).expect("legacy record loads");

        let rewritten = serde_json::to_string(&upgraded).expect("serializes");
        let reloaded: HelperChannel =
            serde_json::from_str(&rewritten).expect("its own output reloads");

        assert_eq!(reloaded.transports.len(), upgraded.transports.len());
        assert_eq!(reloaded.transports[0].uri, upgraded.transports[0].uri);
        assert_eq!(reloaded.channel_id, upgraded.channel_id);
        assert_eq!(reloaded.created_at, upgraded.created_at);
        assert!(
            serde_json::from_str::<serde_json::Value>(&rewritten).unwrap()["schema_version"]
                == serde_json::json!(CHANNEL_RECORD_SCHEMA_VERSION),
            "the upgrade is persisted, so the next read needs no lifting"
        );
    }

    /// The records travel inside `ChannelRecord`, so the compatibility has to
    /// survive the enum's tagging rather than only working on the inner type.
    #[test]
    fn the_compatibility_survives_the_channel_record_wrapper() {
        let legacy = format!(r#"{{ "Helper": {LEGACY_HELPER} }}"#);

        let decoded: ChannelRecord =
            serde_json::from_str(&legacy).expect("a legacy record inside its wrapper");

        match decoded {
            ChannelRecord::Helper(h) => assert_eq!(h.transports.len(), 1),
            other => panic!("expected a helper record, got {other:?}"),
        }
    }
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
