// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#[cfg(any(feature = "ffi", target_arch = "wasm32"))]
pub(crate) mod wire;

use std::collections::HashMap;

use crate::{
    primitives::discovery::response::SecretVersionEntry,
    protocol::types::{Target, UserSecret},
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    ContactMessage, GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, PairRequestMessage,
    PrePairRequestMessage, SenderKind, StoreShareRequestMessage, TransportProtocol,
    UnpairRequestMessage, UpdateChannelInfoRequestMessage, VerifyShareRequestMessage,
};

/// Lightweight discriminant of [`PendingAction`].
///
/// Carries no payload — useful for the
/// [`DeRecEvent::AutoAccepted`] event (so listeners can route on
/// "what flow just got auto-accepted" without holding the action's
/// inner request/key material) and for the
/// [`AutoAcceptPolicy::allows`] dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PendingActionKind {
    Pairing,
    PrePair,
    StoreShare,
    VerifyShare,
    Discovery,
    GetShare,
    Unpair,
    UpdateChannelInfo,
}

/// Per-flow opt-in for auto-accepting incoming requests.
///
/// Default = every field `false` (no flow auto-accepted; `process()`
/// emits [`DeRecEvent::ActionRequired`] like today). When a field is
/// `true`, `process()` invokes the equivalent of
/// [`super::DeRecProtocol::accept`] internally and emits
/// [`DeRecEvent::AutoAccepted`] **in place of**
/// [`DeRecEvent::ActionRequired`], followed by the same flow events
/// the caller would have seen from a manual `accept`.
///
/// Wire the policy through
/// [`super::DeRecProtocolBuilder::with_auto_accept`].
///
/// # Per-flow notes
///
/// - [`Self::pairing`] covers both standard and replica pairing.
///   Standard pairing transitions the channel to `Paired` immediately;
///   auto-accepting it skips any UI confirmation of "User X wants to
///   pair." Replica pairing leaves the channel in `Pending` until both
///   sides run `verify_fingerprint()`, so auto-accept here is benign
///   (channel is inert until the out-of-band fingerprint match).
/// - [`Self::pre_pair`] gates the plaintext `PrePair` leg of HashedKeys
///   pairing. The MITM defence is on the *scanner* side
///   (binding-hash check) and is unaffected by this flag, but enabling
///   it turns the initiator into a request-amplification oracle: any
///   party that knows the contact's `nonce` + `channel_id` can elicit
///   a key-publish response. Prefer to keep this off unless you
///   control both ends of the transport (LAN, integration tests).
/// - [`Self::store_share`] is the helper's only admission-control point
///   for inbound shares. The protocol enforces no size, quota or rate
///   limit of its own, and the negotiated `maxShareSize` from
///   [`derec_proto::ParameterRange`] is checked for range overlap at
///   pairing time only — never against an actual share. While this flag
///   is `false`, the [`DeRecEvent::ActionRequired`] carrying
///   [`PendingAction::StoreShare`] hands the application the decoded
///   [`derec_proto::StoreShareRequestMessage`], which is where a size or
///   quota decision belongs — see
///   [`super::DeRecProtocol::reject`] for a worked example. Setting it
///   `true` removes that opportunity entirely: every share from every
///   paired Owner is stored unconditionally, at whatever size it
///   arrives. Keep it `false` in any deployment with per-user storage
///   limits.
/// - [`Self::unpair`] is destructive — accepting deletes the local
///   channel record and any shares/secrets associated with it. The
///   [`DeRecEvent::Unpaired`] event still fires (after the deletion),
///   so observability is preserved, but the user has no chance to
///   intervene before the data is gone. Apps that want a "are you
///   sure?" gate should keep this off.
/// - [`Self::update_channel_info`] silently overwrites the stored
///   channel record with the peer's new transport / communication
///   info. Cryptographically safe (only the paired peer can send it),
///   but a compromised peer key gets weaponised faster — outbound
///   traffic on the channel re-routes to whatever endpoint the peer
///   announced.
///
/// All other fields wrap routine request/response flows and have no
/// caveats beyond "the caller decided not to gate them." Note that this
/// applies to gating alone: auto-accept never relaxes an invariant the
/// protocol enforces itself, only the application's opportunity to
/// refuse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AutoAcceptPolicy {
    pub pairing: bool,
    pub pre_pair: bool,
    pub store_share: bool,
    pub verify_share: bool,
    pub discovery: bool,
    pub get_share: bool,
    pub unpair: bool,
    pub update_channel_info: bool,
}

impl AutoAcceptPolicy {
    /// Enable auto-accept for every flow. Equivalent to setting every
    /// field to `true` — read the field-level docs on
    /// [`AutoAcceptPolicy`] before using this in production; several
    /// flows are state-changing or expose a request-amplification
    /// surface.
    pub fn all() -> Self {
        Self {
            pairing: true,
            pre_pair: true,
            store_share: true,
            verify_share: true,
            discovery: true,
            get_share: true,
            unpair: true,
            update_channel_info: true,
        }
    }

    /// `true` when the policy opts in to auto-accepting the given action.
    /// Used by [`super::DeRecProtocol::process`] at the auto-accept
    /// intercept site.
    pub fn allows(&self, action: &PendingAction) -> bool {
        match action.kind() {
            PendingActionKind::Pairing => self.pairing,
            PendingActionKind::PrePair => self.pre_pair,
            PendingActionKind::StoreShare => self.store_share,
            PendingActionKind::VerifyShare => self.verify_share,
            PendingActionKind::Discovery => self.discovery,
            PendingActionKind::GetShare => self.get_share,
            PendingActionKind::Unpair => self.unpair,
            PendingActionKind::UpdateChannelInfo => self.update_channel_info,
        }
    }
}

/// An opaque action token emitted inside [`DeRecEvent::ActionRequired`] events.
///
/// When `process()` receives an incoming protocol request, it returns an
/// `ActionRequired` event carrying a `PendingAction`. The application must
/// pass this token to [`super::DeRecProtocol::accept`] or
/// [`super::DeRecProtocol::reject`] to complete the flow.
///
/// `Debug` shows only the [`PendingActionKind`] discriminant plus
/// `channel_id`, keeping any peer-supplied request contents out of log
/// lines. No variant carries private key material — the accept handlers
/// reload the pairing secret from the secret store (single source of
/// truth), so the token stays small and safe to persist or ship across a
/// language boundary.
pub enum PendingAction {
    Pairing {
        channel_id: ChannelId,
        request: PairRequestMessage,
        kind: SenderKind,
        peer_communication_info: HashMap<String, String>,
        /// Trace id read from the inbound `PairRequest` envelope. Echoed
        /// verbatim on the `PairResponse` envelope when the application
        /// calls `accept` or `reject`; see `DeRecMessage.traceId`.
        trace_id: u64,
    },
    /// The peer scanned a `HashedKeys`-mode `ContactMessage` and is asking
    /// for the real pairing public keys via a plaintext `PrePairRequest`.
    ///
    /// Accepting fetches `PairingSecret` from the secret store and replies
    /// with the actual `mlkemEncapsulationKey` / `eciesPublicKey`; the
    /// scanner then validates the published keys against the contact's
    /// `contactBindingHash` and proceeds to a normal `PairRequest` flow.
    /// Rejecting sends back a non-Ok `PrePairResponse` and keeps no state.
    ///
    /// Carries no `pairing_secret` — the handler loads it from the secret
    /// store at `accept` time (single source of truth) and the action stays
    /// small enough to round-trip cheaply across the WASM boundary.
    PrePair {
        channel_id: ChannelId,
        request: PrePairRequestMessage,
        /// Trace id read from the inbound `PrePairRequest` envelope. Echoed
        /// verbatim on the `PrePairResponse` when the application calls
        /// `accept` or `reject`; see `DeRecMessage.traceId`.
        trace_id: u64,
    },
    StoreShare {
        channel_id: ChannelId,
        request: StoreShareRequestMessage,
        shared_key: SharedKey,
        /// Trace id read from the inbound request envelope. Echoed verbatim
        /// on the response envelope when the application calls `accept` or
        /// `reject`; see `DeRecMessage.traceId`.
        trace_id: u64,
    },
    VerifyShare {
        channel_id: ChannelId,
        request: VerifyShareRequestMessage,
        shared_key: SharedKey,
        trace_id: u64,
    },
    /// The peer is asking us to enumerate which `(secret_id, version)`
    /// tuples we currently hold for them on this channel (see
    /// [`crate::primitives::discovery`]). Accepting replies with the
    /// catalog so the asker can correlate it with their own view —
    /// commonly the precursor an owner uses to drive `Recovery`, but
    /// useful any time the owner wants to know what a given helper
    /// still has. Rejecting sends back a non-`Ok` response and
    /// discloses no catalog content.
    Discovery {
        channel_id: ChannelId,
        request: GetSecretIdsVersionsRequestMessage,
        shared_key: SharedKey,
        trace_id: u64,
    },
    GetShare {
        channel_id: ChannelId,
        request: GetShareRequestMessage,
        shared_key: SharedKey,
        trace_id: u64,
    },
    /// The peer has asked us to drop our state for this channel
    /// (see [`crate::primitives::unpairing`]). Accepting deletes the local
    /// channel/share/secret state and sends back an `Ok` response; rejecting
    /// sends a non-`Ok` response and keeps the state.
    Unpair {
        channel_id: ChannelId,
        request: UnpairRequestMessage,
        shared_key: SharedKey,
        trace_id: u64,
    },
    /// The peer has announced an update to their communication info and/or
    /// transport endpoint.
    ///
    /// Calling [`super::DeRecProtocol::accept`] on this action does the
    /// state mutation **for you**: the orchestrator writes the new fields
    /// onto the stored [`crate::protocol::types::HelperChannel`] and sends back
    /// an `Ok` response. When `transport_protocol` is part of the update,
    /// the response is routed to the **new** endpoint, so subsequent
    /// outbound traffic on this channel already targets the new address.
    /// Applications do not need to call any setter themselves on the
    /// receiving side — receiving-side endpoint changeover is handled
    /// inside `accept`. The local-node endpoint setters
    /// [`crate::protocol::DeRecProtocol::set_communication_info`] and
    /// [`crate::protocol::DeRecProtocol::set_own_transport`] exist for
    /// the **initiating** side only, where the announcement comes from.
    ///
    /// Calling [`super::DeRecProtocol::reject`] sends a non-`Ok`
    /// response and leaves the stored channel state unchanged.
    UpdateChannelInfo {
        channel_id: ChannelId,
        request: UpdateChannelInfoRequestMessage,
        shared_key: SharedKey,
        trace_id: u64,
    },
}

impl std::fmt::Debug for PendingAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let channel_id = match self {
            PendingAction::Pairing { channel_id, .. }
            | PendingAction::PrePair { channel_id, .. }
            | PendingAction::StoreShare { channel_id, .. }
            | PendingAction::VerifyShare { channel_id, .. }
            | PendingAction::Discovery { channel_id, .. }
            | PendingAction::GetShare { channel_id, .. }
            | PendingAction::Unpair { channel_id, .. }
            | PendingAction::UpdateChannelInfo { channel_id, .. } => channel_id,
        };
        f.debug_struct("PendingAction")
            .field("kind", &self.kind())
            .field("channel_id", &channel_id.0)
            .finish()
    }
}

impl PendingAction {
    /// Return this action's discriminant — used by
    /// [`AutoAcceptPolicy::allows`] and by the [`DeRecEvent::AutoAccepted`]
    /// event so callers can route on flow kind without inspecting the
    /// inner payload.
    pub fn kind(&self) -> PendingActionKind {
        match self {
            PendingAction::Pairing { .. } => PendingActionKind::Pairing,
            PendingAction::PrePair { .. } => PendingActionKind::PrePair,
            PendingAction::StoreShare { .. } => PendingActionKind::StoreShare,
            PendingAction::VerifyShare { .. } => PendingActionKind::VerifyShare,
            PendingAction::Discovery { .. } => PendingActionKind::Discovery,
            PendingAction::GetShare { .. } => PendingActionKind::GetShare,
            PendingAction::Unpair { .. } => PendingActionKind::Unpair,
            PendingAction::UpdateChannelInfo { .. } => PendingActionKind::UpdateChannelInfo,
        }
    }

    /// The token of the exchange that raised this action.
    ///
    /// Every variant carries one: an action only exists because a request
    /// arrived, and the response the application's decision produces echoes
    /// the same token. Reading it uniformly is what lets
    /// [`accept`](super::DeRecProtocol::accept) and
    /// [`reject`](super::DeRecProtocol::reject) attribute their work to that
    /// exchange without matching on the variant.
    pub fn trace_id(&self) -> u64 {
        match self {
            PendingAction::Pairing { trace_id, .. }
            | PendingAction::PrePair { trace_id, .. }
            | PendingAction::StoreShare { trace_id, .. }
            | PendingAction::VerifyShare { trace_id, .. }
            | PendingAction::Discovery { trace_id, .. }
            | PendingAction::GetShare { trace_id, .. }
            | PendingAction::Unpair { trace_id, .. }
            | PendingAction::UpdateChannelInfo { trace_id, .. } => *trace_id,
        }
    }
}

/// Describes an outbound protocol flow to initiate via [`super::DeRecProtocol::start`].
///
/// # Role gating
///
/// The orchestrator enforces flow directionality against
/// [`crate::protocol::types::HelperChannel::peer_role`] (set at pairing time):
///
/// - [`Self::Discovery`], [`Self::ProtectSecret`], [`Self::VerifyShares`],
///   [`Self::RecoverSecret`], and [`Self::Unpair`] require the peer to be
///   a [`SenderKind::Helper`] on every targeted channel; otherwise
///   [`crate::Error::RoleMismatch`] is returned.
/// - [`Self::Pairing`] creates the channel, so no role exists yet.
/// - [`Self::UpdateChannelInfo`] is symmetric — either party may initiate.
pub enum DeRecFlow {
    Pairing {
        kind: SenderKind,
        contact: ContactMessage,
        /// App-level identity metadata for the peer being paired with.
        /// Stored verbatim on the resulting [`crate::protocol::types::HelperChannel`]
        /// (`channel.communication_info`). The protocol does not inspect
        /// it — pass an empty map to record nothing.
        peer_communication_info: std::collections::HashMap<String, String>,
    },
    Discovery {
        target: Target,
    },
    /// Publish the current secret to the protocol's paired peers.
    ///
    /// The secret identifier comes from the
    /// [`super::DeRecProtocol`] instance (set at construction via
    /// [`crate::protocol::DeRecProtocolBuilder::new`]) — one protocol
    /// instance manages exactly one secret.
    ///
    /// The target set is derived from the channel store: every paired
    /// Owner→Helper channel receives a share if the configured threshold
    /// is met, and every paired Source→ReplicaDestination channel
    /// receives the full secret payload. Apps that need to drive a single
    /// peer should pair just that peer; the protocol no longer accepts
    /// a per-call subset.
    ///
    /// When the count of paired Helpers is below
    /// [`crate::protocol::DeRecProtocolBuilder::with_threshold`], no VSS
    /// split runs and Helpers receive nothing — the secret still lands on
    /// any paired Replica destinations in "secret-only" form.
    ProtectSecret {
        secrets: Vec<UserSecret>,
        description: Option<String>,
    },
    VerifyShares {
        /// Must equal this instance's own `secret_id`.
        ///
        /// Verification challenges the helpers holding *this* device's
        /// shares, so there is no other secret it could address. Passing a
        /// different id is refused with [`crate::Error::InvalidInput`] rather
        /// than ignored — a caller that believed it was verifying another
        /// secret would otherwise be told the wrong thing succeeded.
        ///
        /// Contrast [`Self::RecoverSecret`], whose `secret_id` genuinely
        /// names another instance's secret.
        secret_id: u64,
        version: u32,
        target: Target,
    },
    RecoverSecret {
        secret_id: u64,
        version: u32,
    },
    /// Ask the replica group whether this device is behind, and catch up if
    /// it is.
    ///
    /// **Replica-only.** Requires a configured `replica_id` and at least one
    /// other group member. Every member is asked which version it holds; the
    /// one holding the newest state is then asked for it, and the reply is
    /// hydrated exactly as an inbound sync would be. Ties resolve to the
    /// group's `Source`.
    ///
    /// A member reporting an *older* version than this device is ignored —
    /// the check never turns into a publish. Nothing here writes to a peer.
    ///
    /// Nothing triggers this automatically: the library provides the
    /// mechanism and the application chooses when to run it (a user action, a
    /// timer, app start). Concludes with [`DeRecEvent::ReplicaDiscoveryComplete`],
    /// plus the usual hydration event when a fetch actually happened.
    ReplicaDiscovery,
    /// Remove a member from the replica group.
    ///
    /// **Replica-only.** `replica_id` names the member being removed — as a
    /// plain `u64`, matching the decimal form ids take everywhere else.
    /// Naming this device is a voluntary departure; naming another is an
    /// eviction. A `replica_id` that names no current member is rejected with
    /// [`crate::Error::InvalidInput`] rather than silently doing nothing.
    ///
    /// # Announcing is all this flow does
    ///
    /// `start` tells every member, including the departing one, and flags that
    /// member locally. **It removes nothing on its own, and emits no
    /// [`DeRecEvent::ReplicaRemoved`].** The flag keeps the member out of the
    /// next roster while leaving it on the distribution list, which is how it
    /// learns it may tear down.
    ///
    /// The removal completes only when **the application publishes a roster
    /// that omits the member** — an ordinary
    /// [`DeRecFlow::ProtectSecret`]. `ReplicaRemoved` fires when that round
    /// completes, not before. An application that calls this flow and then
    /// waits for the event without publishing waits forever.
    ///
    /// One consequence is worth stating plainly: **a group with no secret to
    /// publish cannot complete a removal**, because there is no roster to
    /// send. The member stays flagged until something is published.
    ///
    /// A member tears down only once it has been told to leave *and* has seen
    /// a newer roster excluding it. Absence alone never destroys a copy of the
    /// secret — a publisher that silently omitted a member would otherwise
    /// destroy that member's state instead of merely forgetting it.
    UnpairReplica {
        replica_id: u64,
        memo: Option<String>,
    },
    /// Initiate an unpair flow against a paired channel.
    ///
    /// **Owner-initiated only.** This node must hold
    /// [`derec_proto::SenderKind::Owner`] on `channel_id`; otherwise
    /// [`crate::Error::RoleMismatch`] is returned. Helpers cannot tear
    /// down the relationship from the protocol layer — they may only
    /// refuse an incoming unpair request via
    /// [`super::DeRecProtocol::reject`].
    ///
    /// Whether the local state for `channel_id` is dropped immediately on
    /// `start(Unpair)` or only after the peer acknowledges is governed by
    /// [`crate::protocol::DeRecProtocolBuilder::with_unpair_ack`].
    Unpair {
        channel_id: ChannelId,
        /// Optional human-readable reason embedded into the wire request.
        /// Pass `None` (or an empty string) to omit.
        memo: Option<String>,
    },
    /// Broadcast updated communication info and/or transport endpoint to one
    /// or more paired channels.
    ///
    /// Either party may initiate. Either field may be `None` to leave it
    /// unchanged; presence of `communication_info` (even with an empty map)
    /// instructs the peer to replace its stored map for this channel with
    /// the supplied one. Presence of `transport_protocol` instructs the peer
    /// to use the new endpoint for the response and all subsequent messages.
    ///
    /// The application is responsible for calling
    /// [`crate::protocol::DeRecProtocol::set_communication_info`] and/or
    /// [`crate::protocol::DeRecProtocol::set_own_transport`] **before**
    /// initiating this flow so the local state matches what is announced.
    /// See the setter docs for the endpoint-changeover discipline.
    UpdateChannelInfo {
        target: Target,
        /// Updated communication info. `None` leaves the peer's stored map
        /// untouched; `Some(_)` replaces it (an empty `HashMap` clears it).
        communication_info: Option<std::collections::HashMap<String, String>>,
        /// Every endpoint this device can now be reached on, in its own
        /// preference order. Empty leaves the peer's stored set untouched;
        /// non-empty replaces it outright. The first entry also fills the
        /// deprecated singular `transportProtocol` so a peer predating
        /// `supportedTransports` still learns the new address.
        own_transports: Vec<TransportProtocol>,
    },
}

/// Determines whether the unpair initiator waits for the peer's
/// acknowledgement before dropping its local state for the channel.
///
/// See [`crate::protocol::DeRecProtocolBuilder::with_unpair_ack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnpairAck {
    /// The initiator keeps its local channel/share/secret state until the
    /// peer's `Ok` response arrives — or until the configured protocol
    /// timeout elapses, at which point the state is dropped anyway and an
    /// [`DeRecEvent::Unpaired`] event surfaces.
    #[default]
    Required,
    /// The initiator drops its local state immediately after sending the
    /// request and emits [`DeRecEvent::Unpaired`] right away. Any later
    /// response is silently ignored.
    NotRequired,
}

/// Events emitted by [`super::DeRecProtocol::process`].
///
/// The application reacts to these instead of routing raw messages manually.
#[non_exhaustive]
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum DeRecEvent {
    /// Pairing completed — the shared key for `channel_id` is now persisted.
    ///
    /// `kind` is the local party's role in the pairing. The channel record
    /// stores its inverse — the peer's role — on
    /// [`crate::protocol::types::HelperChannel::peer_role`], which the
    /// orchestrator consults on every subsequent flow start and inbound
    /// message. Applications use `kind` to decide what to do next:
    ///
    /// - [`SenderKind::Owner`] — the Owner completed pairing with a Helper.
    ///   Call [`super::DeRecProtocol::start`] with [`DeRecFlow::ProtectSecret`]
    ///   to distribute shares, or [`DeRecFlow::Discovery`] to ask the Helper
    ///   which secrets it holds (e.g. after a recovery re-pairing).
    /// - [`SenderKind::Helper`] — the Helper side completed pairing; no
    ///   additional action is required (the Helper waits for incoming messages).
    /// - [`SenderKind::ReplicaSource`] / [`SenderKind::ReplicaDestination`] —
    ///   a replica pairing completed; the application may use the channel
    ///   as needed (Source pushes via `ProtectSecret`, Destination receives
    ///   via [`Self::ReplicaSecretReceived`]).
    PairingCompleted {
        /// Long-term `channel_id` both peers atomically rotated to at the
        /// end of the handshake. All post-pairing traffic and library
        /// state for this relationship keys on this value.
        channel_id: ChannelId,
        /// The transient `channel_id` used only during the pairing
        /// handshake — the one that traveled on the `ContactMessage` and
        /// the pairing envelopes. Already replaced with `channel_id` in
        /// library state; the library will refuse messages routed to it
        /// from this point on. Provided so applications that persisted
        /// the pairing id (e.g. displayed it in a UI or mirrored it to
        /// their own store) can rekey their own records.
        pairing_channel_id: ChannelId,
        kind: SenderKind,
        /// Key-value pairs extracted from the peer's `CommunicationInfo`
        /// (e.g. `"name"`, `"email"`, `"phone"`). Empty if the peer sent none.
        peer_communication_info: HashMap<String, String>,
    },

    /// A replica-mode pair handshake completed. Fires **alongside**
    /// [`Self::PairingCompleted`] on replica channels.
    ///
    /// Under the unidirectional replica model, the peer's role
    /// (`ReplicaDestination` or `ReplicaSource`) is already on
    /// [`crate::protocol::types::HelperChannel::peer_role`] — this event just adds the
    /// peer's `replica_id`, which the app needs as a `from_replica_id`
    /// when subsequent secret syncs arrive or when targeting the peer via
    /// `ProtectSecret`.
    ReplicaPaired {
        /// The channel the pair handshake just completed on.
        channel_id: ChannelId,
        /// The peer's replica identity, extracted from
        /// `derec.replica_id` in the peer's `CommunicationInfo`.
        peer_replica_id: u64,
    },

    /// A share was accepted and stored locally (Helper side).
    ///
    /// `replica_id` is the stable per-device identifier of the writer,
    /// copied from the inbound `StoreShareRequestMessage.replica_id`.
    /// `None` indicates the writer was a non-replica `Owner`. The field
    /// is metadata for the application; see
    /// [`crate::protocol::DeRecShareStore::save`] for the storage
    /// disambiguation contract that makes concurrent writes from
    /// distinct replicas coexist.
    ShareStored {
        channel_id: ChannelId,
        version: u32,
        replica_id: Option<u64>,
    },

    /// A `ReplicaSource` peer pushed a secret sync on a `ReplicaDestination`
    /// channel. The library has already auto-acked the inbound
    /// `StoreShareRequest` and decoded the `ReplicaSecretPayload` into
    /// typed fields — the application can install `secret` directly,
    /// optionally using `shares` to verify or to take over the recovery
    /// flow toward each helper.
    ///
    /// **Recovery transitivity**: `secret.helpers[i].shared_key` lets
    /// the receiver authenticate as the Source toward each helper. For
    /// replica-to-replica traffic, all replicas share a single
    /// group-wide channel key (see
    /// [`crate::protocol::types::ReplicaSecretPayload`] for the handover
    /// protocol) — the receiver's own
    /// [`crate::protocol::DeRecSecretStore`] entry for this channel
    /// holds that group key, so impersonating the Source toward another
    /// destination is just a normal channel-key load. Treat the
    /// receiving device accordingly — see
    /// [`crate::protocol::types::ReplicaInfo`] for the security note.
    ReplicaSecretReceived {
        /// The channel the request arrived on.
        channel_id: ChannelId,
        /// The peer's replica identity (from `Channel.replica_id`,
        /// populated at pair time).
        from_replica_id: u64,
        /// `secret_id` echoed from the inbound `StoreShareRequest`.
        secret_id: u64,
        /// `version` echoed from the inbound `StoreShareRequest`.
        version: u32,
        /// Decoded full secret — same shape the sender wrote. The
        /// `helpers`, `replicas` and `secrets` fields carry the canonical
        /// roster snapshot for this version.
        secret: crate::protocol::types::Secret,
        /// Per-helper VSS share map. Each entry pairs a helper's
        /// `channel_id` with the serialized `CommittedDeRecShare` bytes
        /// the helper received — sufficient material for the receiver
        /// to drive a recovery against those helpers if needed.
        shares: Vec<crate::protocol::types::ChannelShare>,
    },

    /// The first sync for a `secret_id` this device had no snapshot for —
    /// the secret now exists here.
    ///
    /// Distinguished from [`Self::ReplicaSecretReceived`], which reports a
    /// later version of a secret the device already held. Both are hydrated
    /// by the library before the event fires; the difference is what the
    /// application should show the user, since only this one changes the set
    /// of secrets on the device.
    ///
    /// This is **not** a recovery. Recovery reconstructs a secret from helper
    /// shares and is driven by the application through
    /// [`crate::protocol::DeRecProtocol::restore`]; this arrives unsolicited
    /// from a group member and is applied on receipt.
    ReplicaSecretInstalled {
        /// The channel the request arrived on. During an admission handover
        /// this is the ephemeral pairing channel, not the group channel —
        /// the group's own id is `secret.replicas.channel_id`.
        channel_id: ChannelId,
        /// The member that wrote this version, from the payload.
        from_replica_id: u64,
        /// `secret_id` echoed from the inbound `StoreShareRequest`.
        secret_id: u64,
        /// `version` echoed from the inbound `StoreShareRequest`.
        version: u32,
        /// Decoded full secret, already written to the stores.
        secret: crate::protocol::types::Secret,
        /// Per-helper VSS share map, as on [`Self::ReplicaSecretReceived`].
        shares: Vec<crate::protocol::types::ChannelShare>,
    },

    /// A replica peer's `StoreShareResponse` to a secret sync we sent
    /// earlier. Fires on the replica channel, mirroring
    /// [`Self::ShareConfirmed`] / [`Self::ShareRejected`] on the helper
    /// side.
    ///
    /// `status` and `memo` come straight from the peer's
    /// `StoreShareResponseMessage.result`. Apps decide whether to retry,
    /// rebroadcast, or surface the failure to the user.
    ReplicaSecretAcked {
        channel_id: ChannelId,
        /// The peer's replica identity (from `Channel.replica_id`).
        from_replica_id: u64,
        /// `secret_id` echoed from the response.
        secret_id: u64,
        /// `version` echoed from the response.
        version: u32,
        /// The `StatusEnum` value from the peer's response.
        status: i32,
        /// Human-readable explanation from the peer (empty on `Ok`).
        memo: String,
    },

    /// A group member **refused** a secret sync we sent.
    ///
    /// The member answered and declined — distinct from
    /// [`Self::ReplicaSyncFailed`], where no usable answer arrived at all
    /// (transport error, encoding error, or timeout). Either way the member
    /// lands in `behind` on [`Self::ReplicaSyncComplete`] rather than failing
    /// the round; replicas are best-effort.
    ///
    /// Keyed by `replica_id`, not `channel_id`: every member answers on the
    /// one group channel, so the channel cannot say who replied.
    ReplicaSyncRejected {
        /// The member that refused, from the response payload.
        replica_id: u64,
        /// `secret_id` echoed from the response.
        secret_id: u64,
        /// `version` echoed from the response.
        version: u32,
        /// The `StatusEnum` value from the member's response.
        /// `VERSION_CONFLICT` means the round must be resolved and
        /// republished at a new version — see [`Self::ReplicaSyncComplete`].
        status: i32,
        /// Human-readable explanation from the member.
        memo: String,
    },

    /// A secret sync could not be delivered to a member at all.
    ///
    /// Distinct from [`Self::ReplicaSyncRejected`], which is the member
    /// answering "no": here nothing was sent, so no acknowledgement can ever
    /// arrive. The member is reported once, at dispatch, and appears in
    /// [`Self::ReplicaSyncComplete::behind`].
    ReplicaSyncFailed {
        /// The member that could not be reached.
        replica_id: u64,
        /// The version this round was publishing.
        version: u32,
        /// The transport or encoding failure, rendered for display.
        reason: String,
    },

    /// A member was removed from the group and its roster row dropped.
    ///
    /// Fires on the members that remain. The departing device instead reports
    /// [`Self::SelfRemovedFromGroup`].
    ReplicaRemoved {
        /// The member that left or was evicted.
        replica_id: u64,
    },

    /// The group's [`crate::protocol::types::ReplicaRole::Source`] moved to a
    /// different member, because the previous source is leaving.
    ///
    /// Fires on the device that ran the removal, naming the successor it chose,
    /// and on any member whose own row is promoted by an arriving roster. A
    /// member that is neither is unaffected: it learns the new source from
    /// `ReplicaInfo.role` like any other roster field.
    ReplicaSourceChanged {
        /// The member that now holds the source role.
        replica_id: u64,
    },

    /// This device has left the group and dropped its entire `secret_id`
    /// partition — group channel, helper channels, shares, secrets and the
    /// user-secret snapshot.
    ///
    /// Fires only after both halves of the safety rule hold: this device was
    /// told to leave, and has since seen a roster excluding it.
    SelfRemovedFromGroup {
        /// The version whose roster completed the removal.
        version: u32,
    },

    /// A replica catch-up finished.
    ///
    /// `group_version` is the newest version any member reported; it is `0`
    /// when no member answered. `fetched_from` names the member the state was
    /// pulled from, and is `None` when this device was already current — in
    /// which case no hydration event follows.
    ReplicaDiscoveryComplete {
        /// The version this device held when the check started.
        local_version: u32,
        /// The newest version any member reported.
        group_version: u32,
        /// The member the newest state was pulled from, if a fetch happened.
        fetched_from: Option<u64>,
    },

    /// The replica leg of a publishing round finished.
    ///
    /// Reported separately from [`Self::SharingComplete`] because the two
    /// populations have different success rules and different keys. Replicas
    /// are **best-effort**: a member in `behind` does not fail the round. A
    /// replica holds a full copy and contributes nothing to the recovery
    /// quorum, so blocking on one offline device would freeze writes for the
    /// whole group while buying no safety.
    ///
    /// `behind` is the application's retry list. The library keeps no durable
    /// per-member sync state, so an application that wants convergence across
    /// restarts must persist this itself or republish to the whole group.
    ///
    /// # Best-effort governs the *outcome*, not the timing
    ///
    /// A member that never answers does not fail the round — but it does
    /// delay the report. This event and [`Self::SharingComplete`] are emitted
    /// together, once both populations have settled, so an unreachable member
    /// holds *both* back until it times out
    /// ([`Timeouts::sharing_round`](crate::protocol::types::Timeouts::sharing_round)).
    /// Per-peer events ([`Self::ShareConfirmed`],
    /// [`Self::ReplicaSecretAcked`]) are not delayed and can be watched
    /// instead where promptness matters.
    ReplicaSyncComplete {
        /// The version this round was publishing.
        version: u32,
        /// Members that acknowledged.
        synced: Vec<u64>,
        /// Members that refused, timed out, or could not be reached.
        behind: Vec<u64>,
    },

    /// A Helper confirmed it stored our share (Owner side).
    ShareConfirmed { channel_id: ChannelId, version: u32 },

    /// A Helper rejected or failed to store our share (Owner side).
    ///
    /// The protocol absorbs sharing failures and converts them to events
    /// so the application can display per-participant progress. `status` and
    /// `memo` come from the Helper's response (or are synthetic for timeouts).
    ShareRejected {
        channel_id: ChannelId,
        version: u32,
        /// The `StatusEnum` value from the Helper's response.
        status: i32,
        /// Human-readable reason from the Helper, or `"timeout"`.
        memo: String,
    },

    /// A sharing round has completed (all participants responded or timed out).
    ///
    /// Emitted once per round after every targeted Helper has either
    /// confirmed, rejected, or timed out.
    ///
    /// # It also waits for the replica leg
    ///
    /// A round that targeted replica group members as well as Helpers does
    /// **not** report until *both* populations have settled. The counts below
    /// describe Helpers only, and they are known as soon as the Helpers answer
    /// — but the event is withheld until every member has acknowledged,
    /// refused, or timed out.
    ///
    /// The practical consequence: **one unreachable member delays this event
    /// by up to the configured timeout**
    /// ([`Timeouts::sharing_round`](crate::protocol::types::Timeouts::sharing_round)),
    /// even though the Helpers may have confirmed in milliseconds. An
    /// application waiting on `SharingComplete` to tell the user their secret
    /// is protected will appear to hang for that window. Nothing is lost and
    /// the round does terminate — the timeout sweep closes it — but the
    /// application is told late.
    ///
    /// A Helpers-only round is unaffected and completes as soon as the Helpers
    /// answer.
    ///
    /// If the two legs need to be observed independently, watch the per-peer
    /// events instead: [`DeRecEvent::ShareConfirmed`] /
    /// [`DeRecEvent::ShareRejected`] land as each Helper answers, without
    /// waiting for anyone else.
    ///
    /// The replica leg reports separately via
    /// [`DeRecEvent::ReplicaSyncComplete`], which is emitted at the same
    /// moment as this event when the round had members.
    SharingComplete {
        version: u32,
        confirmed_count: usize,
        failed_count: usize,
        /// `true` when `confirmed_count >= threshold`.
        threshold_met: bool,
    },

    /// A Helper's verification proof checked out (Owner side).
    ShareVerified { channel_id: ChannelId, version: u32 },

    /// A Helper reported all secrets it currently stores for this channel (Owner side).
    ///
    /// Emitted after the Owner calls [`super::DeRecProtocol::start`] with
    /// [`DeRecFlow::Discovery`] and the Helper responds. Each
    /// [`SecretVersionEntry`] carries a `secret_id` and a list of
    /// `(version, description)` pairs for every share the Helper holds.
    ///
    /// The application should persist this list and, once enough Helpers have
    /// responded, call [`super::DeRecProtocol::start`] with
    /// [`DeRecFlow::RecoverSecret`] for the desired `(secret_id, version)`.
    SecretsDiscovered {
        channel_id: ChannelId,
        /// All secrets and their stored versions the Helper holds for this channel.
        secrets: Vec<SecretVersionEntry>,
    },

    /// A recovery share response was received from a Helper but reconstruction
    /// cannot succeed yet — more shares are needed to meet the threshold.
    ///
    /// - `channel_id` identifies the Helper that sent this share response.
    /// - `shares_received` is the total number of share responses collected so far
    ///   for this `(secret_id, version)` recovery context.
    RecoveryShareReceived {
        channel_id: ChannelId,
        shares_received: usize,
    },

    /// A recovery share response was received but reconstruction failed for a
    /// reason other than insufficient shares (e.g. corrupted share, version
    /// mismatch, decode error).
    ///
    /// - `channel_id` identifies the Helper that sent this share response.
    /// - `shares_received` is the total number of share responses collected so far.
    /// - `error` describes the failure cause.
    RecoveryShareError {
        channel_id: ChannelId,
        shares_received: usize,
        error: String,
    },

    /// Recovery completed — the reconstructed
    /// [`crate::protocol::types::Secret`] is returned exactly once.
    ///
    /// The variant mirrors [`Self::ReplicaSecretReceived`]: the
    /// inner `secret` carries the full typed snapshot
    /// — `secrets: Vec<UserSecret>` (the user-facing entries the
    /// owner originally protected) plus the roster snapshot
    /// (`helpers` and `replicas`) captured at
    /// distribution time. Apps that only care about the user-facing
    /// entries read `secret.secrets`; the roster fields are useful
    /// when the recovering owner wants to know who held the shares,
    /// re-pair with the same helpers, or sync replicas after the
    /// recovery completes.
    ///
    /// The library decodes the two-layer (`DeRecSecret` → `Secret`)
    /// protobuf wrapping internally; a decode failure surfaces as
    /// [`Self::RecoveryShareError`] for that final share, not as
    /// `SecretRecovered` with bogus contents.
    ///
    /// Pass `secret` to [`super::DeRecProtocol::restore`] on a fresh
    /// protocol instance to commit canonical helper / replica state
    /// and wipe the throwaway recovery-mode channels.
    SecretRecovered {
        secret: crate::protocol::types::Secret,
    },

    /// An incoming request requires application confirmation before the library responds.
    ///
    /// Emitted by [`super::DeRecProtocol::process`] for every incoming request
    /// that is **not** opted into auto-accept by [`AutoAcceptPolicy`].
    /// The application must call [`super::DeRecProtocol::accept`] or
    /// [`super::DeRecProtocol::reject`] to complete the flow.
    ActionRequired {
        channel_id: ChannelId,
        action: PendingAction,
    },

    /// The library auto-accepted an incoming request because the
    /// configured [`AutoAcceptPolicy`] opted in to its flow.
    ///
    /// Emitted by [`super::DeRecProtocol::process`] **in place of**
    /// [`Self::ActionRequired`] for the auto-accepted flow, followed
    /// (in the same event vec) by the same flow events a manual
    /// `accept(action)` would have produced (e.g. `ShareStored`,
    /// `PairingCompleted`, `Unpaired`). Applications use this event
    /// for observability / audit logging — no further action is
    /// required from the caller.
    AutoAccepted {
        channel_id: ChannelId,
        /// The action's discriminant. The original
        /// [`PendingAction`] payload is consumed by the internal
        /// `accept` and is not surfaced here; routing on the kind is
        /// enough for observability since the flow-completion events
        /// that follow carry the per-flow details.
        action_kind: PendingActionKind,
    },

    /// The local channel state for `channel_id` has been dropped as the
    /// result of an unpair flow.
    ///
    /// Surfaces on **both** sides of the flow:
    ///
    /// - Initiator: emitted when (a) `UnpairAck::NotRequired` and the request
    ///   has just been sent, (b) `UnpairAck::Required` and the peer
    ///   acknowledged with `Ok`, or (c) `UnpairAck::Required` and the
    ///   configured timeout elapsed without a response.
    /// - Responder: emitted by [`super::DeRecProtocol::accept`] after the
    ///   channel/share/secret state for the requesting peer has been removed.
    Unpaired { channel_id: ChannelId },

    /// The peer answered an outbound unpair request with a non-`Ok` status.
    ///
    /// The initiator's local state is **not** dropped — the application
    /// decides what to do (retry, escalate, or force-delete locally).
    UnpairRejected {
        channel_id: ChannelId,
        /// The `StatusEnum` value from the peer's response.
        status: i32,
        /// Human-readable reason from the peer.
        memo: String,
    },

    /// The contact creator answered our `PrePairRequest` with a non-`Ok`
    /// status (scanner side, `HashedKeys` flow).
    ///
    /// The scanner cannot proceed to a normal `PairRequest` because the
    /// public keys were never published. Distinct from
    /// [`crate::primitives::pairing::PairingError::PrePairHashMismatch`],
    /// which fires when keys *were* published but failed the binding-hash
    /// check — a cryptographic failure surfaced as `Err`, not an event.
    PrePairRejected {
        channel_id: ChannelId,
        /// The `StatusEnum` value from the contact creator's response.
        status: i32,
        /// Human-readable reason from the contact creator.
        memo: String,
    },

    /// The stored [`crate::protocol::types::HelperChannel`] for `channel_id` has been updated
    /// with new communication info and/or transport endpoint.
    ///
    /// Surfaces on **both** sides of the flow:
    ///
    /// - Responder: emitted by [`super::DeRecProtocol::accept`] after the
    ///   update has been persisted to the local channel store.
    /// - Initiator: emitted by [`super::DeRecProtocol::process`] when the
    ///   peer's `Ok` response arrives.
    ///
    /// The new `communication_info` / `transport_protocol` values are
    /// already on the local
    /// [`crate::protocol::types::HelperChannel`] by the time the event fires;
    /// applications that care about the post-update state read it from
    /// the channel store directly.
    ChannelInfoUpdated { channel_id: ChannelId },

    /// The peer answered an outbound `UpdateChannelInfo` request with a
    /// non-`Ok` status. The peer's stored state is unchanged. The initiator's
    /// own state is also unaffected.
    ChannelInfoUpdateRejected {
        channel_id: ChannelId,
        /// The `StatusEnum` value from the peer's response.
        status: i32,
        /// Human-readable reason from the peer.
        memo: String,
    },

    /// Well-formed message with no actionable effect (e.g. an ACK).
    NoOp,

    /// A pairing flow was initiated for `channel_id` with the local
    /// role `kind`. Emitted synchronously from
    /// [`super::DeRecProtocol::start`] when the `PairRequest` (or
    /// `PrePairRequest` for `HashedKeys` / `NoKeys` modes) was
    /// dispatched successfully. Followed by
    /// [`Self::PairingCompleted`] (or a failure variant) once the peer
    /// responds. On a local send failure, `start` returns `Err` instead
    /// — no `PairingStarted` is emitted.
    PairingStarted {
        channel_id: ChannelId,
        /// Correlates this request with the response it will draw, and with
        /// every other request this same [`DeRecProtocol::start`](super::DeRecProtocol::start)
        /// call dispatched. One token is drawn per round, so a fan-out shares
        /// it across all of its targets.
        trace_id: u64,

        /// The local party's role in the pairing (same value that will
        /// appear on [`Self::PairingCompleted::kind`]; the channel record
        /// persists its inverse as
        /// [`crate::protocol::types::HelperChannel::peer_role`]).
        kind: SenderKind,
    },

    /// A discovery request was dispatched to `channel_id`. Emitted per
    /// targeted channel by [`super::DeRecProtocol::start`]. Followed by
    /// [`Self::SecretsDiscovered`] once the helper responds.
    DiscoveryStarted {
        channel_id: ChannelId,
        /// Correlates this request with the response it will draw, and with
        /// every other request this same [`DeRecProtocol::start`](super::DeRecProtocol::start)
        /// call dispatched. One token is drawn per round, so a fan-out shares
        /// it across all of its targets.
        trace_id: u64,
    },

    /// A discovery request could not be dispatched to `channel_id`.
    /// Emitted per targeted channel by [`super::DeRecProtocol::start`]
    /// when the outbound send (or per-channel preparation) failed. The
    /// remaining channels in the same fan-out are unaffected.
    DiscoveryFailed {
        channel_id: ChannelId,
        error: String,
    },

    /// A share-storage request was dispatched to `channel_id` for
    /// `version`. Emitted **per targeted helper** by
    /// [`super::DeRecProtocol::start`]. Followed by [`Self::ShareStored`] /
    /// [`Self::ShareConfirmed`] / [`Self::ShareRejected`] as the peer
    /// responds; the helper leg finishes with [`Self::SharingComplete`].
    ///
    /// The replica leg is **not** reported here. This event is keyed by
    /// channel, and every member of a group shares one — emitting per member
    /// would yield indistinguishable duplicates. Members report through
    /// [`Self::ReplicaSyncFailed`] at dispatch and
    /// [`Self::ReplicaSyncComplete`] at the end, both keyed by `replica_id`.
    ProtectSecretStarted {
        channel_id: ChannelId,
        version: u32,
        /// Correlates this request with the response it will draw, and with
        /// every other request this same [`DeRecProtocol::start`](super::DeRecProtocol::start)
        /// call dispatched. One token is drawn per round, so a fan-out shares
        /// it across all of its targets.
        trace_id: u64,
    },

    /// A share-storage request could not be dispatched to `channel_id`
    /// for `version`. Remaining fan-out targets are unaffected.
    ProtectSecretFailed {
        channel_id: ChannelId,
        version: u32,
        error: String,
    },

    /// A verify-share challenge was dispatched to `channel_id` for
    /// `version`. Followed by [`Self::ShareVerified`] once the helper
    /// responds.
    VerifySharesStarted {
        channel_id: ChannelId,
        version: u32,
        /// Correlates this request with the response it will draw, and with
        /// every other request this same [`DeRecProtocol::start`](super::DeRecProtocol::start)
        /// call dispatched. One token is drawn per round, so a fan-out shares
        /// it across all of its targets.
        trace_id: u64,
    },

    /// A verify-share challenge could not be dispatched to `channel_id`
    /// for `version`.
    VerifySharesFailed {
        channel_id: ChannelId,
        version: u32,
        error: String,
    },

    /// A recovery share request was dispatched to `channel_id` for
    /// `version`. Followed by [`Self::RecoveryShareReceived`] /
    /// [`Self::RecoveryShareError`] / [`Self::SecretRecovered`] as
    /// helper responses arrive.
    RecoverSecretStarted {
        channel_id: ChannelId,
        version: u32,
        /// Correlates this request with the response it will draw, and with
        /// every other request this same [`DeRecProtocol::start`](super::DeRecProtocol::start)
        /// call dispatched. One token is drawn per round, so a fan-out shares
        /// it across all of its targets.
        trace_id: u64,
    },

    /// A recovery share request could not be dispatched to `channel_id`
    /// for `version`.
    RecoverSecretFailed {
        channel_id: ChannelId,
        version: u32,
        error: String,
    },

    /// An unpair request could not be dispatched to `channel_id`.
    ///
    /// Emitted by [`super::DeRecProtocol::restore`] when tearing down the
    /// ephemeral recovery channels. The teardown is fire-and-forget, so
    /// the peer's reachability was never load-bearing: local state is
    /// dropped anyway and a [`Self::Unpaired`] for the same channel
    /// follows. The pair reports "the channel is gone locally, but the
    /// peer was not told" — the application may notify it out-of-band.
    UnpairFailed {
        channel_id: ChannelId,
        error: String,
    },

    /// An unpair request was dispatched to `channel_id`. Followed by
    /// [`Self::Unpaired`] once the peer acknowledges (or, under
    /// [`UnpairAck::NotRequired`], emitted in the same event vec
    /// immediately after `UnpairStarted`).
    UnpairStarted {
        channel_id: ChannelId,
        /// Correlates this request with the response it will draw, and with
        /// every other request this same [`DeRecProtocol::start`](super::DeRecProtocol::start)
        /// call dispatched. One token is drawn per round, so a fan-out shares
        /// it across all of its targets.
        trace_id: u64,
    },

    /// An update-channel-info request was dispatched to `channel_id`.
    /// Followed by [`Self::ChannelInfoUpdated`] once the peer responds.
    UpdateChannelInfoStarted {
        channel_id: ChannelId,
        /// Correlates this request with the response it will draw, and with
        /// every other request this same [`DeRecProtocol::start`](super::DeRecProtocol::start)
        /// call dispatched. One token is drawn per round, so a fan-out shares
        /// it across all of its targets.
        trace_id: u64,
    },

    /// An update-channel-info exchange failed for `channel_id`: either an
    /// outbound request could not be dispatched, or an inbound request
    /// announcing an unservable transport switch was refused (see
    /// [`crate::Error::NoUsableEndpoint`]).
    UpdateChannelInfoFailed {
        channel_id: ChannelId,
        error: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use derec_proto::{
        GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, PrePairRequestMessage,
        StoreShareRequestMessage, UnpairRequestMessage, UpdateChannelInfoRequestMessage,
        VerifyShareRequestMessage,
    };

    fn store_share_action() -> PendingAction {
        PendingAction::StoreShare {
            channel_id: ChannelId(1),
            request: StoreShareRequestMessage::default(),
            shared_key: [0u8; 32],
            trace_id: 0,
        }
    }

    fn verify_share_action() -> PendingAction {
        PendingAction::VerifyShare {
            channel_id: ChannelId(1),
            request: VerifyShareRequestMessage::default(),
            shared_key: [0u8; 32],
            trace_id: 0,
        }
    }

    fn discovery_action() -> PendingAction {
        PendingAction::Discovery {
            channel_id: ChannelId(1),
            request: GetSecretIdsVersionsRequestMessage::default(),
            shared_key: [0u8; 32],
            trace_id: 0,
        }
    }

    fn get_share_action() -> PendingAction {
        PendingAction::GetShare {
            channel_id: ChannelId(1),
            request: GetShareRequestMessage::default(),
            shared_key: [0u8; 32],
            trace_id: 0,
        }
    }

    fn unpair_action() -> PendingAction {
        PendingAction::Unpair {
            channel_id: ChannelId(1),
            request: UnpairRequestMessage::default(),
            shared_key: [0u8; 32],
            trace_id: 0,
        }
    }

    fn update_channel_info_action() -> PendingAction {
        PendingAction::UpdateChannelInfo {
            channel_id: ChannelId(1),
            request: UpdateChannelInfoRequestMessage::default(),
            shared_key: [0u8; 32],
            trace_id: 0,
        }
    }

    fn pre_pair_action() -> PendingAction {
        PendingAction::PrePair {
            channel_id: ChannelId(1),
            request: PrePairRequestMessage::default(),
            trace_id: 0,
        }
    }

    #[test]
    fn pending_action_kind_round_trips_each_variant() {
        assert_eq!(store_share_action().kind(), PendingActionKind::StoreShare);
        assert_eq!(verify_share_action().kind(), PendingActionKind::VerifyShare);
        assert_eq!(discovery_action().kind(), PendingActionKind::Discovery);
        assert_eq!(get_share_action().kind(), PendingActionKind::GetShare);
        assert_eq!(unpair_action().kind(), PendingActionKind::Unpair);
        assert_eq!(
            update_channel_info_action().kind(),
            PendingActionKind::UpdateChannelInfo
        );
        assert_eq!(pre_pair_action().kind(), PendingActionKind::PrePair);
    }

    #[test]
    fn auto_accept_policy_default_is_all_false() {
        let p = AutoAcceptPolicy::default();
        assert!(!p.pairing);
        assert!(!p.pre_pair);
        assert!(!p.store_share);
        assert!(!p.verify_share);
        assert!(!p.discovery);
        assert!(!p.get_share);
        assert!(!p.unpair);
        assert!(!p.update_channel_info);
    }

    #[test]
    fn auto_accept_policy_all_is_all_true() {
        let p = AutoAcceptPolicy::all();
        assert!(p.pairing);
        assert!(p.pre_pair);
        assert!(p.store_share);
        assert!(p.verify_share);
        assert!(p.discovery);
        assert!(p.get_share);
        assert!(p.unpair);
        assert!(p.update_channel_info);
    }

    #[test]
    fn auto_accept_policy_allows_dispatches_per_flow() {
        let only_store = AutoAcceptPolicy {
            store_share: true,
            ..Default::default()
        };
        assert!(only_store.allows(&store_share_action()));
        assert!(!only_store.allows(&verify_share_action()));
        assert!(!only_store.allows(&discovery_action()));
        assert!(!only_store.allows(&get_share_action()));
        assert!(!only_store.allows(&unpair_action()));
        assert!(!only_store.allows(&update_channel_info_action()));
        assert!(!only_store.allows(&pre_pair_action()));

        let none = AutoAcceptPolicy::default();
        assert!(!none.allows(&store_share_action()));

        let all = AutoAcceptPolicy::all();
        assert!(all.allows(&store_share_action()));
        assert!(all.allows(&verify_share_action()));
        assert!(all.allows(&discovery_action()));
        assert!(all.allows(&get_share_action()));
        assert!(all.allows(&unpair_action()));
        assert!(all.allows(&update_channel_info_action()));
        assert!(all.allows(&pre_pair_action()));
    }
}
