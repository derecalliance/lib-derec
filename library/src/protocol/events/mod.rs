// SPDX-License-Identifier: Apache-2.0

pub(crate) mod wire;

use std::collections::HashMap;

use crate::{
    primitives::discovery::response::SecretVersionEntry,
    protocol::types::{Target, UserSecret},
    types::{ChannelId, SharedKey},
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    ContactMessage, GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, PairRequestMessage,
    PrePairRequestMessage, SenderKind, StoreShareRequestMessage, TransportProtocol,
    UnpairRequestMessage, UpdateChannelInfoRequestMessage, VerifyShareRequestMessage,
};

/// An opaque action token emitted inside [`DeRecEvent::ActionRequired`] events.
///
/// When `process()` receives an incoming protocol request, it returns an
/// `ActionRequired` event carrying a `PendingAction`. The application must
/// pass this token to [`super::DeRecProtocol::accept`] or
/// [`super::DeRecProtocol::reject`] to complete the flow.
pub enum PendingAction {
    Pairing {
        channel_id: ChannelId,
        request: PairRequestMessage,
        pairing_secret: PairingSecretKeyMaterial,
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
    /// transport endpoint. Accepting applies the update to the stored
    /// [`crate::protocol::types::Channel`] and sends back an `Ok` response on the new
    /// endpoint (when `transport_protocol` was updated); rejecting sends a
    /// non-`Ok` response and leaves the stored state unchanged.
    UpdateChannelInfo {
        channel_id: ChannelId,
        request: UpdateChannelInfoRequestMessage,
        shared_key: SharedKey,
        trace_id: u64,
    },
}

/// Describes an outbound protocol flow to initiate via [`super::DeRecProtocol::start`].
///
/// # Role gating
///
/// The orchestrator enforces flow directionality against
/// [`crate::protocol::types::Channel::role`] (set at pairing time):
///
/// - [`Self::Discovery`], [`Self::ProtectSecret`], [`Self::VerifyShares`],
///   [`Self::RecoverSecret`], and [`Self::Unpair`] require this node to be
///   the [`SenderKind::Owner`] on every targeted channel; otherwise
///   [`crate::Error::RoleMismatch`] is returned.
/// - [`Self::Pairing`] creates the channel, so no role exists yet.
/// - [`Self::UpdateChannelInfo`] is symmetric — either party may initiate.
pub enum DeRecFlow {
    Pairing {
        kind: SenderKind,
        contact: ContactMessage,
        /// App-level identity metadata for the peer being paired with.
        /// Stored verbatim on the resulting [`crate::protocol::types::Channel`]
        /// (`channel.communication_info`). The protocol does not inspect
        /// it — pass an empty map to record nothing.
        peer_communication_info: std::collections::HashMap<String, String>,
    },
    Discovery {
        target: Target,
    },
    ProtectSecret {
        /// Vault identifier this share distribution belongs to.
        ///
        /// The application owns the channel↔secret mapping; pass the same
        /// `secret_id` here that identifies the vault `target` was selected
        /// for.
        secret_id: u64,
        /// Helpers to distribute shares to. Typically [`Target::Many`]
        /// carrying the channel ids the application has tagged as
        /// protecting this vault.
        target: Target,
        secrets: Vec<UserSecret>,
        description: Option<String>,
    },
    VerifyShares {
        secret_id: u64,
        version: u32,
        target: Target,
    },
    RecoverSecret {
        secret_id: u64,
        version: u32,
    },
    /// Initiate an unpair flow against one or more paired channels.
    ///
    /// **Owner-initiated only.** This node must hold
    /// [`derec_proto::SenderKind::Owner`] on every channel
    /// in `target`; otherwise [`crate::Error::RoleMismatch`] is returned.
    /// Helpers cannot tear down the relationship from the protocol layer —
    /// they may only refuse an incoming unpair request via
    /// [`super::DeRecProtocol::reject`].
    ///
    /// Whether the local state for `target` is dropped immediately on
    /// `start(Unpair)` or only after the peer acknowledges is governed by
    /// [`crate::protocol::DeRecProtocolBuilder::with_unpair_ack`].
    Unpair {
        target: Target,
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
        /// Updated transport endpoint. `None` leaves it untouched.
        transport_protocol: Option<TransportProtocol>,
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
pub enum DeRecEvent {
    /// Pairing completed — the shared key for `channel_id` is now persisted.
    ///
    /// `kind` is the local party's role in the pairing, also persisted as
    /// [`crate::protocol::types::Channel::role`] and consulted by the orchestrator on
    /// every subsequent flow start and inbound message. Applications use it
    /// to decide what to do next:
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
    ///   via [`Self::ReplicaVaultReceived`]).
    PairingCompleted {
        channel_id: ChannelId,
        kind: SenderKind,
        /// Key-value pairs extracted from the peer's `CommunicationInfo`
        /// (e.g. `"name"`, `"email"`, `"phone"`). Empty if the peer sent none.
        peer_communication_info: HashMap<String, String>,
    },

    /// A replica-mode pair handshake completed. Fires **alongside**
    /// [`Self::PairingCompleted`] on replica channels.
    ///
    /// Under the unidirectional replica model, the local side's role
    /// (`ReplicaSource` or `ReplicaDestination`) is already on
    /// [`crate::protocol::types::Channel::role`] — this event just adds the
    /// peer's `replica_id`, which the app needs as a `from_replica_id`
    /// when subsequent vault syncs arrive or when targeting the peer via
    /// `ProtectSecret`.
    ReplicaPaired {
        /// The channel the pair handshake just completed on.
        channel_id: ChannelId,
        /// The peer's replica identity, extracted from
        /// `derec.replica_id` in the peer's `CommunicationInfo`.
        peer_replica_id: u64,
    },

    /// A share was accepted and stored locally (Helper side).
    ShareStored { channel_id: ChannelId, version: u32 },

    /// A `ReplicaSource` peer pushed a vault sync on a `ReplicaDestination`
    /// channel. The library has already auto-acked the inbound
    /// `StoreShareRequest` and decoded the `ReplicaSecretPayload` into
    /// typed fields — the application can install `vault` directly,
    /// optionally using `shares` to verify or to take over the recovery
    /// flow toward each helper.
    ///
    /// **Recovery transitivity**: `vault.helpers[i].shared_key` lets the
    /// receiver authenticate as the Source toward each helper, and
    /// `vault.replicas[i].shared_key` does the same toward other
    /// destinations. Treat the receiving device accordingly — see
    /// [`crate::protocol::types::ReplicaInfo`] for the security note.
    ReplicaVaultReceived {
        /// The channel the request arrived on.
        channel_id: ChannelId,
        /// The peer's replica identity (from `Channel.replica_id`,
        /// populated at pair time).
        from_replica_id: u64,
        /// `secret_id` echoed from the inbound `StoreShareRequest`.
        secret_id: u64,
        /// `version` echoed from the inbound `StoreShareRequest`.
        version: u32,
        /// Decoded full vault — same shape the sender wrote. The
        /// `helpers`, `replicas`, `secrets`, and `owner_replica_id`
        /// fields carry the canonical roster snapshot for this version.
        vault: crate::protocol::types::SecretContainer,
        /// Per-helper VSS share map. Each entry pairs a helper's
        /// `channel_id` with the serialized `CommittedDeRecShare` bytes
        /// the helper received — sufficient material for the receiver
        /// to drive a recovery against those helpers if needed.
        shares: Vec<crate::protocol::types::ChannelShare>,
    },

    /// A replica peer's `StoreShareResponse` to a vault sync we sent
    /// earlier. Fires on the replica channel, mirroring
    /// [`Self::ShareConfirmed`] / [`Self::ShareRejected`] on the helper
    /// side.
    ///
    /// `status` and `memo` come straight from the peer's
    /// `StoreShareResponseMessage.result`. Apps decide whether to retry,
    /// rebroadcast, or surface the failure to the user.
    ReplicaVaultAcked {
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
    /// Emitted once per [`DeRecFlow::ProtectSecret`] flow after every targeted
    /// Helper has either confirmed, rejected, or timed out.
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

    /// Recovery completed — the reconstructed secret is returned exactly once.
    SecretRecovered { secret: Vec<u8> },

    /// An incoming request requires application confirmation before the library responds.
    ///
    /// Emitted by [`super::DeRecProtocol::process`] for every incoming request.
    /// The application must call [`super::DeRecProtocol::accept`] or
    /// [`super::DeRecProtocol::reject`] to complete the flow.
    ActionRequired {
        channel_id: ChannelId,
        action: PendingAction,
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

    /// The stored [`crate::protocol::types::Channel`] for `channel_id` has been updated
    /// with new communication info and/or transport endpoint.
    ///
    /// Surfaces on **both** sides of the flow:
    ///
    /// - Responder: emitted by [`super::DeRecProtocol::accept`] after the
    ///   update has been persisted.
    /// - Initiator: emitted by [`super::DeRecProtocol::process`] when the
    ///   peer's `Ok` response arrives.
    ///
    /// Each optional field carries the value that was applied (mirroring the
    /// request), so the application can react (e.g. refresh UI, retire the
    /// old endpoint).
    ChannelInfoUpdated {
        channel_id: ChannelId,
        /// New communication info, if it was part of the update.
        communication_info: Option<HashMap<String, String>>,
        /// New transport endpoint, if it was part of the update.
        transport_protocol: Option<derec_proto::TransportProtocol>,
    },

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
}
