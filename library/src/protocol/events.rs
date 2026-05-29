// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::{
    primitives::discovery::response::SecretVersionEntry,
    types::{ChannelId, SharedKey, Target, UserSecret},
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    ContactMessage, GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, PairRequestMessage,
    SenderKind, StoreShareRequestMessage, UnpairRequestMessage, VerifyShareRequestMessage,
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
        response_kind: SenderKind,
        peer_communication_info: HashMap<String, String>,
    },
    StoreShare {
        channel_id: ChannelId,
        request: StoreShareRequestMessage,
        shared_key: SharedKey,
    },
    VerifyShare {
        channel_id: ChannelId,
        request: VerifyShareRequestMessage,
        shared_key: SharedKey,
    },
    Discovery {
        channel_id: ChannelId,
        request: GetSecretIdsVersionsRequestMessage,
        shared_key: SharedKey,
    },
    GetShare {
        channel_id: ChannelId,
        request: GetShareRequestMessage,
        shared_key: SharedKey,
    },
    /// The peer has asked us to drop our state for this channel
    /// (see [`crate::primitives::unpairing`]). Accepting deletes the local
    /// channel/share/secret state and sends back an `Ok` response; rejecting
    /// sends a non-`Ok` response and keeps the state.
    Unpair {
        channel_id: ChannelId,
        request: UnpairRequestMessage,
        shared_key: SharedKey,
    },
}

/// Describes an outbound protocol flow to initiate via [`super::DeRecProtocol::start`].
pub enum DeRecFlow {
    Pairing {
        kind: SenderKind,
        contact: ContactMessage,
        /// App-level identity metadata for the peer being paired with.
        /// Stored verbatim on the resulting [`crate::types::Channel`]
        /// (`channel.communication_info`). The protocol does not inspect
        /// it — pass an empty map to record nothing.
        peer_communication_info: std::collections::HashMap<String, String>,
    },
    Discovery {
        target: Target,
    },
    ProtectSecret {
        secrets: Vec<UserSecret>,
        description: Option<String>,
    },
    VerifyShares {
        version: u32,
        target: Target,
    },
    RecoverSecret {
        secret_id: u64,
        version: u32,
    },
    /// Initiate an unpair flow against one or more paired channels.
    ///
    /// Whether the local state for `target` is dropped immediately (fire-and-
    /// forget) or only after the peer acknowledges is governed by
    /// [`crate::protocol::DeRecProtocolBuilder::with_unpair_ack`].
    Unpair {
        target: Target,
        /// Optional human-readable reason embedded into the wire request.
        /// Pass `None` (or an empty string) to omit.
        memo: Option<String>,
    },
}

/// Determines whether the unpair initiator waits for the peer's
/// acknowledgement before dropping its local state for the channel.
///
/// See [`crate::protocol::DeRecProtocolBuilder::with_unpair_ack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpairAck {
    /// The initiator keeps its local channel/share/secret state until the
    /// peer's `Ok` response arrives — or until the configured protocol
    /// timeout elapses, at which point the state is dropped anyway and an
    /// [`DeRecEvent::Unpaired`] event surfaces.
    Required,
    /// The initiator drops its local state immediately after sending the
    /// request and emits [`DeRecEvent::Unpaired`] right away. Any later
    /// response is silently ignored.
    NotRequired,
}

impl Default for UnpairAck {
    fn default() -> Self {
        Self::Required
    }
}

// TODO: fix this warning
/// Events emitted by [`super::DeRecProtocol::process`].
///
/// The application reacts to these instead of routing raw messages manually.
#[non_exhaustive]
pub enum DeRecEvent {
    /// Pairing completed — the shared key for `channel_id` is now persisted.
    ///
    /// `kind` is the local party's role in the pairing. Applications use this
    /// to decide what to do next:
    ///
    /// - [`SenderKind::Owner`] — the Owner completed pairing with a Helper.
    ///   Call [`super::DeRecProtocol::start`] with [`DeRecFlow::ProtectSecret`]
    ///   to distribute shares, or [`DeRecFlow::Discovery`] to ask the Helper
    ///   which secrets it holds (e.g. after a recovery re-pairing).
    /// - [`SenderKind::Helper`] — the Helper side completed pairing; no
    ///   additional action is required (the Helper waits for incoming messages).
    /// - [`SenderKind::Replica`] — a Replica pairing completed; the application
    ///   may use the channel as needed.
    PairingCompleted {
        channel_id: ChannelId,
        kind: SenderKind,
        /// Key-value pairs extracted from the peer's `CommunicationInfo`
        /// (e.g. `"name"`, `"email"`, `"phone"`). Empty if the peer sent none.
        peer_communication_info: HashMap<String, String>,
    },

    /// A share was accepted and stored locally (Helper side).
    ShareStored { channel_id: ChannelId, version: u32 },

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

    /// Well-formed message with no actionable effect (e.g. an ACK).
    NoOp,
}
