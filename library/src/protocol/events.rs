// SPDX-License-Identifier: Apache-2.0

//! Public event and action types emitted / consumed by [`super::DeRecProtocol`].

use std::collections::HashMap;

use crate::{
    primitives::discovery::response::SecretVersionEntry,
    types::{ChannelId, SharedKey, Target, UserSecret},
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    ContactMessage, GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, PairRequestMessage,
    SenderKind, StoreShareRequestMessage, VerifyShareRequestMessage,
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
}

/// Describes an outbound protocol flow to initiate via [`super::DeRecProtocol::start`].
pub enum DeRecFlow {
    Pairing {
        kind: SenderKind,
        contact: ContactMessage,
        name: Option<String>,
    },
    Discovery {
        target: Target,
    },
    ProtectSecret {
        secrets: Vec<UserSecret>,
        description: Option<String>,
    },
    VerifyShares {
        version: i32,
        target: Target,
    },
    RecoverSecret {
        secret_id: Vec<u8>,
        version: i32,
    },
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
    /// - [`SenderKind::OwnerRecovery`] — the Owner just completed a recovery
    ///   pairing. Once out-of-band authentication is done, call
    ///   [`super::DeRecProtocol::start`] with [`DeRecFlow::Discovery`] to ask
    ///   the Helper which secrets it holds.
    /// - [`SenderKind::OwnerNonRecovery`] — standard Owner pairing; proceed
    ///   with [`DeRecFlow::ProtectSecret`] or [`DeRecFlow::VerifyShares`] as
    ///   needed.
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
    ShareStored { channel_id: ChannelId, version: i32 },

    /// A Helper confirmed it stored our share (Owner side).
    ShareConfirmed { channel_id: ChannelId, version: i32 },

    /// A Helper rejected or failed to store our share (Owner side).
    ///
    /// The protocol absorbs sharing failures and converts them to events
    /// so the application can display per-participant progress. `status` and
    /// `memo` come from the Helper's response (or are synthetic for timeouts).
    ShareRejected {
        channel_id: ChannelId,
        version: i32,
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
        version: i32,
        confirmed_count: usize,
        failed_count: usize,
        /// `true` when `confirmed_count >= threshold`.
        threshold_met: bool,
    },

    /// A Helper's verification proof checked out (Owner side).
    ShareVerified { channel_id: ChannelId, version: i32 },

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

    /// Well-formed message with no actionable effect (e.g. an ACK).
    NoOp,
}
