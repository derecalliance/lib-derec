// SPDX-License-Identifier: Apache-2.0

//! Higher-level protocol orchestrator for the DeRec protocol.
//!
//! This module provides [`DeRecProtocol`], a stateful orchestrator that wraps the
//! core protocol flows (pairing, sharing, verification, discovery, recovery). The
//! caller supplies concrete implementations of:
//!
//! - [`DeRecChannelStore`] — paired-channel record storage
//! - [`DeRecShareStore`] — secret share storage
//! - [`DeRecSecretStore`] — cryptographic key storage
//! - [`DeRecTransport`] — outbound message delivery
//!
//! The application feeds incoming wire bytes to [`DeRecProtocol::process`] and
//! reacts to the returned [`DeRecEvent`] values. All routing, state persistence,
//! and reply sending are handled internally.

pub mod error;
pub mod events;
pub(crate) mod pending_action_wire;
pub mod reserved_keys;
pub mod traits;
pub mod types;

mod builder;
mod handlers;

use crate::{
    Error, Result, primitives::pairing::request::create_contact as create_contact_message,
    types::ChannelId,
};
pub use builder::DeRecProtocolBuilder;
use derec_proto::{
    ContactMessage, ContactMode, DeRecMessage, GetShareResponseMessage, StatusEnum,
    TransportProtocol,
};
pub use error::{ChannelStoreError, ProcessError, SecretStoreError, ShareStoreError};
use prost::Message;
use std::collections::{HashMap, HashSet};
pub use traits::{
    ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    SecretStoreFuture, ShareStoreFuture, TransportFuture,
};
pub use types::{
    Channel, ChannelShare, ChannelStatus, HelperInfo, MissingPolicy, ReplicaInfo,
    ReplicaSecretPayload, SecretContainer, SecretKind, SecretValue, Share, Target, UserSecret,
};

/// In-progress recovery accumulators keyed by `(secret_id, version)`.
///
/// Each entry collects [`GetShareResponseMessage`] values for a pending recovery
/// context until enough shares arrive for reconstruction.
pub(super) type PendingRecovery = HashMap<(u64, u32), Vec<GetShareResponseMessage>>;

/// In-progress unpair requests keyed by `channel_id`, with the `started_at`
/// (epoch seconds) the orchestrator stamped when it sent the request.
///
/// Only populated under [`crate::protocol::events::UnpairAck::Required`];
/// under [`UnpairAck::NotRequired`](crate::protocol::events::UnpairAck::NotRequired)
/// state is dropped immediately and this map is never touched.
pub(super) type PendingUnpair = HashMap<ChannelId, u64>;

/// Tracks an in-progress sharing round.
///
/// Created when [`DeRecFlow::ProtectSecret`] is started and consumed when all
/// targeted Helpers have responded (confirmed, rejected, or timed out).
struct SharingRound {
    version: u32,
    /// Channels that have not yet responded.
    pending: HashSet<ChannelId>,
    /// Channels that confirmed storage.
    confirmed: HashSet<ChannelId>,
    /// Channels that rejected or timed out.
    failed: HashSet<ChannelId>,
    /// Timestamp (seconds since epoch) when the round was started.
    started_at: u64,
}

pub use events::{DeRecEvent, DeRecFlow, PendingAction, UnpairAck};

#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;
#[cfg(target_arch = "wasm32")]
use crate::wasm::now_secs;

/// Internal state of the single secret container managed by the protocol.
///
/// Created on the first `ProtectSecret` flow and reused (with incrementing
/// version) on every subsequent call.
/// Higher-level DeRec protocol orchestrator.
///
/// Generic over:
/// - `ChannelStore` — paired channel storage ([`DeRecChannelStore`])
/// - `ShareStore`   — share storage ([`DeRecShareStore`])
/// - `SecretStore`  — secret storage ([`DeRecSecretStore`])
/// - `Transport`    — outbound transport ([`DeRecTransport`])
///
/// The caller provides concrete implementations; the library imposes no
/// runtime or I/O requirements.
///
/// # Lifecycle
///
/// ```text
/// DeRecProtocol::new(channel_store, share_store, secret_store, transport, own_endpoint)
///   │
///   ├── create_contact / start(Pairing)          → pairing
///   ├── start(ProtectSecret)                     → sharing
///   ├── start(VerifyShares)                      → verification
///   ├── start(Pairing { Owner })           (recovery re-pair)
///   │     └── start(Discovery)                   → discovery  (emits SecretsDiscovered)
///   └── start(RecoverSecret)                     → recovery   (emits SecretRecovered)
///
/// loop { process(incoming_bytes) → Vec<DeRecEvent> }
/// ```
pub struct DeRecProtocol<
    ChannelStore: DeRecChannelStore,
    ShareStore: DeRecShareStore,
    SecretStore: DeRecSecretStore,
    Transport: DeRecTransport,
> {
    /// Set via [`DeRecProtocolBuilder::with_channel_store`].
    pub channel_store: ChannelStore,
    /// Set via [`DeRecProtocolBuilder::with_share_store`].
    pub share_store: ShareStore,
    /// Set via [`DeRecProtocolBuilder::with_secret_store`].
    pub secret_store: SecretStore,
    /// Set via [`DeRecProtocolBuilder::with_transport`].
    pub transport: Transport,
    /// Set via [`DeRecProtocolBuilder::with_own_transport`].
    pub own_transport: TransportProtocol,
    pending_recovery: PendingRecovery,
    /// Channels with an outstanding unpair request awaiting the peer's
    /// acknowledgement (Required mode only — see [`UnpairAck`]).
    pending_unpair: PendingUnpair,
    /// Configured via [`DeRecProtocolBuilder::with_unpair_ack`].
    pub(crate) unpair_ack: UnpairAck,
    /// Events produced by [`Self::start`] that don't fit the "no events from
    /// start; only from process" public contract. Drained at the top of every
    /// [`Self::process`] call. Today this exists solely for
    /// `UnpairAck::NotRequired`, which has to surface `Unpaired` immediately
    /// (no inbound response is coming).
    pending_start_events: Vec<DeRecEvent>,
    /// Configured via [`DeRecProtocolBuilder::with_threshold`].
    threshold: usize,
    /// Configured via [`DeRecProtocolBuilder::with_keep_versions_count`].
    keep_versions_count: usize,
    /// Configured via [`DeRecProtocolBuilder::with_timeout`].
    timeout_in_secs: u64,
    /// Configured via [`DeRecProtocolBuilder::with_communication_info`].
    pub(crate) communication_info: HashMap<String, String>,
    /// Configured via [`DeRecProtocolBuilder::with_auto_respond_on_failure`].
    pub(crate) auto_respond_on_failure: bool,
    /// Configured via [`DeRecProtocolBuilder::with_auto_reply_to`].
    ///
    /// When `true`, every outbound request envelope is stamped with
    /// `request.reply_to = self.own_transport` so the responder knows which
    /// endpoint to route the response to. When `false` (the default),
    /// outbound requests leave `reply_to` unset and the responder falls back
    /// to the channel's stored peer endpoint. See `replyTo` on each request
    /// proto for the wire-level semantics.
    pub(crate) auto_reply_to: bool,
    /// Active sharing round, if any. Populated by `start(ProtectSecret)` and
    /// consumed when all targeted Helpers respond or time out.
    sharing_round: Option<SharingRound>,
    /// Configured via [`DeRecProtocolBuilder::with_replica_id`].
    ///
    /// `Some(id)` enables this node to participate in replica-mode pairings
    /// (the id is auto-injected under `derec.replica_id` in outbound
    /// `PairRequest`/`PairResponse`, and required to honour inbound replica
    /// pairings). `None` disables replica flows entirely — any attempt to
    /// initiate or accept a replica-mode pairing returns
    /// [`Error::ReplicaIdNotConfigured`](crate::Error::ReplicaIdNotConfigured).
    pub(crate) replica_id: Option<u64>,
}

impl<Ch: DeRecChannelStore, Sh: DeRecShareStore, Ss: DeRecSecretStore, T: DeRecTransport>
    DeRecProtocol<Ch, Sh, Ss, T>
{
    /// Construct a new [`DeRecProtocol`] with the provided stores, transport, and own endpoint.
    ///
    /// Prefer [`DeRecProtocolBuilder`] for a compile-time-checked construction path.
    pub fn new(
        channel_store: Ch,
        share_store: Sh,
        secret_store: Ss,
        transport: T,
        own_transport: TransportProtocol,
        threshold: usize,
        keep_versions_count: usize,
        timeout_in_secs: u64,
    ) -> Self {
        Self {
            channel_store,
            share_store,
            secret_store,
            transport,
            own_transport,
            pending_recovery: HashMap::new(),
            pending_unpair: HashMap::new(),
            unpair_ack: UnpairAck::Required,
            pending_start_events: Vec::new(),
            threshold,
            keep_versions_count,
            timeout_in_secs,
            communication_info: HashMap::new(),
            auto_respond_on_failure: false,
            auto_reply_to: false,
            sharing_round: None,
            replica_id: None,
        }
    }

    /// Returns the configured local replica id, or `None` if the protocol
    /// was built without [`DeRecProtocolBuilder::with_replica_id`].
    ///
    /// Apps can use this to surface "replica flows are enabled" to the user,
    /// or to inspect their own identity for logging/diagnostics. The id is
    /// the same value that the orchestrator auto-injects under
    /// `derec.replica_id` in outbound replica-mode `PairRequest` /
    /// `PairResponse` envelopes.
    pub fn replica_id(&self) -> Option<u64> {
        self.replica_id
    }

    /// Generate an out-of-band contact message (QR code payload, deep link, …).
    ///
    /// Either party (Owner or Helper) may call this to begin a pairing session.
    /// The returned [`ContactMessage`] should be delivered out-of-band to the peer
    /// (e.g. serialized into a QR code or deep link). The ephemeral pairing secret
    /// is persisted automatically via `secret_store`.
    ///
    /// # Channel ID
    ///
    /// Pass `Some(id)` to use a specific channel identifier, or `None` to have
    /// the library generate a random one. The channel ID is embedded in the
    /// returned [`ContactMessage`] and should be treated as the canonical
    /// identifier for this pairing session going forward.
    ///
    /// # Contact mode
    ///
    /// - [`ContactMode::InlineKeys`] embeds the initiator's ML-KEM + ECIES
    ///   public keys directly in the contact. Simplest to use; the contact is
    ///   ~1.2 KB.
    /// - [`ContactMode::HashedKeys`] embeds only a SHA-384 binding hash over
    ///   the keys. The contact stays small enough for a QR code; the scanner
    ///   obtains the real keys via a `PrePair` round-trip and validates them
    ///   against the hash. Requires the `own_transport` set on this protocol
    ///   to be **ephemeral** — the plaintext PrePair traffic must not be
    ///   linkable to a long-lived endpoint.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn create_contact(
        &mut self,
        channel_id: Option<ChannelId>,
        contact_mode: ContactMode,
    ) -> Result<ContactMessage> {
        let channel_id = channel_id.unwrap_or_else(|| ChannelId(rand::random::<u64>()));

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel_id.0,
            contact_mode = contact_mode as i32,
            "creating contact message"
        );

        let result = create_contact_message(
            channel_id,
            contact_mode,
            self.own_transport.clone(),
        )?;

        self.secret_store
            .save(channel_id, SecretValue::PairingSecret(result.secret_key))
            .await?;

        #[cfg(feature = "logging")]
        tracing::info!(channel_id = channel_id.0, "contact message created");

        Ok(result.contact_message)
    }

    /// Replace this node's local communication info.
    ///
    /// Only mutates local state — to propagate the change to paired peers,
    /// follow up with [`DeRecFlow::UpdateChannelInfo`].
    ///
    /// # Destructive replacement
    ///
    /// The supplied map fully replaces the current value. An empty map will
    /// be transmitted as "clear all entries" when a subsequent
    /// `UpdateChannelInfo` flow runs, which the peer will mirror into its
    /// stored map. Pass the complete new map, not a delta.
    pub fn set_communication_info(&mut self, info: HashMap<String, String>) {
        self.communication_info = info;
    }

    /// Replace this node's local transport endpoint.
    ///
    /// Only mutates local state — to propagate the change to paired peers,
    /// follow up with [`DeRecFlow::UpdateChannelInfo`].
    ///
    /// # Endpoint changeover discipline
    ///
    /// When `UpdateChannelInfo` is broadcast, each receiving peer routes its
    /// response (and all subsequent messages) to the NEW endpoint. The
    /// application MUST therefore:
    ///
    /// 1. Bring up the new endpoint and start listening on it **before**
    ///    initiating the `UpdateChannelInfo` flow.
    /// 2. Keep the old endpoint operational during the changeover. Peers
    ///    that have not yet processed the update still route to the old
    ///    address; in-flight messages may also be targeted there.
    /// 3. Retire the old endpoint only once every targeted peer has
    ///    surfaced [`DeRecEvent::ChannelInfoUpdated`] (or
    ///    [`DeRecEvent::ChannelInfoUpdateRejected`]), plus a grace window
    ///    for in-flight traffic.
    ///
    /// Failing to keep both endpoints reachable during this window will
    /// cause messages to be lost.
    pub fn set_own_transport(&mut self, transport: TransportProtocol) {
        self.own_transport = transport;
    }

    /// Unified entry point for initiating any protocol flow.
    ///
    /// Returns `Some(channel_id)` for [`DeRecFlow::Pairing`], `None` for all others.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn start(&mut self, flow: DeRecFlow) -> Result<Option<u64>> {
        // When `auto_reply_to` is enabled, stamp every outbound
        // channel-mode request with our own transport so the responder
        // routes its reply back to us — even if the channel's stored
        // peer endpoint points elsewhere (e.g. a sibling replica).
        // Pairing has its own dedicated `transport_protocol` field so
        // it's intentionally excluded.
        let reply_to = self.auto_reply_to.then(|| self.own_transport.clone());

        match flow {
            DeRecFlow::Pairing {
                kind,
                contact,
                peer_communication_info,
            } => self.start_pairing(kind, contact, peer_communication_info).await,
            DeRecFlow::Discovery { target } => self.start_discovery(target, reply_to).await,
            DeRecFlow::ProtectSecret {
                secret_id,
                target,
                secrets,
                description,
            } => {
                self.start_protect_secret(secret_id, target, secrets, description, reply_to)
                    .await
            }
            DeRecFlow::VerifyShares {
                secret_id,
                version,
                target,
            } => self.start_verify_shares(secret_id, version, target, reply_to).await,
            DeRecFlow::RecoverSecret { secret_id, version } => {
                self.start_recover_secret(secret_id, version, reply_to).await
            }
            DeRecFlow::Unpair { target, memo } => self.start_unpair(target, memo, reply_to).await,
            DeRecFlow::UpdateChannelInfo {
                target,
                communication_info,
                transport_protocol,
            } => {
                self.start_update_channel_info(target, communication_info, transport_protocol)
                    .await
            }
        }
    }

    async fn start_pairing(
        &mut self,
        kind: derec_proto::SenderKind,
        contact: derec_proto::ContactMessage,
        peer_communication_info: HashMap<String, String>,
    ) -> Result<Option<u64>> {
        let channel_id = handlers::pairing::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &self.transport,
            &self.own_transport,
            &self.communication_info,
            kind,
            contact,
            peer_communication_info,
            self.replica_id,
        )
        .await?;
        Ok(Some(channel_id))
    }

    async fn start_discovery(
        &mut self,
        target: crate::protocol::types::Target,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Option<u64>> {
        let resolved =
            handlers::resolve_target(&mut self.channel_store, target.clone()).await?;
        handlers::require_role(&self.channel_store, &resolved, derec_proto::SenderKind::Owner)
            .await?;
        handlers::discovery::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &self.transport,
            target,
            reply_to,
        )
        .await?;
        Ok(None)
    }

    async fn start_protect_secret(
        &mut self,
        secret_id: u64,
        target: crate::protocol::types::Target,
        secrets: Vec<crate::protocol::types::UserSecret>,
        description: Option<String>,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Option<u64>> {
        let resolved =
            handlers::resolve_target(&mut self.channel_store, target.clone()).await?;
        // ProtectSecret accepts channels where the local kind is Owner
        // (peer is a Helper — the classic share path) OR ReplicaSource
        // (peer is a ReplicaDestination — vault sync). Channels where
        // the local kind is Helper are not legitimate ProtectSecret
        // initiators and are refused.
        for channel_id in &resolved {
            let channel = self
                .channel_store
                .load(*channel_id)
                .await?
                .ok_or(Error::InvalidInput(
                    "channel id not present in channel store",
                ))?;
            if !matches!(
                channel.role,
                derec_proto::SenderKind::Owner | derec_proto::SenderKind::ReplicaSource
            ) {
                return Err(Error::RoleMismatch {
                    channel_id: *channel_id,
                    expected: derec_proto::SenderKind::Owner,
                    actual: channel.role,
                });
            }
            // Replica channels start `Pending` after pair-handshake
            // completion and only transition to `Paired` once both
            // sides confirm the fingerprint out-of-band. Refusing
            // `ProtectSecret` against a `Pending` target prevents a
            // MITM-leaning peer from receiving the vault before
            // verification.
            if channel.status == crate::protocol::types::ChannelStatus::Pending {
                return Err(Error::InvalidInput(
                    "ProtectSecret target is still Pending — \
                     verify the fingerprint before distributing",
                ));
            }
        }
        let (version, sent_channels) = handlers::sharing::start(
            &mut self.channel_store,
            &mut self.share_store,
            &mut self.secret_store,
            &self.transport,
            secrets,
            description,
            self.threshold,
            self.keep_versions_count,
            secret_id,
            target,
            reply_to,
            self.replica_id,
        )
        .await?;

        self.sharing_round = Some(SharingRound {
            version,
            pending: sent_channels.into_iter().collect(),
            confirmed: HashSet::new(),
            failed: HashSet::new(),
            started_at: now_secs(),
        });

        Ok(None)
    }

    async fn start_verify_shares(
        &mut self,
        secret_id: u64,
        version: u32,
        target: crate::protocol::types::Target,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Option<u64>> {
        let resolved =
            handlers::resolve_target(&mut self.channel_store, target.clone()).await?;
        handlers::require_role(&self.channel_store, &resolved, derec_proto::SenderKind::Owner)
            .await?;
        handlers::verification::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &self.transport,
            version,
            target,
            secret_id,
            reply_to,
        )
        .await?;
        Ok(None)
    }

    async fn start_recover_secret(
        &mut self,
        secret_id: u64,
        version: u32,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Option<u64>> {
        let all_paired: Vec<crate::types::ChannelId> = self
            .channel_store
            .channels()
            .await?
            .iter()
            .map(|c| c.id)
            .collect();
        handlers::require_role(
            &self.channel_store,
            &all_paired,
            derec_proto::SenderKind::Owner,
        )
        .await?;
        handlers::recovery::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &self.transport,
            &mut self.pending_recovery,
            secret_id,
            version,
            reply_to,
        )
        .await?;
        Ok(None)
    }

    async fn start_unpair(
        &mut self,
        target: crate::protocol::types::Target,
        memo: Option<String>,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Option<u64>> {
        let resolved =
            handlers::resolve_target(&mut self.channel_store, target.clone()).await?;
        handlers::require_role(&self.channel_store, &resolved, derec_proto::SenderKind::Owner)
            .await?;
        // The handler returns immediate `Unpaired` events for the
        // `UnpairAck::NotRequired` path; the wait-for-ack path returns
        // nothing here and the events surface later from `process()`
        // (on the response) or the timeout sweep. Events are stashed
        // on the protocol for the next `process()` to drain so callers
        // observing the synchronous stream see them.
        let events = handlers::unpairing::start(
            &mut self.channel_store,
            &mut self.share_store,
            &mut self.secret_store,
            &self.transport,
            &mut self.pending_unpair,
            target,
            memo,
            self.unpair_ack,
            now_secs(),
            reply_to,
        )
        .await?;
        self.pending_start_events.extend(events);
        Ok(None)
    }

    async fn start_update_channel_info(
        &mut self,
        target: crate::protocol::types::Target,
        communication_info: Option<HashMap<String, String>>,
        transport_protocol: Option<derec_proto::TransportProtocol>,
    ) -> Result<Option<u64>> {
        handlers::update_channel_info::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &self.transport,
            target,
            communication_info,
            transport_protocol,
        )
        .await?;
        Ok(None)
    }

    /// Accept a pending action from an [`DeRecEvent::ActionRequired`] event.
    ///
    /// Executes the "do work + send response" path for the given action,
    /// returning the same events that auto-respond would have produced.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn accept(&mut self, action: PendingAction) -> Result<Vec<DeRecEvent>> {
        match action {
            PendingAction::Pairing {
                channel_id,
                request,
                pairing_secret,
                kind,
                trace_id,
                ..
            } => {
                handlers::pairing::accept(
                    &mut self.channel_store,
                    &mut self.secret_store,
                    &self.transport,
                    &self.communication_info,
                    channel_id,
                    &request,
                    &pairing_secret,
                    kind,
                    trace_id,
                    self.replica_id,
                )
                .await
            }
            PendingAction::StoreShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::sharing::accept(
                    &mut self.channel_store,
                    &mut self.share_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    trace_id,
                )
                .await
            }
            PendingAction::VerifyShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::verification::accept(
                    &mut self.channel_store,
                    &mut self.share_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    trace_id,
                )
                .await
            }
            PendingAction::Discovery {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::discovery::accept(
                    &mut self.channel_store,
                    &mut self.share_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    trace_id,
                )
                .await
            }
            PendingAction::GetShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::recovery::accept(
                    &mut self.channel_store,
                    &mut self.share_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    trace_id,
                )
                .await
            }
            PendingAction::Unpair {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::unpairing::accept(
                    &mut self.channel_store,
                    &mut self.share_store,
                    &mut self.secret_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    trace_id,
                )
                .await
            }
            PendingAction::UpdateChannelInfo {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::update_channel_info::accept(
                    &mut self.channel_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    trace_id,
                )
                .await
            }
            PendingAction::PrePair {
                channel_id,
                request,
                trace_id,
            } => {
                handlers::pairing::accept_pre_pair(
                    &mut self.secret_store,
                    &self.transport,
                    channel_id,
                    &request,
                    trace_id,
                )
                .await
            }
        }
    }

    /// Reject a pending action from an [`DeRecEvent::ActionRequired`] event.
    ///
    /// Builds and sends a rejection response to the peer with the given status
    /// and memo. The `status` parameter allows the caller to specify the exact
    /// failure reason (e.g. [`StatusEnum::Rejected`], [`StatusEnum::Fail`],
    /// [`StatusEnum::TooFrequent`], etc.).
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn reject(
        &mut self,
        action: PendingAction,
        status: StatusEnum,
        memo: &str,
    ) -> Result<()> {
        match action {
            PendingAction::Pairing {
                channel_id,
                request,
                trace_id,
                ..
            } => {
                handlers::pairing::reject(
                    &mut self.secret_store,
                    &self.transport,
                    &self.communication_info,
                    channel_id,
                    &request,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
            PendingAction::StoreShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::sharing::reject(
                    &mut self.channel_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
            PendingAction::VerifyShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::verification::reject(
                    &mut self.channel_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
            PendingAction::Discovery {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::discovery::reject(
                    &mut self.channel_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
            PendingAction::GetShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::recovery::reject(
                    &mut self.channel_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
            PendingAction::Unpair {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::unpairing::reject(
                    &mut self.channel_store,
                    &self.transport,
                    channel_id,
                    &request,
                    &shared_key,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
            PendingAction::UpdateChannelInfo {
                channel_id,
                shared_key,
                trace_id,
                ..
            } => {
                handlers::update_channel_info::reject(
                    &mut self.channel_store,
                    &self.transport,
                    channel_id,
                    &shared_key,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
            PendingAction::PrePair {
                channel_id,
                request,
                trace_id,
            } => {
                handlers::pairing::reject_pre_pair(
                    &self.transport,
                    channel_id,
                    &request,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
        }
    }

    /// Feed any incoming wire bytes here regardless of which flow they belong to.
    ///
    /// The library:
    ///
    /// 1. Decodes the outer [`DeRecMessage`] envelope to read `channel_id`
    /// 2. Looks up the channel's key material to determine the message kind
    /// 3. Dispatches to the appropriate message handler based on the channel state
    /// 4. Returns the events the application should react to
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(message_len = message.len()))
    )]
    pub async fn process(
        &mut self,
        message: &[u8],
    ) -> std::result::Result<Vec<DeRecEvent>, ProcessError> {
        let _ = self.cleanup_expired_channels().await;

        let mut start_events = std::mem::take(&mut self.pending_start_events);
        let mut timeout_events = self.check_sharing_round_timeouts();
        let mut unpair_timeout_events = self.check_unpair_timeouts().await;

        let envelope = DeRecMessage::decode(message).map_err(|e| ProcessError {
            channel_id: None,
            source: Error::ProtobufDecode(e),
        })?;
        let channel_id = ChannelId(envelope.channel_id);

        let result = self.process_inner(&envelope, channel_id).await;
        let mut events = result.map_err(|source| ProcessError {
            channel_id: Some(channel_id),
            source,
        })?;

        // Ordering: deferred-from-start events first (so the app sees them
        // before any inbound-message reactions), then sharing-round
        // timeouts, then unpair timeouts, then events produced by this
        // specific message.
        start_events.append(&mut timeout_events);
        start_events.append(&mut unpair_timeout_events);
        start_events.append(&mut events);
        let mut events = start_events;

        self.update_sharing_round(&mut events);

        Ok(events)
    }

    async fn process_inner(
        &mut self,
        message: &DeRecMessage,
        channel_id: ChannelId,
    ) -> Result<Vec<DeRecEvent>> {
        if self.is_message_expired(message, channel_id) {
            return Ok(vec![DeRecEvent::NoOp]);
        }

        if let Some(events) = self.process_channel_message(message, channel_id).await? {
            return Ok(events);
        }

        if let Some(events) = self.process_pairing_message(message, channel_id).await? {
            return Ok(events);
        }

        #[cfg(feature = "logging")]
        tracing::warn!(channel_id = channel_id.0, "no key material for channel");

        Err(Error::InvalidInput(
            "unknown channel_id: no shared key or pairing secret found",
        ))
    }

    /// Compute the fingerprint for a paired channel.
    ///
    /// Returns a formatted string like `"1234-5678-9012-3456"` derived from
    /// the channel's shared key via SHA-256. Both parties will derive the same
    /// fingerprint for the same shared key, enabling visual out-of-band
    /// verification.
    ///
    /// Returns an error if the channel has no shared key (not yet paired).
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(channel_id = channel_id.0)))]
    pub async fn get_fingerprint(&self, channel_id: ChannelId) -> Result<String> {
        let shared_key = match self
            .secret_store
            .load(channel_id, SecretKind::SharedKey)
            .await?
        {
            Some(SecretValue::SharedKey(key)) => key,
            _ => {
                return Err(Error::InvalidInput(
                    "channel has no shared key — not yet paired",
                ));
            }
        };

        Ok(derec_cryptography::replica::fingerprint(&shared_key))
    }

    /// Verify that a fingerprint matches the one derived from a channel's shared key.
    ///
    /// If the fingerprint matches, the channel status is updated from `Pending`
    /// to `Paired`, enabling it to process protocol messages. Returns `true` on
    /// match, `false` otherwise. Returns an error if the channel has no shared key.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(channel_id = channel_id.0)))]
    pub async fn verify_fingerprint(
        &mut self,
        channel_id: ChannelId,
        fingerprint: &str,
    ) -> Result<bool> {
        let local = self.get_fingerprint(channel_id).await?;
        if local != fingerprint {
            return Ok(false);
        }

        // Update channel status to Paired.
        if let Some(mut channel) = self.channel_store.load(channel_id).await? {
            channel.status = crate::protocol::types::ChannelStatus::Paired;
            self.channel_store.save(channel).await?;
        }

        Ok(true)
    }

    fn is_message_expired(
        &self,
        envelope: &DeRecMessage,
        #[cfg_attr(not(feature = "logging"), allow(unused))] channel_id: ChannelId,
    ) -> bool {
        let Some(ts) = &envelope.timestamp else {
            return false;
        };
        let msg_secs = ts.seconds as u64;
        let now = now_secs();
        let age = now.saturating_sub(msg_secs);
        if age > self.timeout_in_secs {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                message_age_secs = age,
                timeout_secs = self.timeout_in_secs,
                "message discarded — older than configured timeout"
            );
            return true;
        }
        false
    }

    async fn process_channel_message(
        &mut self,
        message: &DeRecMessage,
        channel_id: ChannelId,
    ) -> Result<Option<Vec<DeRecEvent>>> {
        let Some(SecretValue::SharedKey(shared_key)) = self
            .secret_store
            .load(channel_id, SecretKind::SharedKey)
            .await?
        else {
            return Ok(None);
        };

        if let Some(channel) = self.channel_store.load(channel_id).await? {
            if channel.status == crate::protocol::types::ChannelStatus::Pending {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    channel_id = channel_id.0,
                    "message ignored — channel is pending fingerprint verification"
                );
                return Ok(Some(vec![DeRecEvent::NoOp]));
            }
        }

        let events = handlers::handle(
            &mut self.channel_store,
            &mut self.share_store,
            &mut self.secret_store,
            &self.transport,
            &mut self.pending_recovery,
            &mut self.pending_unpair,
            message,
            channel_id,
            &shared_key,
        )
        .await?;

        Ok(Some(events))
    }

    async fn process_pairing_message(
        &mut self,
        message: &DeRecMessage,
        channel_id: ChannelId,
    ) -> Result<Option<Vec<DeRecEvent>>> {
        use derec_proto::MessageBody;

        // Try the plaintext PrePair layer first. PrePair envelopes carry
        // a serialized `MessageBody` directly (no encryption — no shared
        // or asymmetric key exists yet), so they decode without crypto
        // material. ECIES ciphertext for the regular Pair flow won't
        // realistically decode to a valid `PrePair*` variant; if it ever
        // did, we fall through to the encrypted path below.
        if let Ok(inner) =
            crate::derec_message::extract_inner_plaintext_message(&message.message)
        {
            match inner {
                inner @ MessageBody::PrePairRequest(_) => {
                    // Initiator side: needs `PairingSecret` to answer.
                    // Routes through the regular pairing dispatcher
                    // (`pairing::handle`) — same shape as PairRequest /
                    // PairResponse handling, just with the inner already
                    // decoded so we skip the decryption step.
                    let Some(SecretValue::PairingSecret(pairing_secret)) = self
                        .secret_store
                        .load(channel_id, SecretKind::PairingSecret)
                        .await?
                    else {
                        return Ok(None);
                    };
                    let events = handlers::pairing::handle(
                        &mut self.channel_store,
                        &mut self.secret_store,
                        &inner,
                        channel_id,
                        &pairing_secret,
                        message.trace_id,
                        self.replica_id,
                    )
                    .await?;
                    return Ok(Some(events));
                }
                MessageBody::PrePairResponse(resp) => {
                    // Scanner side: needs the original HashedKeys contact
                    // (saved at `start` time) to validate the binding hash.
                    let Some(SecretValue::PairingContact(contact)) = self
                        .secret_store
                        .load(channel_id, SecretKind::PairingContact)
                        .await?
                    else {
                        return Ok(None);
                    };
                    let events = handlers::pairing::on_pre_pair_response(
                        &mut self.channel_store,
                        &mut self.secret_store,
                        &self.transport,
                        &self.own_transport,
                        &self.communication_info,
                        channel_id,
                        &contact,
                        &resp,
                        self.replica_id,
                    )
                    .await?;
                    return Ok(Some(events));
                }
                _ => {} // Fall through to the encrypted Pair path.
            }
        }

        // Regular (encrypted) Pair flow.
        let Some(SecretValue::PairingSecret(pairing_secret)) = self
            .secret_store
            .load(channel_id, SecretKind::PairingSecret)
            .await?
        else {
            return Ok(None);
        };

        let events = handlers::handle_pairing(
            &mut self.channel_store,
            &mut self.secret_store,
            message,
            channel_id,
            &pairing_secret,
            self.replica_id,
        )
        .await?;
        Ok(Some(events))
    }

    /// Check if any channels in the active sharing round have timed out.
    ///
    /// Returns `ShareRejected` events for timed-out channels and moves them
    /// from `pending` to `failed` in the round tracker.
    fn check_sharing_round_timeouts(&mut self) -> Vec<DeRecEvent> {
        let Some(round) = &mut self.sharing_round else {
            return vec![];
        };
        let now = now_secs();
        if now.saturating_sub(round.started_at) <= self.timeout_in_secs {
            return vec![];
        }
        let timed_out: Vec<ChannelId> = round.pending.drain().collect();
        let version = round.version;
        let mut events = Vec::with_capacity(timed_out.len());
        for channel_id in timed_out {
            round.failed.insert(channel_id);
            events.push(DeRecEvent::ShareRejected {
                channel_id,
                version,
                status: StatusEnum::Fail as i32,
                memo: "timeout".to_owned(),
            });

            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                version,
                "sharing round: helper timed out"
            );
        }
        events
    }

    /// Drop local state for any pending unpair whose acknowledgement window has
    /// elapsed, returning an `Unpaired` event per dropped channel.
    async fn check_unpair_timeouts(&mut self) -> Vec<DeRecEvent> {
        let now = now_secs();
        let expired: Vec<ChannelId> = self
            .pending_unpair
            .iter()
            .filter_map(|(cid, started_at)| {
                if now.saturating_sub(*started_at) > self.timeout_in_secs {
                    Some(*cid)
                } else {
                    None
                }
            })
            .collect();

        let mut events = Vec::with_capacity(expired.len());
        for cid in expired {
            self.pending_unpair.remove(&cid);
            if handlers::unpairing::drop_channel_state(
                &mut self.channel_store,
                &mut self.share_store,
                &mut self.secret_store,
                cid,
            )
            .await
            .is_ok()
            {
                events.push(DeRecEvent::Unpaired { channel_id: cid });
            }
        }
        events
    }

    /// Update the active sharing round based on events produced by `process_inner`.
    ///
    /// Moves channels from `pending` to `confirmed` or `failed` as
    /// `ShareConfirmed` / `ShareRejected` events arrive. When no channels
    /// remain pending, appends a [`DeRecEvent::SharingComplete`] summary.
    fn update_sharing_round(&mut self, events: &mut Vec<DeRecEvent>) {
        if self.sharing_round.is_none() {
            return;
        }

        let round = self.sharing_round.as_mut().unwrap();
        for event in events.iter() {
            match event {
                DeRecEvent::ShareConfirmed {
                    channel_id,
                    version,
                } if *version == round.version => {
                    round.pending.remove(channel_id);
                    round.confirmed.insert(*channel_id);
                }
                DeRecEvent::ShareRejected {
                    channel_id,
                    version,
                    ..
                } if *version == round.version => {
                    round.pending.remove(channel_id);
                    round.failed.insert(*channel_id);
                }
                _ => {}
            }
        }

        let is_complete = round.pending.is_empty();
        let version = round.version;
        let confirmed_count = round.confirmed.len();
        let failed_count = round.failed.len();

        if is_complete {
            let threshold_met = confirmed_count >= self.threshold;
            self.sharing_round = None;
            events.push(DeRecEvent::SharingComplete {
                version,
                confirmed_count,
                failed_count,
                threshold_met,
            });

            #[cfg(feature = "logging")]
            tracing::info!(
                version,
                confirmed_count,
                failed_count,
                threshold_met,
                "sharing round complete"
            );
        }
    }

    /// Remove pending channels that have exceeded the configured timeout,
    /// along with their associated pairing keys.
    ///
    /// Called automatically during [`process`](Self::process), but can also be
    /// invoked manually by the application.
    async fn cleanup_expired_channels(&mut self) -> Result<Vec<ChannelId>> {
        let now = now_secs();
        let timeout = self.timeout_in_secs;
        let channels = self.channel_store.channels().await?;

        let mut removed = Vec::new();
        for channel in channels {
            if channel.status == crate::protocol::types::ChannelStatus::Pending
                && now.saturating_sub(channel.created_at) > timeout
            {
                self.channel_store.remove(channel.id).await?;
                // Clean up any leftover pairing secret for this channel.
                let _ = self
                    .secret_store
                    .remove(channel.id, SecretKind::PairingSecret)
                    .await;
                let _ = self
                    .secret_store
                    .remove(channel.id, SecretKind::PairingContact)
                    .await;

                #[cfg(feature = "logging")]
                tracing::info!(
                    channel_id = channel.id.0,
                    elapsed_secs = now.saturating_sub(channel.created_at),
                    "expired pending channel removed"
                );

                removed.push(channel.id);
            }
        }
        Ok(removed)
    }
}
