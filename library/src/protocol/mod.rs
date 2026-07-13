// SPDX-License-Identifier: Apache-2.0

//! Higher-level protocol orchestrator for the DeRec protocol.
//!
//! This module provides [`DeRecProtocol`], a stateful orchestrator that wraps the
//! core protocol flows. The caller supplies concrete implementations of:
//!
//! - [`DeRecChannelStore`] — paired-channel record storage
//! - [`DeRecShareStore`] — secret share storage
//! - [`DeRecSecretStore`] — cryptographic key storage
//! - [`DeRecUserSecretStore`] — secret-snapshot storage for replica auto-publish
//! - [`DeRecTransport`] — outbound message delivery
//!
//! The application feeds incoming wire bytes to [`DeRecProtocol::process`] and
//! reacts to the returned [`DeRecEvent`] values. All routing, state persistence,
//! and reply sending are handled internally.
//!
//! # Flows
//!
//! Each `DeRecProtocol::start(DeRecFlow::…)` entry point drives one
//! protocol flow:
//!
//! - **Pairing** — establish a channel + derive a shared key with a peer.
//! - **ProtectSecret** (sharing) — VSS-split the current secret to every
//!   paired Helper and ship the full secret to every paired Replica.
//! - **VerifyShares** — challenge a Helper to prove it still holds a
//!   specific stored share via a SHA-384 commitment (see
//!   [`PendingVerification`] for the orchestrator-owned request/response
//!   binding map).
//! - **Discovery** — ask a Helper which `(secret_id, version)` tuples it
//!   currently holds for us. Frequently the precursor to `RecoverSecret`
//!   but useful for routine inventory too.
//! - **RecoverSecret** — collect enough Helper shares to reconstruct an
//!   earlier secret version.
//! - **Restore** — [`DeRecProtocol::restore`] commits a recovered
//!   [`crate::protocol::types::Secret`] into a fresh protocol instance:
//!   reseats canonical helper / replica channels at the recovered
//!   version and wipes the throwaway recovery-mode channels. Not a
//!   [`DeRecFlow`] variant — called once, directly on the protocol,
//!   after a `SecretRecovered` event surfaces.
//! - **UpdateChannelInfo** — broadcast updated `communication_info`
//!   and/or `transport_protocol` to one or more paired peers. Either
//!   side may initiate. The accompanying setters
//!   [`DeRecProtocol::set_communication_info`] and
//!   [`DeRecProtocol::set_own_transport`] update local state first; the
//!   flow then announces the change. The endpoint-changeover discipline
//!   on `set_own_transport` is required reading before broadcasting a
//!   transport update — both endpoints must remain reachable through
//!   the changeover or in-flight traffic will be lost.
//! - **Unpair** — Owner-initiated channel teardown. Ack semantics are
//!   governed by [`DeRecProtocolBuilder::with_unpair_ack`].
//!
//! See [`DeRecFlow`] for the per-variant role requirements and field
//! semantics.
//!
//! # Reserved `CommunicationInfo` keys
//!
//! `CommunicationInfo` is an opaque app-defined string map *except* for
//! entries under the `derec.*` namespace, which the library reserves
//! for its own use (e.g. carrying the sender's `replica_id` on
//! replica-mode pairing envelopes). Apps SHOULD NOT use this namespace;
//! the orchestrator silently auto-injects, extracts, and strips
//! `derec.*` entries at the protocol boundary. See
//! [`reserved_keys`] for the current set of keys and their wire
//! encoding.

pub mod error;
pub mod events;
pub(crate) mod pending_action_wire;
pub mod reserved_keys;
pub mod traits;
pub mod types;

mod builder;
mod handlers;

use crate::{
    Error, Result,
    primitives::pairing::request::create_contact as create_contact_message,
    types::ChannelId,
};
pub use builder::DeRecProtocolBuilder;
use derec_proto::{ContactMessage, ContactMode, DeRecMessage, StatusEnum, TransportProtocol};
pub use error::{
    ChannelStoreError, ProcessError, SecretStoreError, ShareStoreError, StateStoreError,
};
use prost::Message;
use std::collections::{HashMap, HashSet};
pub use traits::{
    ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore,
    DeRecTransport, DeRecUserSecretStore, SecretStoreFuture, ShareStoreFuture, StateStoreFuture,
    TransportFuture,
};
pub use types::{
    Channel, ChannelShare, ChannelStatus, HelperInfo, MissingPolicy, ReplicaInfo,
    ReplicaSecretPayload, Secret, SecretKind, SecretValue, Share, StateItem, StateKey, StateKind,
    Target, UserSecret, UserSecrets,
};


pub use events::{
    AutoAcceptPolicy, DeRecEvent, DeRecFlow, PendingAction, PendingActionKind, UnpairAck,
};
pub use handlers::restore::RestoreError;

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
/// DeRecProtocolBuilder::new(secret_id).<setters>.build()?
///   │
///   ├── create_contact / start(Pairing)          → pairing
///   ├── start(ProtectSecret)                     → sharing
///   ├── start(VerifyShares)                      → verification
///   ├── start(Pairing { Owner })                 (recovery re-pair)
///   │     └── start(Discovery)                   → discovery       (emits SecretsDiscovered)
///   ├── start(RecoverSecret)                     → recovery        (emits SecretRecovered)
///   │     └── restore(&secret, version)          → commit recovered secret into canonical state
///   ├── start(UpdateChannelInfo)                 → endpoint/info update (either side)
///   └── start(Unpair)                            → unpair          (Owner-initiated; ack
///                                                                   semantics governed by
///                                                                   [`DeRecProtocolBuilder::with_unpair_ack`])
///
/// loop { process(incoming_bytes) → Vec<DeRecEvent> }
/// ```
///
/// See [`DeRecFlow`] for the full set of orchestrator entry points
/// and the role each requires on the targeted channel(s).
pub struct DeRecProtocol<
    ChannelStore: DeRecChannelStore,
    ShareStore: DeRecShareStore,
    SecretStore: DeRecSecretStore,
    UserSecretStore: DeRecUserSecretStore,
    StateStore: DeRecStateStore,
    Transport: DeRecTransport,
> {
    /// Set via [`DeRecProtocolBuilder::with_channel_store`].
    pub channel_store: ChannelStore,
    /// Set via [`DeRecProtocolBuilder::with_share_store`].
    pub share_store: ShareStore,
    /// Set via [`DeRecProtocolBuilder::with_secret_store`].
    pub secret_store: SecretStore,
    /// Set via [`DeRecProtocolBuilder::with_user_secret_store`].
    pub user_secret_store: UserSecretStore,
    /// Set via [`DeRecProtocolBuilder::with_state_store`]. Holds
    /// in-flight orchestrator state (verification challenges, recovery
    /// accumulators, pending unpair acks) so stateless / load-balanced
    /// deployments preserve it across process restarts.
    pub state_store: StateStore,
    /// Set via [`DeRecProtocolBuilder::with_transport`].
    pub transport: Transport,
    /// Set via [`DeRecProtocolBuilder::with_own_transport`].
    pub own_transport: TransportProtocol,
    /// Configured via [`DeRecProtocolBuilder::with_unpair_ack`].
    pub(crate) unpair_ack: UnpairAck,
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
    /// Configured via [`DeRecProtocolBuilder::with_auto_accept`].
    ///
    /// When a flow's field on the policy is `true`, [`Self::process`]
    /// invokes the equivalent of [`Self::accept`] internally for that
    /// flow and emits [`DeRecEvent::AutoAccepted`] in place of
    /// [`DeRecEvent::ActionRequired`].
    pub(crate) auto_accept: AutoAcceptPolicy,
    /// Configured via [`DeRecProtocolBuilder::with_replica_id`].
    ///
    /// `Some(id)` enables this node to participate in replica-mode pairings
    /// (the id is auto-injected under `derec.replica_id` in outbound
    /// `PairRequest`/`PairResponse`, and required to honour inbound replica
    /// pairings). `None` disables replica flows entirely — any attempt to
    /// initiate or accept a replica-mode pairing returns
    /// [`Error::ReplicaIdNotConfigured`](crate::Error::ReplicaIdNotConfigured).
    pub(crate) replica_id: Option<u64>,
    /// Configured via [`DeRecProtocolBuilder::with_parameter_range`].
    ///
    /// `Some(range)` advertises the local node's acceptable bounds in
    /// outbound `PairRequest` / `PairResponse` envelopes and validates
    /// the peer's advertised range on inbound ones. `None` declares no
    /// constraints — every peer range is accepted and outbound
    /// envelopes omit the field.
    pub(crate) parameter_range: Option<derec_proto::ParameterRange>,
    /// Identifier of the single secret this protocol instance manages.
    ///
    /// Set at construction (`DeRecProtocolBuilder::new(secret_id)`) and
    /// never changes — apps that juggle multiple secrets instantiate one
    /// protocol per `secret_id`.
    secret_id: u64,
}

impl<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
> DeRecProtocol<Ch, Sh, Ss, Us, St, T>
{

    /// Construct a [`DeRecProtocol`] directly from its components.
    ///
    /// Prefer [`DeRecProtocolBuilder`] for the type-checked
    /// construction path; both entry points run the same runtime
    /// validation and surface the same errors.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidInput`] if `threshold < 2`. A
    /// threshold of `0` or `1` collapses threshold secret sharing and
    /// lets a single helper reconstruct the secret unilaterally — two
    /// is the minimum value that preserves secret confidentiality
    /// against one compromised helper.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret_id: u64,
        channel_store: Ch,
        share_store: Sh,
        secret_store: Ss,
        user_secret_store: Us,
        state_store: St,
        transport: T,
        own_transport: TransportProtocol,
        threshold: usize,
        keep_versions_count: usize,
        timeout_in_secs: u64,
    ) -> Result<Self> {
        if threshold < 2 {
            return Err(crate::Error::InvalidInput(
                "threshold must be >= 2; 0 or 1 lets a single helper reconstruct the secret \
                 and defeats threshold sharing",
            ));
        }
        Ok(Self {
            channel_store,
            share_store,
            secret_store,
            user_secret_store,
            state_store,
            transport,
            own_transport,
            unpair_ack: UnpairAck::Required,
            threshold,
            keep_versions_count,
            timeout_in_secs,
            communication_info: HashMap::new(),
            auto_respond_on_failure: false,
            auto_reply_to: false,
            auto_accept: AutoAcceptPolicy::default(),
            replica_id: None,
            parameter_range: None,
            secret_id,
        })
    }

    /// Returns the secret identifier this protocol instance was configured with.
    pub fn secret_id(&self) -> u64 {
        self.secret_id
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
    /// The returned [`ContactMessage`] should be delivered out-of-band to the peer.
    /// Any material the library needs later — either the ephemeral pairing
    /// secret (`InlineKeys` / `HashedKeys`) or the contact itself (`NoKeys`) —
    /// is persisted automatically via the configured stores.
    ///
    /// # Channel ID
    ///
    /// Pass `Some(id)` to use a specific channel identifier, or `None` to have
    /// the library generate a random one. Applications targeting `NoKeys` mode
    /// typically pass a small human-typable value (4 digits) for manual entry.
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
    /// - [`ContactMode::NoKeys`] carries no key material and no commitment —
    ///   only `channel_id`, `nonce`, and `transport_protocol`. Small enough
    ///   to be hand-typed. Keys are generated on the fly by the creator when
    ///   the corresponding `PrePairRequest` arrives; trust rests entirely on
    ///   the OOB delivery channel being fully trusted (e.g. a verified email
    ///   from an already-KYC-authenticated institution). Applications MUST
    ///   rate-limit inbound `PrePairRequest`s per `channel_id` and expire
    ///   outstanding NoKeys contacts on a short timer.
    ///
    /// # Nonce
    ///
    /// - `None`: the library generates a fresh cryptographically-random
    ///   `u64`. Recommended default for `InlineKeys` and `HashedKeys` where
    ///   the nonce is a security parameter.
    /// - `Some(n)`: application-controlled value. Required for `NoKeys`
    ///   where the recipient typically types it in; also valid for the
    ///   other modes if the app wants deterministic control.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn create_contact(
        &mut self,
        channel_id: Option<ChannelId>,
        contact_mode: ContactMode,
        nonce: Option<u64>,
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
            nonce,
        )?;

        // Persist the material the eventual `PrePairRequest` /
        // `PairRequest` handler will need to look up:
        // - `Some(secret_key)` on InlineKeys / HashedKeys → store as
        //   `PairingSecret`. Handler decrypts the encrypted PairRequest
        //   with the ECIES secret and re-publishes keys on the PrePair
        //   leg (HashedKeys only).
        // - `None` on NoKeys → store the contact itself as
        //   `PairingContact` so the incoming PrePairRequest handler can
        //   (a) authenticate the caller by matching `nonce`, and
        //   (b) generate fresh key material on the fly for the response.
        match result.secret_key {
            Some(secret_key) => {
                self.secret_store
                    .save(
                        self.secret_id,
                        channel_id,
                        SecretValue::PairingSecret(secret_key),
                    )
                    .await?;
            }
            None => {
                self.secret_store
                    .save(
                        self.secret_id,
                        channel_id,
                        SecretValue::PairingContact(result.contact_message.clone()),
                    )
                    .await?;
            }
        }

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
    /// Set the local node's transport endpoint.
    ///
    /// Accepts anything implementing
    /// [`IntoOwnTransport`](crate::transport::IntoOwnTransport): a
    /// typed [`crate::transport::TransportProtocol`], a `&str`, or a
    /// `String`. Validation runs eagerly — a malformed URI surfaces
    /// as [`crate::Error::Transport`] instead of being stored and
    /// later propagated to peers.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Transport`] if the supplied value
    /// fails URI validation (empty, oversize, control characters,
    /// or scheme mismatch).
    pub fn set_own_transport(
        &mut self,
        own_transport: impl crate::transport::IntoOwnTransport,
    ) -> crate::Result<()> {
        let tp = own_transport.into_own_transport()?;
        self.own_transport = tp.into();
        Ok(())
    }

    /// Unified entry point for initiating any protocol flow.
    ///
    /// Returns the flow's per-target `*Started` / `*Failed` events (one
    /// `PairingStarted` for [`DeRecFlow::Pairing`]; one per targeted
    /// channel for fan-out flows). See each `*Started` /
    /// `*Failed` variant on [`DeRecEvent`] for the per-flow shape.
    ///
    /// # Errors
    ///
    /// - Programmer errors (invalid input, missing preconditions, role
    ///   mismatch) surface as `Err` before any fan-out begins. Once
    ///   fan-out starts for a multi-target flow, per-channel transport
    ///   failures become `*Failed` events in the returned vec — they do
    ///   not abort the round.
    /// - Single-channel flows ([`DeRecFlow::Pairing`],
    ///   [`DeRecFlow::Unpair`]) return `Err` on send failure — no
    ///   `*Failed` event exists, so the single-`Err` signal is
    ///   unambiguous.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn start(&mut self, flow: DeRecFlow) -> Result<Vec<DeRecEvent>> {
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
            } => {
                self.start_pairing(kind, contact, peer_communication_info)
                    .await
            }
            DeRecFlow::Discovery { target } => self.start_discovery(target, reply_to).await,
            DeRecFlow::ProtectSecret {
                secrets,
                description,
            } => {
                self.start_protect_secret(secrets, description, reply_to)
                    .await
            }
            DeRecFlow::VerifyShares {
                secret_id,
                version,
                target,
            } => {
                self.start_verify_shares(secret_id, version, target, reply_to)
                    .await
            }
            DeRecFlow::RecoverSecret { secret_id, version } => {
                self.start_recover_secret(secret_id, version, reply_to)
                    .await
            }
            DeRecFlow::Unpair { channel_id, memo } => {
                self.start_unpair(channel_id, memo, reply_to).await
            }
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

    /// Accept a pending action from an [`DeRecEvent::ActionRequired`] event.
    ///
    /// Executes the "do work + send response" path for the given action,
    /// returning the same events that auto-respond would have produced.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn accept(&mut self, action: PendingAction) -> Result<Vec<DeRecEvent>> {
        let mut events = self.accept_inner(action).await?;
        let auto_publish_events = self.maybe_auto_publish_after_pair(&events).await?;
        events.extend(auto_publish_events);
        Ok(events)
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
                    self.secret_id,
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
                    self.secret_id,
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
                    self.secret_id,
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
                    self.secret_id,
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
                    self.secret_id,
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
                    self.secret_id,
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
                    self.secret_id,
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
    ///
    /// # Security: bounding inbound message size
    ///
    /// This function does **not** enforce an upper bound on `message.len()`,
    /// and no library entry point that ingests peer wire bytes does either.
    /// Legitimate envelopes span many orders of magnitude:
    ///
    /// - Tens of bytes for empty acks / ping-class messages.
    /// - A few KB for pairing material and verification proofs.
    /// - Hundreds of KB to several MB for `StoreShareRequest` carrying a
    ///   share of a large secret.
    /// - Many MB for `ReplicaSync` envelopes carrying an entire secret
    ///   (`O(num_secrets × num_helpers × max_secret_bytes)`).
    ///
    /// Any cap tight enough to provide meaningful DoS resistance would risk
    /// silently truncating a legitimate replica sync — at which point the
    /// secret can become unrecoverable. The protocol therefore delegates
    /// inbound-size bounding to the **application's transport layer**,
    /// which knows the deployment's max secret size, helper count, and
    /// replica fan-out and can pick a ceiling that fits.
    ///
    /// Callers MUST refuse oversized envelopes upstream (e.g. enforce a
    /// max HTTP body / WebSocket frame size consistent with their
    /// configuration) before handing bytes to this function.
    ///
    /// Malformed bytes — including truncation, varint overflow, and any
    /// `prost`-level decode failure — surface as
    /// [`ProcessError`] wrapping [`Error::ProtobufDecode`]. This function
    /// never panics on adversarial input. Protobuf recursion depth is
    /// bounded by `prost`'s decoder; DeRec's schema is shallow (~3 levels),
    /// so no additional caller-side recursion limit is required.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(message_len = message.len()))
    )]
    pub async fn process(
        &mut self,
        message: &[u8],
    ) -> std::result::Result<Vec<DeRecEvent>, ProcessError> {
        let _ = self.cleanup_expired_channels().await;

        let mut timeout_events = self.check_sharing_round_timeouts().await;
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

        // Auto-accept intercept: any `ActionRequired` in `events` whose
        // action kind the configured `AutoAcceptPolicy` opts into is
        // replaced in-place with `AutoAccepted` + the same flow events
        // a manual `accept(action)` would have produced. Errors from
        // the internal `accept_inner` propagate via `ProcessError`
        // exactly as a manual accept would surface them through the
        // caller's own error-handling — keeps the contract uniform.
        events = self
            .apply_auto_accept(events)
            .await
            .map_err(|source| ProcessError {
                channel_id: Some(channel_id),
                source,
            })?;

        // Ordering: sharing-round timeouts first, then unpair
        // timeouts, then events produced by this specific message.
        timeout_events.append(&mut unpair_timeout_events);
        timeout_events.append(&mut events);
        let mut events = timeout_events;

        self.update_sharing_round(&mut events).await;

        let auto_publish_events = self
            .maybe_auto_publish_after_pair(&events)
            .await
            .map_err(|source| ProcessError {
                channel_id: Some(channel_id),
                source,
            })?;
        events.extend(auto_publish_events);

        Ok(events)
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
            .load(self.secret_id, channel_id, SecretKind::SharedKey)
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
        let mut transitioned_replica = false;
        if let Some(mut channel) = self.channel_store.load(self.secret_id, channel_id).await? {
            transitioned_replica = channel.role == derec_proto::SenderKind::ReplicaSource
                && channel.status == crate::protocol::types::ChannelStatus::Pending;
            channel.status = crate::protocol::types::ChannelStatus::Paired;
            self.channel_store.save(self.secret_id, channel).await?;
        }

        // Replica destinations only become eligible publish targets once
        // the fingerprint is verified. Mirror the helper-pair hook in
        // `process()` so the newly-confirmed peer receives the current
        // secret without an explicit follow-up `ProtectSecret` call. The
        // Pending→Paired transition means at least one Replica
        // Destination is now paired, so the empty-payload fallback
        // always applies when no `UserSecrets` snapshot has been cached
        // yet.
        if transitioned_replica {
            let snapshot = self.user_secret_store.load_latest(self.secret_id).await?;
            let (secrets, description) = match snapshot {
                Some(s) => (s.secrets, s.description),
                None => (Vec::new(), None),
            };
            let reply_to = self.auto_reply_to.then(|| self.own_transport.clone());
            self.publish_secret(secrets, description, reply_to).await?;
        }

        Ok(true)
    }

    /// Rebuild this protocol's `secret_id` namespace from a
    /// [`crate::protocol::types::Secret`] handed up by a
    /// [`DeRecEvent::SecretRecovered`] event. See
    /// [`crate::protocol::restore`] for the design rationale.
    ///
    /// # Caller flow
    ///
    /// ```text
    /// fresh DeRecProtocol → empty stores
    ///   → re-pair with helpers on a fresh channel-id namespace
    ///   → start(RecoverSecret { secret_id, version })
    ///   → SecretRecovered { secret } event arrives
    ///   → DeRecProtocol::restore(&secret, version)
    /// ```
    ///
    /// On success: canonical helper channels are persisted with
    /// `SharedKey` + owner-side tracking shares at
    /// `recovered_version`; canonical replica channels are persisted
    /// with the group key from `secret.replicas.shared_key`;
    /// the user-secret snapshot is committed at `recovered_version`;
    /// the protocol's `replica_id` is adopted from
    /// `secret.owner_replica_id` if previously unset; every other
    /// channel under `self.secret_id` (i.e. the recovery-mode
    /// channels) is unpaired (request sent to the helper, local
    /// state dropped). The protocol resumes normal operation
    /// immediately — the next `start(ProtectSecret)` publishes
    /// `recovered_version + 1` to the restored helpers.
    ///
    /// The snapshot write is the commit point — nothing is removed
    /// before it succeeds. Any mid-flight failure leaves state the
    /// next `restore` call will detect as one of the precondition
    /// errors below.
    ///
    /// # Errors
    ///
    /// Precondition / invariant failures surface as
    /// [`Error::Restore`](crate::Error::Restore) wrapping one of:
    ///
    /// - [`RestoreError::AlreadyRestored`] when a user-secret
    ///   snapshot exists for this `secret_id`.
    /// - [`RestoreError::Conflict`] when one or more channels live
    ///   at canonical helper / replica ids carried by `secret`.
    /// - [`RestoreError::Invariant`] when the recovered `Secret`
    ///   is internally inconsistent (e.g. non-empty `replicas` with
    ///   empty `replicas.shared_key`).
    ///
    /// Store I/O failures mid-restore propagate as the underlying
    /// [`Error::ShareStore`](crate::Error::ShareStore),
    /// [`Error::ChannelStore`](crate::Error::ChannelStore), or
    /// [`Error::SecretStore`](crate::Error::SecretStore) variant.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn restore(
        &mut self,
        secret: &crate::protocol::types::Secret,
        recovered_version: u32,
    ) -> Result<Vec<DeRecEvent>> {
        handlers::restore::restore(
            &mut self.channel_store,
            &mut self.share_store,
            &mut self.secret_store,
            &mut self.user_secret_store,
            &self.transport,
            &mut self.state_store,
            &mut self.replica_id,
            self.secret_id,
            secret,
            recovered_version,
        )
        .await
    }

    async fn start_pairing(
        &mut self,
        kind: derec_proto::SenderKind,
        contact: derec_proto::ContactMessage,
        peer_communication_info: HashMap<String, String>,
    ) -> Result<Vec<DeRecEvent>> {
        let channel_id = handlers::pairing::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &self.transport,
            &self.own_transport,
            &self.communication_info,
            self.secret_id,
            kind,
            contact,
            peer_communication_info,
            self.replica_id,
            self.parameter_range,
        )
        .await?;
        Ok(vec![DeRecEvent::PairingStarted {
            channel_id: ChannelId(channel_id),
            kind,
        }])
    }

    async fn start_discovery(
        &mut self,
        target: crate::protocol::types::Target,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Vec<DeRecEvent>> {
        let resolved =
            handlers::resolve_target(&mut self.channel_store, self.secret_id, target.clone())
                .await?;
        handlers::require_role(
            &self.channel_store,
            self.secret_id,
            &resolved,
            derec_proto::SenderKind::Owner,
        )
        .await?;
        handlers::discovery::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &self.transport,
            self.secret_id,
            target,
            reply_to,
        )
        .await
    }

    async fn start_protect_secret(
        &mut self,
        secrets: Vec<crate::protocol::types::UserSecret>,
        description: Option<String>,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Vec<DeRecEvent>> {
        self.publish_secret(secrets, description, reply_to).await
    }

    /// Run one publish round: VSS-split for Helpers when the threshold is
    /// met, build the Replica composite payload with the share material
    /// embedded, and fan both out. A no-op (silent return) when no paired
    /// Helpers or Replicas exist.
    async fn publish_secret(
        &mut self,
        secrets: Vec<crate::protocol::types::UserSecret>,
        description: Option<String>,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Vec<DeRecEvent>> {
        let Some(round) = handlers::sharing::start(
            &mut self.channel_store,
            &mut self.share_store,
            &mut self.secret_store,
            &mut self.user_secret_store,
            &self.transport,
            secrets,
            description,
            self.threshold,
            self.keep_versions_count,
            self.secret_id,
            reply_to,
            self.replica_id,
        )
        .await?
        else {
            return Ok(Vec::new());
        };

        // Only channels whose dispatch succeeded count as `pending` in
        // the sharing round accumulator — a peer we couldn't reach on
        // send won't be responding, so it doesn't gate SharingComplete.
        let version = round.version;
        let pending: HashSet<ChannelId> = round
            .outcomes
            .iter()
            .filter_map(|(cid, r)| r.as_ref().ok().map(|_| *cid))
            .collect();

        if !pending.is_empty() {
            self.state_store
                .save(
                    self.secret_id,
                    StateItem::SharingRound {
                        version,
                        pending,
                        confirmed: HashSet::new(),
                        failed: HashSet::new(),
                        started_at: now_secs(),
                    },
                )
                .await?;
        }

        Ok(round
            .outcomes
            .into_iter()
            .map(|(channel_id, res)| match res {
                Ok(()) => DeRecEvent::ProtectSecretStarted {
                    channel_id,
                    version,
                },
                Err(e) => DeRecEvent::ProtectSecretFailed {
                    channel_id,
                    version,
                    error: e.to_string(),
                },
            })
            .collect())
    }

    async fn start_verify_shares(
        &mut self,
        secret_id: u64,
        version: u32,
        target: crate::protocol::types::Target,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Vec<DeRecEvent>> {
        let resolved =
            handlers::resolve_target(&mut self.channel_store, self.secret_id, target.clone())
                .await?;
        handlers::require_role(
            &self.channel_store,
            self.secret_id,
            &resolved,
            derec_proto::SenderKind::Owner,
        )
        .await?;
        handlers::verification::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &self.transport,
            &mut self.state_store,
            version,
            target,
            secret_id,
            reply_to,
        )
        .await
    }

    async fn start_recover_secret(
        &mut self,
        secret_id: u64,
        version: u32,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Vec<DeRecEvent>> {
        let all_paired: Vec<crate::types::ChannelId> = self
            .channel_store
            .channels(self.secret_id)
            .await?
            .iter()
            .map(|c| c.id)
            .collect();
        handlers::require_role(
            &self.channel_store,
            self.secret_id,
            &all_paired,
            derec_proto::SenderKind::Owner,
        )
        .await?;
        handlers::recovery::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &mut self.state_store,
            &self.transport,
            secret_id,
            version,
            reply_to,
        )
        .await
    }

    async fn start_unpair(
        &mut self,
        channel_id: ChannelId,
        memo: Option<String>,
        reply_to: Option<derec_proto::TransportProtocol>,
    ) -> Result<Vec<DeRecEvent>> {
        handlers::require_role(
            &self.channel_store,
            self.secret_id,
            &[channel_id],
            derec_proto::SenderKind::Owner,
        )
        .await?;
        // The handler returns an immediate `Unpaired` event for the
        // `UnpairAck::NotRequired` path (interleaved after
        // `UnpairStarted` here); the wait-for-ack path surfaces
        // `Unpaired` later from `process()` on the response, or from
        // the timeout sweep.
        let mut events = vec![DeRecEvent::UnpairStarted { channel_id }];
        events.extend(
            handlers::unpairing::start(
                &mut self.channel_store,
                &mut self.share_store,
                &mut self.secret_store,
                &self.transport,
                &mut self.state_store,
                self.secret_id,
                channel_id,
                memo,
                self.unpair_ack,
                now_secs(),
                reply_to,
            )
            .await?,
        );
        Ok(events)
    }

    async fn start_update_channel_info(
        &mut self,
        target: crate::protocol::types::Target,
        communication_info: Option<HashMap<String, String>>,
        transport_protocol: Option<derec_proto::TransportProtocol>,
    ) -> Result<Vec<DeRecEvent>> {
        handlers::update_channel_info::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &self.transport,
            self.secret_id,
            target,
            communication_info,
            transport_protocol,
        )
        .await
    }

    async fn accept_inner(&mut self, action: PendingAction) -> Result<Vec<DeRecEvent>> {
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
                    self.secret_id,
                    channel_id,
                    &request,
                    &pairing_secret,
                    kind,
                    trace_id,
                    self.replica_id,
                    self.parameter_range,
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
                    self.secret_id,
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
                    self.secret_id,
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
                    self.secret_id,
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
                    self.secret_id,
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
                    self.secret_id,
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
                    self.secret_id,
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
                    self.secret_id,
                    channel_id,
                    &request,
                    trace_id,
                )
                .await
            }
        }
    }

    /// Auto-publish the cached secret if `events` contain a
    /// helper-side `PairingCompleted` (the freshly-paired Helper needs
    /// shares). The replica-side equivalent fires from
    /// `verify_fingerprint` once the channel leaves `Pending`.
    ///
    /// The payload comes from `user_secret_store.load_latest()` when one
    /// has been cached by an earlier `start(ProtectSecret)`. When no
    /// snapshot exists yet **and** at least one Replica Destination is
    /// already paired, the hook publishes an empty payload so the roster
    /// snapshot still reaches every Destination — that's how a
    /// multi-device sync stays consistent before the application has
    /// added any user secrets.
    async fn maybe_auto_publish_after_pair(
        &mut self,
        events: &[DeRecEvent],
    ) -> Result<Vec<DeRecEvent>> {
        let helper_just_paired = events.iter().any(|e| {
            matches!(
                e,
                DeRecEvent::PairingCompleted {
                    kind: derec_proto::SenderKind::Owner,
                    ..
                }
            )
        });
        if !helper_just_paired {
            return Ok(Vec::new());
        }
        let snapshot = self.user_secret_store.load_latest(self.secret_id).await?;
        let (secrets, description) = match snapshot {
            Some(s) => (s.secrets, s.description),
            None => {
                if !self.has_paired_replica_destination().await? {
                    return Ok(Vec::new());
                }
                (Vec::new(), None)
            }
        };
        let reply_to = self.auto_reply_to.then(|| self.own_transport.clone());
        self.publish_secret(secrets, description, reply_to).await
    }

    /// Returns `true` when at least one channel carries the local
    /// `ReplicaSource` role in `Paired` status — i.e. the peer is a
    /// Replica Destination that is fully verified and eligible for
    /// secret sync.
    async fn has_paired_replica_destination(&self) -> Result<bool> {
        let channels = self.channel_store.channels(self.secret_id).await?;
        Ok(channels.iter().any(|c| {
            c.role == derec_proto::SenderKind::ReplicaSource
                && c.status == crate::protocol::types::ChannelStatus::Paired
        }))
    }

    /// Walk the post-`process_inner` event list and apply the
    /// [`AutoAcceptPolicy`]: each `ActionRequired` whose action kind
    /// the policy opts into is replaced with `AutoAccepted` plus the
    /// flow events `accept_inner(action)` produces. Other events pass
    /// through unchanged.
    async fn apply_auto_accept(&mut self, events: Vec<DeRecEvent>) -> Result<Vec<DeRecEvent>> {
        let mut out = Vec::with_capacity(events.len());
        for event in events {
            match event {
                DeRecEvent::ActionRequired { channel_id, action }
                    if self.auto_accept.allows(&action) =>
                {
                    let action_kind = action.kind();
                    out.push(DeRecEvent::AutoAccepted {
                        channel_id,
                        action_kind,
                    });
                    let accept_events = self.accept_inner(action).await?;
                    out.extend(accept_events);
                }
                other => out.push(other),
            }
        }
        Ok(out)
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
            .load(self.secret_id, channel_id, SecretKind::SharedKey)
            .await?
        else {
            return Ok(None);
        };

        if let Some(channel) = self.channel_store.load(self.secret_id, channel_id).await? {
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
            &mut self.state_store,
            message,
            self.secret_id,
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
        if let Ok(inner) = crate::derec_message::extract_inner_plaintext_message(&message.message) {
            match inner {
                inner @ MessageBody::PrePairRequest(_) => {
                    // Initiator side. Two flavors:
                    // - HashedKeys: `PairingSecret` was saved at
                    //   `create_contact` time; the accept path publishes
                    //   its embedded keys.
                    // - NoKeys: only `PairingContact` was saved at
                    //   `create_contact_no_keys` time — no keys exist
                    //   until the accept path generates them on the fly.
                    // Route the message iff **either** correlation record
                    // exists; otherwise silently drop (unknown channel).
                    let has_pairing_secret = matches!(
                        self.secret_store
                            .load(self.secret_id, channel_id, SecretKind::PairingSecret)
                            .await?,
                        Some(SecretValue::PairingSecret(_))
                    );
                    let has_pairing_contact = matches!(
                        self.secret_store
                            .load(self.secret_id, channel_id, SecretKind::PairingContact)
                            .await?,
                        Some(SecretValue::PairingContact(_))
                    );
                    if !has_pairing_secret && !has_pairing_contact {
                        return Ok(None);
                    }
                    let events = handlers::pairing::handle_pre_pair_request(&inner, channel_id, message.trace_id)?;
                    return Ok(Some(events));
                }
                MessageBody::PrePairResponse(resp) => {
                    // Scanner side: needs the original HashedKeys contact
                    // (saved at `start` time) to validate the binding hash.
                    let Some(SecretValue::PairingContact(contact)) = self
                        .secret_store
                        .load(self.secret_id, channel_id, SecretKind::PairingContact)
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
                        self.secret_id,
                        channel_id,
                        &contact,
                        &resp,
                        self.replica_id,
                        self.parameter_range,
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
            .load(self.secret_id, channel_id, SecretKind::PairingSecret)
            .await?
        else {
            return Ok(None);
        };

        let events = handlers::handle_pairing(
            &mut self.channel_store,
            &mut self.secret_store,
            &self.transport,
            &self.communication_info,
            message,
            self.secret_id,
            channel_id,
            &pairing_secret,
            self.replica_id,
            self.parameter_range.as_ref(),
        )
        .await?;
        Ok(Some(events))
    }

    /// Check if any channels in the active sharing round have timed out.
    ///
    /// Returns `ShareRejected` events for timed-out channels and moves them
    /// from `pending` to `failed` in the round tracker.
    async fn check_sharing_round_timeouts(&mut self) -> Vec<DeRecEvent> {
        let Ok(Some(StateItem::SharingRound {
            version,
            mut pending,
            confirmed,
            mut failed,
            started_at,
        })) = self
            .state_store
            .load(self.secret_id, StateKey::SharingRound)
            .await
        else {
            return vec![];
        };
        let now = now_secs();
        if now.saturating_sub(started_at) <= self.timeout_in_secs {
            return vec![];
        }
        let timed_out: Vec<ChannelId> = pending.drain().collect();
        let mut events = Vec::with_capacity(timed_out.len());
        for channel_id in timed_out {
            failed.insert(channel_id);
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
        // Persist the timeout-drained round so a subsequent
        // `update_sharing_round` can see the mutations.
        let _ = self
            .state_store
            .save(
                self.secret_id,
                StateItem::SharingRound {
                    version,
                    pending,
                    confirmed,
                    failed,
                    started_at,
                },
            )
            .await;
        events
    }

    /// Drop local state for any pending unpair whose acknowledgement window has
    /// elapsed, returning an `Unpaired` event per dropped channel.
    async fn check_unpair_timeouts(&mut self) -> Vec<DeRecEvent> {
        let now = now_secs();
        let all = match self
            .state_store
            .load_all(self.secret_id, StateKind::PendingUnpair)
            .await
        {
            Ok(items) => items,
            Err(_) => return Vec::new(),
        };
        let expired: Vec<ChannelId> = all
            .into_iter()
            .filter_map(|item| match item {
                StateItem::PendingUnpair {
                    channel_id,
                    started_at,
                } if now.saturating_sub(started_at) > self.timeout_in_secs => Some(channel_id),
                _ => None,
            })
            .collect();

        let mut events = Vec::with_capacity(expired.len());
        for cid in expired {
            let _ = self
                .state_store
                .remove(self.secret_id, StateKey::PendingUnpair { channel_id: cid })
                .await;
            if handlers::unpairing::drop_channel_state(
                &mut self.channel_store,
                &mut self.share_store,
                &mut self.secret_store,
                self.secret_id,
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
    async fn update_sharing_round(&mut self, events: &mut Vec<DeRecEvent>) {
        let Ok(Some(StateItem::SharingRound {
            version: round_version,
            mut pending,
            mut confirmed,
            mut failed,
            started_at,
        })) = self
            .state_store
            .load(self.secret_id, StateKey::SharingRound)
            .await
        else {
            return;
        };

        for event in events.iter() {
            match event {
                DeRecEvent::ShareConfirmed {
                    channel_id,
                    version,
                } if *version == round_version => {
                    pending.remove(channel_id);
                    confirmed.insert(*channel_id);
                }
                DeRecEvent::ShareRejected {
                    channel_id,
                    version,
                    ..
                } if *version == round_version => {
                    pending.remove(channel_id);
                    failed.insert(*channel_id);
                }
                _ => {}
            }
        }

        let is_complete = pending.is_empty();
        let confirmed_count = confirmed.len();
        let failed_count = failed.len();

        if is_complete {
            let threshold_met = confirmed_count >= self.threshold;
            let _ = self
                .state_store
                .remove(self.secret_id, StateKey::SharingRound)
                .await;
            events.push(DeRecEvent::SharingComplete {
                version: round_version,
                confirmed_count,
                failed_count,
                threshold_met,
            });

            #[cfg(feature = "logging")]
            tracing::info!(
                version = round_version,
                confirmed_count,
                failed_count,
                threshold_met,
                "sharing round complete"
            );
        } else {
            let _ = self
                .state_store
                .save(
                    self.secret_id,
                    StateItem::SharingRound {
                        version: round_version,
                        pending,
                        confirmed,
                        failed,
                        started_at,
                    },
                )
                .await;
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
        let channels = self.channel_store.channels(self.secret_id).await?;

        let mut removed = Vec::new();
        for channel in channels {
            if channel.status == crate::protocol::types::ChannelStatus::Pending
                && now.saturating_sub(channel.created_at) > timeout
            {
                self.channel_store
                    .remove(self.secret_id, channel.id)
                    .await?;
                // Clean up any leftover pairing secret for this channel.
                let _ = self
                    .secret_store
                    .remove(self.secret_id, channel.id, SecretKind::PairingSecret)
                    .await;
                let _ = self
                    .secret_store
                    .remove(self.secret_id, channel.id, SecretKind::PairingContact)
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
