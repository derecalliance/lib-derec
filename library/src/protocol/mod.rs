// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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
//!   [`StateItem::PendingVerification`](crate::protocol::types::StateItem)
//!   for the orchestrator-owned request/response binding row in the
//!   state store).
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
//! [`utils::reserved_keys`] for the current set of keys and their wire
//! encoding.

pub mod error;
pub mod events;
pub mod traits;
pub mod types;
pub mod utils;

mod builder;
mod handlers;

/// In-memory store and transport doubles shared by the unit tests
/// throughout this module. Lives at the `protocol` level because the
/// doubles implement the [`traits`] store interfaces and the rigs build
/// a whole [`DeRecProtocol`] — neither is specific to [`handlers`].
#[cfg(test)]
mod test;

use crate::{
    Error, Result, primitives::pairing::request::create_contact as create_contact_message,
    types::ChannelId,
};
pub use builder::{DEFAULT_KEEP_VERSIONS_COUNT, DEFAULT_THRESHOLD, DeRecProtocolBuilder};
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
    ChannelQuery, ChannelRecord, ChannelShare, ChannelStatus, ExpiredChannelCleanup, HelperChannel,
    HelperInfo, MissingPolicy, PairingKeyMaterial, ReplicaInfo, ReplicaMember, ReplicaRole,
    ReplicaSecretPayload, Secret, SecretKind, SecretValue, Share, StateItem, StateKey, StateKind,
    Target, UserSecret, UserSecrets,
};

pub use events::{
    AutoAcceptPolicy, DeRecEvent, DeRecFlow, PendingAction, PendingActionKind, UnpairAck,
};
pub use handlers::restore::RestoreError;

#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;

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
///   ├── start(Unpair)                            → unpair          (Owner-initiated; ack
///   │                                                               semantics governed by
///   │                                                               [`DeRecProtocolBuilder::with_unpair_ack`])
///   ├── start(SyncCheck)                         → replica catch-up (replica-only; asks the
///   │                                                                group whether this device
///   │                                                                is behind)
///   └── start(RemoveReplica)                     → replica removal (replica-only; voluntary
///                                                                   departure or eviction)
///
/// loop { process(incoming_bytes) → Vec<DeRecEvent> }
///
/// tick()  → Vec<DeRecEvent>   (time-driven only; no inbound message required)
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
    /// Configured via [`Timeouts`](crate::protocol::types::Timeouts).
    /// Configured via [`DeRecProtocolBuilder::with_timeouts`].
    pub(crate) timeouts: crate::protocol::types::Timeouts,
    /// Configured via [`DeRecProtocolBuilder::with_unsafe_http`].
    pub(crate) unsafe_http: bool,
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
        timeouts: crate::protocol::types::Timeouts,
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
            timeouts,
            unsafe_http: false,
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

        let result =
            create_contact_message(channel_id, contact_mode, self.own_transport.clone(), nonce)?;

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
                        SecretValue::PairingSecret(PairingKeyMaterial::from_secret(&secret_key)),
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
            DeRecFlow::SyncCheck => {
                handlers::sync_check::start(
                    &mut self.channel_store,
                    &mut self.secret_store,
                    &self.user_secret_store,
                    &mut self.state_store,
                    &self.transport,
                    self.secret_id,
                    self.replica_id,
                    &self.own_transport,
                )
                .await
            }
            DeRecFlow::RemoveReplica { replica_id, memo } => {
                // Announcing is the whole of `start`: the flag it leaves keeps
                // the member out of the next roster while still on the
                // distribution list, which is how an evicted member learns it
                // may tear down. The application publishes that roster.
                handlers::remove_replica::start(
                    &mut self.channel_store,
                    &mut self.secret_store,
                    &self.transport,
                    self.secret_id,
                    replica_id,
                    memo,
                    self.replica_id,
                )
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
    ///
    /// # Helper-side admission control
    ///
    /// This is where a helper enforces its own limits on inbound shares.
    /// The protocol imposes none of its own: it does not bound share
    /// size, storage per sharer, or update frequency, and the
    /// `maxShareSize` negotiated from [`derec_proto::ParameterRange`] is
    /// only checked for range overlap at pairing time, never against an
    /// actual share.
    ///
    /// [`PendingAction::StoreShare`] carries the already-decrypted,
    /// already-parsed [`derec_proto::StoreShareRequestMessage`], so the
    /// application inspects the share without touching wire bytes,
    /// envelopes or key material:
    ///
    /// The application context (`my_app`, its per-user limits) is yours, so
    /// this is illustrative rather than a compiled example:
    ///
    /// ```text
    /// for event in protocol.process(&wire_bytes).await? {
    ///     let DeRecEvent::ActionRequired { action, channel_id } = event else { continue };
    ///     match &action {
    ///         PendingAction::StoreShare { request, .. } => {
    ///             // `channel_id` maps to a user in the application's own
    ///             // store, so the limit can be per-user, per-plan, or
    ///             // whatever the deployment needs.
    ///             let limit = my_app.share_limit_for(channel_id);
    ///             if request.share.len() > limit {
    ///                 protocol
    ///                     .reject(
    ///                         action,
    ///                         StatusEnum::SizeLimitExceeded,
    ///                         &format!("share exceeds the {limit}-byte limit"),
    ///                     )
    ///                     .await?;
    ///             } else {
    ///                 protocol.accept(action).await?;
    ///             }
    ///         }
    ///         _ => { protocol.accept(action).await?; }
    ///     }
    /// }
    /// ```
    ///
    /// The owner receives a `StoreShareResponse` carrying that status and
    /// memo, surfacing as [`DeRecEvent::ShareRejected`] on its side — so
    /// the failure is attributable rather than a silent timeout.
    ///
    /// [`StatusEnum::SizeLimitExceeded`] is the protocol's designated code
    /// for this case; [`StatusEnum::TooFrequent`] covers rate limiting and
    /// [`StatusEnum::Rejected`] a user-declined request.
    ///
    /// This gate exists only while
    /// [`AutoAcceptPolicy::store_share`](crate::protocol::AutoAcceptPolicy::store_share)
    /// is `false`. Enabling it makes `process()` accept and store every
    /// inbound share internally, and no `ActionRequired` is emitted to
    /// reject.
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
                    self.replica_id,
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
                    self.replica_id,
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
                    self.replica_id,
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
    /// # Expired channel cleanup
    ///
    /// Each call first removes `Pending` channels that have exceeded the
    /// configured
    /// [`ExpiredChannelCleanup`]
    /// timeout, along with their pairing keys. Removal is **lazy**: it
    /// happens only when this function runs, so an idle node retains
    /// expired channels until the next inbound message arrives. The
    /// removed ids are discarded on this path — call
    /// [`remove_expired_channels`](Self::remove_expired_channels)
    /// directly to observe them.
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
        let mut timeout_events = self.run_timeout_sweeps().await;

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

        // Ordering: timeout events first (sharing-round then unpair, as
        // `run_timeout_sweeps` orders them), then events produced by this
        // specific message.
        timeout_events.append(&mut events);
        let mut events = timeout_events;

        self.update_sharing_round(&mut events).await;

        let auto_publish_events =
            self.maybe_auto_publish_after_pair(&events)
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

    /// The scheme policy this protocol applies to every transport endpoint
    /// that reaches it. Built from
    /// [`DeRecProtocolBuilder::with_unsafe_http`]; see
    /// [`TransportPolicy`](crate::transport::TransportPolicy).
    pub(crate) fn transport_policy(&self) -> crate::transport::TransportPolicy {
        crate::transport::TransportPolicy::new(self.unsafe_http)
    }

    /// Verify that a fingerprint matches the one derived from a channel's shared key.
    ///
    /// If the fingerprint matches, the channel status is updated from `Pending`
    /// to `Paired`, enabling it to process protocol messages. Returns `true` on
    /// match, `false` otherwise. Returns an error if the channel has no shared key.
    ///
    /// This is the confirmation step for both gated cases: every replica
    /// pairing, and every [`derec_proto::ContactMode::NoKeys`] pairing —
    /// helper channels included, since that mode binds nothing to the contact
    /// and a man-in-the-middle on its plaintext `PrePair` leg would leave the
    /// two sides holding different shared keys, and so different fingerprints.
    /// Compare the two values out of band before calling this.
    ///
    /// On a promotion the current snapshot is published to the newly usable
    /// peer, because it was not an eligible target while `Pending` and the
    /// pairing-time hook therefore skipped it.
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

        // A `NoKeys` helper pairing is held `Pending` for the same reason a
        // replica one is: nothing else binds the keys to the contact that was
        // delivered out of band, so this call is the confirmation. Without
        // this branch such a channel could never leave `Pending`, and the
        // gate would be a deadlock rather than a gate.
        let mut transitioned_helper = false;
        if let Some(record) = self
            .channel_store
            .load(
                self.secret_id,
                crate::protocol::types::ChannelQuery::Helper { channel_id },
            )
            .await?
            && let Some(helper) = record.as_helper()
            && helper.status == crate::protocol::types::ChannelStatus::Pending
        {
            let mut helper = helper.clone();
            helper.status = crate::protocol::types::ChannelStatus::Paired;
            self.channel_store
                .save(
                    self.secret_id,
                    crate::protocol::types::ChannelRecord::Helper(helper),
                )
                .await?;
            transitioned_helper = true;
        }

        // Verification promotes every member sharing this group channel,
        // this device's own row included — the whole group becomes usable at
        // once, which is what makes the roster reconstructible from stores.
        let mut transitioned_replica = false;
        let members = self.channel_store.replicas(self.secret_id).await?;
        for mut member in members {
            if member.channel_id != channel_id
                || member.status != crate::protocol::types::ChannelStatus::Pending
            {
                continue;
            }
            if member.role == crate::protocol::types::ReplicaRole::Destination
                && Some(member.replica_id.0) != self.replica_id
            {
                transitioned_replica = true;
            }
            member.status = crate::protocol::types::ChannelStatus::Paired;
            self.channel_store
                .save(
                    self.secret_id,
                    crate::protocol::types::ChannelRecord::Replica(member),
                )
                .await?;
        }

        // Replica destinations only become eligible publish targets once
        // the fingerprint is verified. Mirror the helper-pair hook in
        // `process()` so the newly-confirmed peer receives the current
        // secret without an explicit follow-up `ProtectSecret` call. The
        // Pending→Paired transition means at least one Replica
        // Destination is now paired, so the empty-payload fallback
        // always applies when no `UserSecrets` snapshot has been cached
        // yet.
        //
        // A promoted helper needs the same push for a different reason:
        // `maybe_auto_publish_after_pair` already fired when the handshake
        // completed, but the channel was `Pending` then, so
        // `load_all_paired_targets` skipped it and it received nothing. This
        // is the first moment it is an eligible target, and nothing else
        // would re-publish before the next explicit `ProtectSecret`.
        if transitioned_replica || transitioned_helper {
            let snapshot = self.user_secret_store.load_latest(self.secret_id).await?;
            let payload = match snapshot {
                Some(s) => Some((s.secrets, s.description)),
                // With no snapshot there is nothing a helper can be sent —
                // an empty payload carries only the roster, which is useful
                // to a Destination and inert to a helper. A replica
                // transition implies a Destination is now paired, so the
                // fallback always applies there.
                None if transitioned_replica || self.has_paired_replica_destination().await? => {
                    Some((Vec::new(), None))
                }
                None => None,
            };
            if let Some((secrets, description)) = payload {
                let reply_to = self.auto_reply_to.then(|| self.own_transport.clone());
                self.publish_secret(secrets, description, reply_to).await?;
            }
        }

        Ok(true)
    }

    /// Rebuild this protocol's `secret_id` namespace from a
    /// [`crate::protocol::types::Secret`] handed up by a
    /// [`DeRecEvent::SecretRecovered`] event.
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
    /// every other
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
    /// [`crate::Error::Restore`] wrapping one of:
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
    /// [`crate::Error::ShareStore`], [`crate::Error::ChannelStore`],
    /// or [`crate::Error::SecretStore`] variant.
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
            // Owner-initiated flow: every target must be a Helper peer.
            derec_proto::SenderKind::Helper,
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
            &self.own_transport,
            reply_to,
            self.replica_id,
        )
        .await?
        else {
            return Ok(Vec::new());
        };

        // Only targets whose dispatch succeeded count as pending — a peer we
        // couldn't reach on send won't be responding, so it must not gate the
        // round's completion. An undeliverable member is reported once here,
        // where the transport error is still available, and lands in `behind`.
        let version = round.version;
        let pending: HashSet<ChannelId> = round
            .outcomes
            .iter()
            .filter_map(|(cid, r)| r.as_ref().ok().map(|_| *cid))
            .collect();
        let pending_replicas: HashSet<crate::types::ReplicaId> = round
            .replica_outcomes
            .iter()
            .filter_map(|(rid, r)| r.as_ref().ok().map(|_| *rid))
            .collect();
        let behind_replicas: HashSet<crate::types::ReplicaId> = round
            .replica_outcomes
            .iter()
            .filter_map(|(rid, r)| r.as_ref().err().map(|_| *rid))
            .collect();

        let mut undeliverable: Vec<DeRecEvent> = round
            .replica_outcomes
            .iter()
            .filter_map(|(rid, r)| {
                r.as_ref().err().map(|e| DeRecEvent::ReplicaSyncFailed {
                    replica_id: rid.0,
                    version,
                    reason: e.to_string(),
                })
            })
            .collect();

        if !pending.is_empty() || !pending_replicas.is_empty() {
            self.state_store
                .save(
                    self.secret_id,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version,
                        pending,
                        confirmed: HashSet::new(),
                        failed: HashSet::new(),
                        pending_replicas,
                        synced_replicas: HashSet::new(),
                        behind_replicas,
                        started_at: now_secs(),
                    })),
                )
                .await?;
        }

        let mut started: Vec<DeRecEvent> = round
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
            .collect();
        started.append(&mut undeliverable);
        Ok(started)
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
            // Owner-initiated flow: every target must be a Helper peer.
            derec_proto::SenderKind::Helper,
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
        // No blanket role gate here: an instance legitimately holds
        // replica channels alongside its helper pairings, and requiring
        // every channel to be Owner-role would abort the recovery over a
        // peer that was never a recovery target. The handler selects the
        // Owner-role, `Paired` channels itself.
        handlers::recovery::start(
            &mut self.channel_store,
            &mut self.secret_store,
            &mut self.state_store,
            &self.transport,
            // Local: our channels, keys and state. Target: the secret
            // asked for on the wire. Equal for an in-place re-request,
            // distinct when recovering from an ephemeral instance.
            self.secret_id,
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
            // Owner-initiated teardown: the peer must be a Helper.
            derec_proto::SenderKind::Helper,
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
                kind,
                trace_id,
                ..
            } => {
                handlers::pairing::accept(
                    &mut self.channel_store,
                    &mut self.secret_store,
                    &self.transport,
                    &self.own_transport,
                    &self.communication_info,
                    self.secret_id,
                    channel_id,
                    &request,
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
                    self.replica_id,
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
    /// The completion event is not on its own enough: a `NoKeys` pairing
    /// completes into `ChannelStatus::Pending` and is not a publish target
    /// until its fingerprint is confirmed. Publishing then would bump the
    /// version for every *other* helper while reaching the new one with
    /// nothing, and `verify_fingerprint` would publish again the moment the
    /// gate opened — two rounds where the flow calls for one. So the hook
    /// fires only for a helper that is already usable, and the gated case is
    /// left to `verify_fingerprint`.
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
        let mut a_usable_helper_just_paired = false;
        for event in events {
            let DeRecEvent::PairingCompleted {
                kind: derec_proto::SenderKind::Owner,
                channel_id,
                ..
            } = event
            else {
                continue;
            };
            if self
                .channel_store
                .load(
                    self.secret_id,
                    crate::protocol::types::ChannelQuery::Helper {
                        channel_id: *channel_id,
                    },
                )
                .await?
                .is_some_and(|record| {
                    record.status() == crate::protocol::types::ChannelStatus::Paired
                })
            {
                a_usable_helper_just_paired = true;
                break;
            }
        }
        if !a_usable_helper_just_paired {
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

    /// Returns `true` when at least one channel records a
    /// `ReplicaDestination` peer in `Paired` status — i.e. a Destination
    /// that is fully verified and eligible for secret sync.
    async fn has_paired_replica_destination(&self) -> Result<bool> {
        let members = self.channel_store.replicas(self.secret_id).await?;
        Ok(members.iter().any(|m| {
            m.role == crate::protocol::types::ReplicaRole::Destination
                && m.status == crate::protocol::types::ChannelStatus::Paired
                && Some(m.replica_id.0) != self.replica_id
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
        if age > self.timeouts.inbound_message.as_secs() {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                message_age_secs = age,
                timeout_secs = self.timeouts.inbound_message.as_secs(),
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

        if let Some(record) = self
            .channel_store
            .load(
                self.secret_id,
                crate::protocol::types::ChannelQuery::Helper { channel_id },
            )
            .await?
            && record.status() == crate::protocol::types::ChannelStatus::Pending
        {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                "message ignored — channel is pending fingerprint verification"
            );
            return Ok(Some(vec![DeRecEvent::NoOp]));
        }

        // Read before the mutable borrows below begin.
        let transport_policy = self.transport_policy();
        let events = handlers::handle(
            &mut self.channel_store,
            &mut self.share_store,
            &mut self.secret_store,
            &mut self.user_secret_store,
            &self.transport,
            &mut self.state_store,
            &self.own_transport,
            message,
            self.secret_id,
            channel_id,
            &shared_key,
            self.replica_id,
            transport_policy,
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
                    let events = handlers::pairing::handle_pre_pair_request(
                        &inner,
                        channel_id,
                        message.trace_id,
                    )?;
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
        let pairing_secret = pairing_secret.to_secret()?;
        // Read before the mutable borrows below begin.
        let transport_policy = self.transport_policy();

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
            transport_policy,
        )
        .await?;
        Ok(Some(events))
    }

    /// Check if any channels in the active sharing round have timed out.
    ///
    /// Returns `ShareRejected` events for timed-out channels and moves them
    /// from `pending` to `failed` in the round tracker.
    /// Advance every time-driven part of the protocol without an inbound
    /// message, returning whatever that produced.
    ///
    /// # Why this exists
    ///
    /// Timeouts are otherwise only evaluated inside [`Self::process`], so they
    /// advance only when traffic arrives. A publish whose helpers all go quiet
    /// has nothing left to trigger it: the round stays open, no
    /// [`DeRecEvent::SharingComplete`] is ever emitted, and an application
    /// waiting on that event waits forever. The same applies to an
    /// unacknowledged unpair.
    ///
    /// A long-lived embedded application could rely on incidental traffic. A
    /// service that rebuilds the protocol per request has no background loop
    /// at all, so this is the entry point its scheduler calls — a cron tick, a
    /// timer task, a queue heartbeat.
    ///
    /// # What it does
    ///
    /// Exactly what [`Self::process`] does about time, minus the message:
    ///
    /// 1. Expired-channel cleanup, if
    ///    [`Timeouts::expired_channels`](crate::protocol::types::Timeouts::expired_channels)
    ///    enabled it — which it is **by default**
    ///    (`Enabled { timeout_in_secs: 300 }`). Setting it to
    ///    [`crate::protocol::ExpiredChannelCleanup::Disabled`]
    ///    skips this step and leaves [`Self::remove_expired_channels`] for
    ///    explicit control.
    /// 2. Sharing-round timeouts — every helper still pending past the
    ///    configured window is failed with
    ///    [`DeRecEvent::ShareRejected`], every member still pending is
    ///    reported [`DeRecEvent::ReplicaSyncFailed`].
    /// 3. Unpair-acknowledgement timeouts.
    /// 4. The round tally, which is what turns a fully-drained round into
    ///    [`DeRecEvent::SharingComplete`] and clears its state row. Step 2
    ///    only marks the participants; without this the round would report
    ///    failures and still never close.
    ///
    /// # Calling it
    ///
    /// Idempotent and safe to call at any time: with nothing in flight it
    /// touches no state and returns an empty vector. Store failures are
    /// swallowed the same way [`Self::process`] swallows them, so a transient
    /// backend error means work is retried on the next call rather than
    /// surfaced here.
    ///
    /// Cadence should be shorter than
    /// [`Timeouts`](crate::protocol::types::Timeouts), since that bounds how long a
    /// stalled round can sit before this notices it.
    ///
    /// Concurrency is the caller's, as everywhere else: this mutates the same
    /// round state an inbound response does, so it must be serialized against
    /// [`Self::process`] for the same `secret_id`. See
    /// [`DeRecStateStore`].
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn tick(&mut self) -> Vec<DeRecEvent> {
        let mut events = self.run_timeout_sweeps().await;
        self.update_sharing_round(&mut events).await;
        events
    }

    /// The time-driven sweeps, shared by [`Self::tick`] and [`Self::process`]
    /// so the two cannot drift.
    ///
    /// Deliberately does **not** run the round tally: `process` runs it once
    /// at the end, over these events together with the message's own, and
    /// running it here as well would reorder what `process` reports.
    async fn run_timeout_sweeps(&mut self) -> Vec<DeRecEvent> {
        if let crate::protocol::ExpiredChannelCleanup::Enabled { timeout_in_secs } =
            self.timeouts.expired_channels
        {
            let _ = self.remove_expired_channels(timeout_in_secs).await;
        }

        let mut events = self.check_sharing_round_timeouts().await;
        events.append(&mut self.check_unpair_timeouts().await);
        events
    }

    async fn check_sharing_round_timeouts(&mut self) -> Vec<DeRecEvent> {
        // More than one round can be open: the pair-completion hook and the
        // promotion inside `verify_fingerprint` both publish, and either can
        // run while an application-initiated round is still in flight. Each is
        // keyed by its version and ages on its own clock, so they are swept
        // independently rather than as a single row.
        let Ok(rounds) = self
            .state_store
            .load_all(self.secret_id, StateKind::SharingRound)
            .await
        else {
            return vec![];
        };

        let now = now_secs();
        let mut events = Vec::new();

        for item in rounds {
            let StateItem::SharingRound(round) = item else {
                continue;
            };
            let crate::protocol::types::SharingRoundState {
                version,
                mut pending,
                confirmed,
                mut failed,
                mut pending_replicas,
                synced_replicas,
                mut behind_replicas,
                started_at,
            } = *round;

            if now.saturating_sub(started_at) <= self.timeouts.sharing_round.as_secs() {
                continue;
            }
            let timed_out: Vec<ChannelId> = pending.drain().collect();
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
            // Members time out on the same clock. A member that never answered
            // is behind, not a round failure — see `ReplicaSyncComplete`.
            let timed_out_replicas: Vec<crate::types::ReplicaId> =
                pending_replicas.drain().collect();
            for replica_id in timed_out_replicas {
                behind_replicas.insert(replica_id);
                events.push(DeRecEvent::ReplicaSyncFailed {
                    replica_id: replica_id.0,
                    version,
                    reason: "timeout".to_owned(),
                });

                #[cfg(feature = "logging")]
                tracing::warn!(
                    replica_id = replica_id.0,
                    version,
                    "sharing round: replica timed out"
                );
            }

            // Persist the timeout-drained round so a subsequent
            // `update_sharing_round` can see the mutations.
            let _ = self
                .state_store
                .save(
                    self.secret_id,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version,
                        pending,
                        confirmed,
                        failed,
                        pending_replicas,
                        synced_replicas,
                        behind_replicas,
                        started_at,
                    })),
                )
                .await;
        }
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
                } if now.saturating_sub(started_at) > self.timeouts.unpair_ack.as_secs() => {
                    Some(channel_id)
                }
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
        // Every open round is offered the same event list and takes only the
        // entries carrying its own version. Rounds overlap whenever a publish
        // fires from an inbound path — the pair-completion hook, or the
        // promotion inside `verify_fingerprint` — while another is in flight,
        // so settling just one of them would strand the rest.
        let Ok(rounds) = self
            .state_store
            .load_all(self.secret_id, StateKind::SharingRound)
            .await
        else {
            return;
        };

        // Collected separately: pushing into `events` while iterating it would
        // let one round's completion be re-examined by the next.
        let mut produced: Vec<DeRecEvent> = Vec::new();

        for item in rounds {
            let StateItem::SharingRound(round) = item else {
                continue;
            };
            let crate::protocol::types::SharingRoundState {
                version: round_version,
                mut pending,
                mut confirmed,
                mut failed,
                mut pending_replicas,
                mut synced_replicas,
                mut behind_replicas,
                started_at,
            } = *round;

            self.settle_one_round(
                events,
                &mut produced,
                round_version,
                &mut pending,
                &mut confirmed,
                &mut failed,
                &mut pending_replicas,
                &mut synced_replicas,
                &mut behind_replicas,
                started_at,
            )
            .await;
        }

        events.append(&mut produced);
    }

    /// Apply `inbound` to one round and either complete it or persist it.
    ///
    /// Split out of [`Self::update_sharing_round`] so the per-round body stays
    /// readable now that several rounds can be open at once.
    #[allow(clippy::too_many_arguments)]
    async fn settle_one_round(
        &mut self,
        inbound: &[DeRecEvent],
        produced: &mut Vec<DeRecEvent>,
        round_version: u32,
        pending: &mut std::collections::HashSet<ChannelId>,
        confirmed: &mut std::collections::HashSet<ChannelId>,
        failed: &mut std::collections::HashSet<ChannelId>,
        pending_replicas: &mut std::collections::HashSet<crate::types::ReplicaId>,
        synced_replicas: &mut std::collections::HashSet<crate::types::ReplicaId>,
        behind_replicas: &mut std::collections::HashSet<crate::types::ReplicaId>,
        started_at: u64,
    ) {
        let events = inbound;
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
                DeRecEvent::ReplicaSecretAcked {
                    from_replica_id,
                    version,
                    ..
                } if *version == round_version => {
                    if let Ok(replica_id) = crate::types::ReplicaId::try_from(*from_replica_id) {
                        pending_replicas.remove(&replica_id);
                        synced_replicas.insert(replica_id);
                    }
                }
                DeRecEvent::ReplicaSyncRejected {
                    replica_id,
                    version,
                    ..
                } if *version == round_version => {
                    if let Ok(replica_id) = crate::types::ReplicaId::try_from(*replica_id) {
                        pending_replicas.remove(&replica_id);
                        behind_replicas.insert(replica_id);
                    }
                }
                _ => {}
            }
        }

        let is_complete = pending.is_empty() && pending_replicas.is_empty();
        let confirmed_count = confirmed.len();
        let failed_count = failed.len();

        if is_complete {
            let threshold_met = confirmed_count >= self.threshold;
            let _ = self
                .state_store
                .remove(
                    self.secret_id,
                    StateKey::SharingRound {
                        version: round_version,
                    },
                )
                .await;
            produced.push(DeRecEvent::SharingComplete {
                version: round_version,
                confirmed_count,
                failed_count,
                threshold_met,
            });

            // Publisher-side half of the removal rule. A member told to leave
            // completes its departure when it acknowledges the version that
            // excludes it — which is what `synced_replicas` records. The
            // receive-side reconciliation cannot do this job here: a publisher
            // never receives the roster it just sent, so without this the
            // device that ran the removal would keep the row forever and go on
            // addressing a member that has already torn itself down.
            let mut removed_replicas: Vec<u64> = Vec::new();
            if let Ok(roster) = self.channel_store.replicas(self.secret_id).await {
                for member in roster {
                    if member.status != crate::protocol::types::ChannelStatus::Unpairing
                        || !synced_replicas.contains(&member.replica_id)
                    {
                        continue;
                    }
                    if self
                        .channel_store
                        .remove(
                            self.secret_id,
                            crate::protocol::types::ChannelQuery::Replica {
                                channel_id: member.channel_id,
                                replica_id: member.replica_id,
                            },
                        )
                        .await
                        .is_ok()
                    {
                        removed_replicas.push(member.replica_id.0);
                    }
                }
            }

            // The replica leg is reported separately: different success rule,
            // different key. Emitted only when the round had a replica leg at
            // all, so a helpers-only publish stays silent here.
            if !synced_replicas.is_empty() || !behind_replicas.is_empty() {
                let mut synced: Vec<u64> = synced_replicas.iter().map(|r| r.0).collect();
                let mut behind: Vec<u64> = behind_replicas.iter().map(|r| r.0).collect();
                // Sets are unordered; sort so the event is reproducible.
                synced.sort_unstable();
                behind.sort_unstable();

                #[cfg(feature = "logging")]
                tracing::info!(
                    version = round_version,
                    synced_count = synced.len(),
                    behind_count = behind.len(),
                    "replica sync round complete"
                );

                produced.push(DeRecEvent::ReplicaSyncComplete {
                    version: round_version,
                    synced,
                    behind,
                });
            }

            removed_replicas.sort_unstable();
            for replica_id in removed_replicas {
                produced.push(DeRecEvent::ReplicaRemoved { replica_id });
            }

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
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: round_version,
                        pending: std::mem::take(pending),
                        confirmed: std::mem::take(confirmed),
                        failed: std::mem::take(failed),
                        pending_replicas: std::mem::take(pending_replicas),
                        synced_replicas: std::mem::take(synced_replicas),
                        behind_replicas: std::mem::take(behind_replicas),
                        started_at,
                    })),
                )
                .await;
        }
    }

    /// Remove `Pending` channels older than `older_than_secs`, along with
    /// their pairing keys. Returns the ids that were removed.
    ///
    /// This is **independent of**
    /// [`Timeouts::expired_channels`](crate::protocol::types::Timeouts::expired_channels): it sweeps at
    /// the threshold it is given even when the policy is
    /// [`crate::protocol::ExpiredChannelCleanup::Disabled`]. That is what
    /// makes `Disabled` mean "the application drives cleanup itself".
    ///
    /// `older_than_secs` is not clamped. The minimum-of-one-second rule
    /// exists to stop the *automatic* sweep from deleting just-started
    /// pairings on every [`process`](Self::process) call; an explicit call
    /// is a deliberate act, so `remove_expired_channels(0)` is permitted
    /// and sweeps the most aggressively the predicate allows.
    ///
    /// The comparison is strict — a channel is removed when its age is
    /// **greater than** `older_than_secs`. Ages are whole seconds, taken
    /// from `created_at`, so `remove_expired_channels(0)` removes every
    /// `Pending` channel created in an earlier second but leaves one
    /// created within the current second.
    ///
    /// Called automatically during [`process`](Self::process) when the
    /// configured policy is
    /// [`crate::protocol::ExpiredChannelCleanup::Enabled`].
    pub async fn remove_expired_channels(
        &mut self,
        older_than_secs: u64,
    ) -> Result<Vec<ChannelId>> {
        let now = now_secs();
        let timeout = older_than_secs;
        let channels = self.channel_store.helpers(self.secret_id).await?;

        let mut removed = Vec::new();
        for channel in channels {
            if channel.status == crate::protocol::types::ChannelStatus::Pending
                && now.saturating_sub(channel.created_at) > timeout
            {
                self.channel_store
                    .remove(
                        self.secret_id,
                        crate::protocol::types::ChannelQuery::Helper {
                            channel_id: channel.channel_id,
                        },
                    )
                    .await?;
                // Clean up any leftover pairing secret for this channel.
                let _ = self
                    .secret_store
                    .remove(
                        self.secret_id,
                        channel.channel_id,
                        SecretKind::PairingSecret,
                    )
                    .await;
                let _ = self
                    .secret_store
                    .remove(
                        self.secret_id,
                        channel.channel_id,
                        SecretKind::PairingContact,
                    )
                    .await;

                #[cfg(feature = "logging")]
                tracing::info!(
                    channel_id = channel.channel_id.0,
                    elapsed_secs = now.saturating_sub(channel.created_at),
                    "expired pending channel removed"
                );

                removed.push(channel.channel_id);
            }
        }

        // A replica pairing that never completed leaves a Pending member row
        // that expires on the same clock. This device's own row is never a
        // pending pairing, so it is exempt.
        for member in self.channel_store.replicas(self.secret_id).await? {
            if member.status == crate::protocol::types::ChannelStatus::Pending
                && Some(member.replica_id.0) != self.replica_id
                && now.saturating_sub(member.created_at) > timeout
            {
                self.channel_store
                    .remove(
                        self.secret_id,
                        crate::protocol::types::ChannelQuery::Replica {
                            channel_id: member.channel_id,
                            replica_id: member.replica_id,
                        },
                    )
                    .await?;

                #[cfg(feature = "logging")]
                tracing::info!(
                    channel_id = member.channel_id.0,
                    replica_id = member.replica_id.0,
                    elapsed_secs = now.saturating_sub(member.created_at),
                    "expired pending replica member removed"
                );

                if !removed.contains(&member.channel_id) {
                    removed.push(member.channel_id);
                }
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod expired_channel_sweep_tests {
    use super::*;
    use crate::protocol::test::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, ExpiredChannelCleanup, HelperChannel, ReplicaMember,
        ReplicaRole, SecretValue,
    };

    const SECRET_ID: u64 = 0xC1;

    fn endpoint() -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: "https://peer.example.com".to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    /// Seed one channel whose `created_at` is `age_secs` in the past.
    async fn seed(
        channels: &mut InMemChannelStore,
        cid: u64,
        status: ChannelStatus,
        age_secs: u64,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: ChannelId(cid),
                    transport: endpoint(),
                    communication_info: std::collections::HashMap::new(),
                    status,
                    created_at: now_secs().saturating_sub(age_secs),
                    peer_role: derec_proto::SenderKind::Helper,
                }),
            )
            .await
            .expect("seed channel");
    }

    fn build(
        channels: InMemChannelStore,
        policy: ExpiredChannelCleanup,
        timeout_in_secs: u64,
    ) -> DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
        NoopTransport,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels)
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transport("https://owner.example.com")
            .with_threshold(2)
            .with_timeouts(crate::protocol::types::Timeouts {
                sharing_round: std::time::Duration::from_secs(timeout_in_secs),
                unpair_ack: std::time::Duration::from_secs(timeout_in_secs),
                inbound_message: std::time::Duration::from_secs(timeout_in_secs),
                expired_channels: policy,
            })
            .build()
            .expect("test protocol builds")
    }

    /// The manual sweep honours its own argument, not the configured
    /// policy — `Disabled` means "I drive this myself", not "off".
    #[test]
    fn manual_sweep_works_under_disabled_policy() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 600).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
            let removed = protocol
                .remove_expired_channels(60)
                .await
                .expect("sweep succeeds");

            assert_eq!(removed, vec![ChannelId(1)]);
            assert!(channels.helper_rows.lock().unwrap().is_empty());
        });
    }

    /// Seed one replica member on the group channel.
    async fn seed_member(
        channels: &mut InMemChannelStore,
        replica_id: u64,
        status: ChannelStatus,
        age_secs: u64,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: ChannelId(9000),
                    replica_id: crate::types::ReplicaId(replica_id),
                    transport: endpoint(),
                    communication_info: std::collections::HashMap::new(),
                    role: ReplicaRole::Destination,
                    status,
                    created_at: now_secs().saturating_sub(age_secs),
                }),
            )
            .await
            .expect("seed member");
    }

    /// A replica pairing that never completed expires like any other, but
    /// this device's own row is exempt: it is a roster entry, not a pending
    /// handshake, and sweeping it would erase the group's self-reference.
    #[test]
    fn sweep_removes_expired_replica_members_but_never_this_device() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed_member(&mut seeded, 7, ChannelStatus::Pending, 600).await;
            seed_member(&mut seeded, 8, ChannelStatus::Paired, 600).await;
            seed_member(&mut seeded, 9, ChannelStatus::Pending, 600).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
            protocol.replica_id = Some(9);
            let removed = protocol
                .remove_expired_channels(60)
                .await
                .expect("sweep succeeds");

            assert_eq!(
                removed,
                vec![ChannelId(9000)],
                "members share one channel, so the group is reported once"
            );
            let rows = channels.member_rows.lock().unwrap();
            assert!(
                !rows.contains_key(&(SECRET_ID, 7)),
                "expired pending member"
            );
            assert!(rows.contains_key(&(SECRET_ID, 8)), "paired member survives");
            assert!(rows.contains_key(&(SECRET_ID, 9)), "own row is exempt");
        });
    }

    /// `Disabled` suppresses the automatic sweep inside `process()`, so an
    /// over-age channel survives because nothing swept it.
    #[test]
    fn disabled_policy_leaves_channel_for_manual_sweep() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 600).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
            let _ = protocol.process(&[]).await;

            assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
        });
    }

    /// The policy's timeout governs the automatic sweep, not
    /// `timeout_in_secs` — verified by setting them to different values
    /// and choosing an age between the two.
    #[test]
    fn policy_timeout_governs_not_protocol_timeout() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 120).await;

            let mut protocol = build(
                channels.clone(),
                ExpiredChannelCleanup::Enabled {
                    timeout_in_secs: 60,
                },
                3600,
            );
            let _ = protocol.process(&[]).await;

            assert!(channels.helper_rows.lock().unwrap().is_empty());
        });
    }

    /// `Paired` channels are never swept, regardless of age.
    #[test]
    fn paired_channels_are_never_removed() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Paired, 99_999).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::default(), 300);
            let removed = protocol
                .remove_expired_channels(1)
                .await
                .expect("sweep succeeds");

            assert!(removed.is_empty());
            assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
        });
    }

    /// Removing a channel also drops its pairing material, so a stale
    /// handshake leaves nothing behind in the secret store.
    #[test]
    fn removal_drops_pairing_material() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let mut seeded = channels.clone();
            let mut seeded_secrets = secrets.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 600).await;
            seeded_secrets
                .save(
                    SECRET_ID,
                    ChannelId(1),
                    SecretValue::PairingContact(Default::default()),
                )
                .await
                .expect("seed pairing contact");

            let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(channels.clone())
                .with_share_store(InMemShareStore::default())
                .with_secret_store(secrets.clone())
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_transport(NoopTransport)
                .with_state_store(InMemStateStore)
                .with_own_transport("https://owner.example.com")
                .with_threshold(2)
                .with_timeouts(crate::protocol::types::Timeouts {
                    expired_channels: ExpiredChannelCleanup::Disabled,
                    ..Default::default()
                })
                .build()
                .expect("test protocol builds");

            let removed = protocol
                .remove_expired_channels(60)
                .await
                .expect("sweep succeeds");

            assert_eq!(removed, vec![ChannelId(1)]);
            assert!(secrets.data.lock().unwrap().is_empty());
        });
    }

    /// An explicit zero is not clamped — the minimum-of-1 rule guards the
    /// automatic sweep only. A `Pending` channel from an earlier second
    /// goes; the `Paired` one stays.
    #[test]
    fn explicit_zero_sweeps_pending_from_earlier_seconds() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 1).await;
            seed(&mut seeded, 2, ChannelStatus::Paired, 1).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
            let removed = protocol
                .remove_expired_channels(0)
                .await
                .expect("sweep succeeds");

            assert_eq!(removed, vec![ChannelId(1)]);
            assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
        });
    }

    /// The comparison is strict, so a channel created within the current
    /// second survives even the most aggressive threshold. This pins the
    /// boundary the automatic sweep relies on to avoid deleting pairings
    /// the instant they start.
    #[test]
    fn zero_age_channel_survives_zero_threshold() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 0).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
            let removed = protocol
                .remove_expired_channels(0)
                .await
                .expect("sweep succeeds");

            assert!(removed.is_empty());
            assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
        });
    }
}

/// Round-outcome accounting for the two populations a publish targets.
///
/// Exercises the flows in §9a of the replica-group spec directly against the
/// accumulator, without standing up a full peer mesh: the accumulator is the
/// component that decides what an application is told about a round, and it is
/// the piece that a shared group channel breaks.
#[cfg(test)]
mod sharing_round_outcome_tests {
    use super::*;
    use crate::protocol::test::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::types::ReplicaId;

    const SECRET_ID: u64 = 0xF00D;

    // The persisting double: the accumulator reads back what it wrote, so a
    // no-op state store would make every assertion here vacuous.
    type TestProtocol = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        NoopTransport,
    >;

    fn build(threshold: usize) -> TestProtocol {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transport("https://owner.example.com")
            .with_threshold(threshold)
            .build()
            .expect("test protocol builds")
    }

    async fn seed_round(
        protocol: &mut TestProtocol,
        version: u32,
        helpers: &[u64],
        members: &[u64],
    ) {
        protocol
            .state_store
            .save(
                SECRET_ID,
                StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                    version,
                    pending: helpers.iter().copied().map(ChannelId).collect(),
                    confirmed: HashSet::new(),
                    failed: HashSet::new(),
                    pending_replicas: members.iter().copied().map(ReplicaId).collect(),
                    synced_replicas: HashSet::new(),
                    behind_replicas: HashSet::new(),
                    started_at: now_secs(),
                })),
            )
            .await
            .expect("seed round");
    }

    /// Two rounds open at once each settle on their own.
    ///
    /// Rounds are not started only by `start(ProtectSecret)`: the
    /// pair-completion hook and the promotion inside `verify_fingerprint` both
    /// publish while handling an *inbound* message, so a second round can open
    /// under an application that never asked for one. When the row was keyed by
    /// `secret_id` alone the newcomer replaced its predecessor and **neither**
    /// finished — responses for the replaced round landed against state that no
    /// longer existed, and no `SharingComplete` was emitted for either. The
    /// application could not defend against it, having no view of round state.
    #[test]
    fn two_open_rounds_settle_independently() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 7, &[9001], &[]).await;
            seed_round(&mut protocol, 8, &[9002], &[]).await;

            // Both rows survive; the second did not displace the first.
            for version in [7u32, 8] {
                assert!(
                    protocol
                        .state_store
                        .load(SECRET_ID, StateKey::SharingRound { version })
                        .await
                        .expect("load")
                        .is_some(),
                    "round v{version} must still be in flight"
                );
            }

            // Answer only v7. Its event carries the version, so v8 must ignore it.
            let mut events = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(9001),
                version: 7,
            }];
            protocol.update_sharing_round(&mut events).await;

            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 7, .. })),
                "v7 completes once its only helper confirms; got {events:?}"
            );
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 8, .. })),
                "v8 has an outstanding helper and must not complete; got {events:?}"
            );
            assert!(
                protocol
                    .state_store
                    .load(SECRET_ID, StateKey::SharingRound { version: 7 })
                    .await
                    .expect("load")
                    .is_none(),
                "a completed round leaves no row"
            );

            // v8 is untouched and still settles on its own answer.
            let mut events = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(9002),
                version: 8,
            }];
            protocol.update_sharing_round(&mut events).await;
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 8, .. })),
                "v8 completes when its own helper answers; got {events:?}"
            );
            assert!(
                protocol
                    .state_store
                    .load(SECRET_ID, StateKey::SharingRound { version: 8 })
                    .await
                    .expect("load")
                    .is_none(),
                "a completed round leaves no row"
            );
        });
    }

    /// A round with no further traffic still reaches a terminal state.
    ///
    /// Timeouts are otherwise only evaluated inside `process`, so a publish
    /// whose helpers all go quiet has nothing left to trigger it. `tick` is
    /// the entry point a scheduler calls, and it must both fail the silent
    /// participants *and* close the round: reporting failures while leaving
    /// the round open would still strand an application waiting on
    /// `SharingComplete`.
    #[test]
    fn tick_closes_a_round_that_no_message_will_ever_finish() {
        run_async(async {
            let mut protocol = build(2);
            protocol.timeouts.sharing_round = std::time::Duration::from_secs(60);

            // A round started well outside the timeout window, with one helper
            // and one member that never answered.
            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: 3,
                        pending: [ChannelId(9001)].into_iter().collect(),
                        confirmed: [ChannelId(9002)].into_iter().collect(),
                        failed: HashSet::new(),
                        pending_replicas: [ReplicaId(1002)].into_iter().collect(),
                        synced_replicas: HashSet::new(),
                        behind_replicas: HashSet::new(),
                        started_at: now_secs().saturating_sub(600),
                    })),
                )
                .await
                .expect("seed round");

            let events = protocol.tick().await;

            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ShareRejected { channel_id, memo, .. }
                        if *channel_id == ChannelId(9001) && memo == "timeout"
                )),
                "the silent helper is failed; got {events:?}"
            );
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ReplicaSyncFailed { replica_id, reason, .. }
                        if *replica_id == 1002 && reason == "timeout"
                )),
                "the silent member is reported behind; got {events:?}"
            );
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 3, .. })),
                "the round must actually close, not just report failures; got {events:?}"
            );
            assert!(
                protocol
                    .state_store
                    .load(SECRET_ID, StateKey::SharingRound { version: 3 })
                    .await
                    .expect("load")
                    .is_none(),
                "a closed round leaves no state row behind"
            );
        });
    }

    /// `tick` runs the unpair sweep too, not only the sharing round.
    ///
    /// An unpair sent under `UnpairAck::Required` keeps local state alive
    /// until the peer acknowledges. A peer that never answers would otherwise
    /// pin that state forever, since nothing else would arrive to trigger the
    /// check.
    #[test]
    fn tick_expires_an_unacknowledged_unpair() {
        run_async(async {
            let mut protocol = build(2);
            protocol.timeouts.unpair_ack = std::time::Duration::from_secs(60);

            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::PendingUnpair {
                        channel_id: ChannelId(4242),
                        started_at: now_secs().saturating_sub(600),
                    },
                )
                .await
                .expect("seed pending unpair");

            let events = protocol.tick().await;

            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::Unpaired { channel_id } if *channel_id == ChannelId(4242)
                )),
                "the unacknowledged unpair completes on the timeout; got {events:?}"
            );
            assert!(
                protocol
                    .state_store
                    .load(
                        SECRET_ID,
                        StateKey::PendingUnpair {
                            channel_id: ChannelId(4242)
                        }
                    )
                    .await
                    .expect("load")
                    .is_none(),
                "the pending row is consumed"
            );
        });
    }

    /// A pending unpair still inside its window survives a `tick`.
    #[test]
    fn tick_leaves_a_recent_unpair_pending() {
        run_async(async {
            let mut protocol = build(2);
            protocol.timeouts.unpair_ack = std::time::Duration::from_secs(600);

            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::PendingUnpair {
                        channel_id: ChannelId(4242),
                        started_at: now_secs(),
                    },
                )
                .await
                .expect("seed pending unpair");

            let events = protocol.tick().await;

            assert!(events.is_empty(), "got {events:?}");
            assert!(
                protocol
                    .state_store
                    .load(
                        SECRET_ID,
                        StateKey::PendingUnpair {
                            channel_id: ChannelId(4242)
                        }
                    )
                    .await
                    .expect("load")
                    .is_some(),
                "the acknowledgement window has not elapsed"
            );
        });
    }

    /// Expired-channel cleanup is part of `tick`, and follows the same
    /// configuration `process` honours rather than a rule of its own.
    ///
    /// Disabled is the default, so a `tick` on a protocol that never opted in
    /// must leave a stale pending channel alone; `remove_expired_channels`
    /// stays available for callers that want to sweep explicitly.
    #[test]
    fn tick_honours_the_expired_channel_policy() {
        run_async(async {
            for (cleanup, expect_removed) in [
                (crate::protocol::ExpiredChannelCleanup::Disabled, false),
                (
                    crate::protocol::ExpiredChannelCleanup::Enabled { timeout_in_secs: 1 },
                    true,
                ),
            ] {
                let mut protocol = build(2);
                protocol.timeouts.expired_channels = cleanup;
                protocol
                    .channel_store
                    .save(
                        SECRET_ID,
                        crate::protocol::types::ChannelRecord::Helper(
                            crate::protocol::types::HelperChannel {
                                channel_id: ChannelId(77),
                                transport: derec_proto::TransportProtocol {
                                    uri: "https://stale.example".to_owned(),
                                    protocol: derec_proto::Protocol::Https as i32,
                                },
                                communication_info: std::collections::HashMap::new(),
                                peer_role: derec_proto::SenderKind::Helper,
                                status: crate::protocol::types::ChannelStatus::Pending,
                                created_at: now_secs().saturating_sub(3600),
                            },
                        ),
                    )
                    .await
                    .expect("seed stale pending channel");

                let _ = protocol.tick().await;

                let gone = protocol
                    .channel_store
                    .helpers(SECRET_ID)
                    .await
                    .expect("helpers")
                    .is_empty();
                assert_eq!(
                    gone, expect_removed,
                    "cleanup {cleanup:?}: expected removed={expect_removed}"
                );
            }
        });
    }

    /// `tick` is safe to call on an idle protocol — the common case for a
    /// scheduler firing on a quiet partition.
    #[test]
    fn tick_on_an_idle_protocol_does_nothing() {
        run_async(async {
            let mut protocol = build(2);
            let events = protocol.tick().await;
            assert!(events.is_empty(), "got {events:?}");
        });
    }

    /// A round still inside its window is left alone: `tick` must not cut
    /// short a publish whose helpers are merely slow.
    #[test]
    fn tick_leaves_a_round_inside_its_window_open() {
        run_async(async {
            let mut protocol = build(2);
            protocol.timeouts.sharing_round = std::time::Duration::from_secs(600);
            seed_round(&mut protocol, 4, &[9001], &[1002]).await;

            let events = protocol.tick().await;

            assert!(events.is_empty(), "got {events:?}");
            assert!(
                protocol
                    .state_store
                    .load(SECRET_ID, StateKey::SharingRound { version: 4 })
                    .await
                    .expect("load")
                    .is_some(),
                "the round is still in flight"
            );
        });
    }

    /// The publisher drops a departing member's row once that member has
    /// acknowledged the version excluding it.
    ///
    /// Reconciliation normally runs when a roster *arrives*, but the device
    /// that ran the removal never receives the roster it just sent. Without a
    /// publisher-side pass it would keep the flagged row forever and keep
    /// addressing a member that has already torn itself down — the removal
    /// would converge everywhere except on the device that ordered it.
    #[test]
    fn the_publisher_drops_a_departing_member_once_it_acknowledges() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 7, &[9001], &[1002, 1003]).await;

            for (id, status) in [
                (1002u64, crate::protocol::types::ChannelStatus::Paired),
                (1003, crate::protocol::types::ChannelStatus::Unpairing),
            ] {
                protocol
                    .channel_store
                    .save(
                        SECRET_ID,
                        crate::protocol::types::ChannelRecord::Replica(
                            crate::protocol::types::ReplicaMember {
                                channel_id: ChannelId(5001),
                                replica_id: ReplicaId(id),
                                transport: derec_proto::TransportProtocol {
                                    uri: "https://peer.example".to_owned(),
                                    protocol: derec_proto::Protocol::Https as i32,
                                },
                                communication_info: std::collections::HashMap::new(),
                                role: crate::protocol::types::ReplicaRole::Destination,
                                status,
                                created_at: 0,
                            },
                        ),
                    )
                    .await
                    .expect("seed member");
            }

            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 7,
                },
                DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1002,
                    secret_id: SECRET_ID,
                    version: 7,
                    status: 0,
                    memo: String::new(),
                },
                DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1003,
                    secret_id: SECRET_ID,
                    version: 7,
                    status: 0,
                    memo: String::new(),
                },
            ];
            protocol.update_sharing_round(&mut events).await;

            let remaining: Vec<u64> = protocol
                .channel_store
                .replicas(SECRET_ID)
                .await
                .expect("roster")
                .into_iter()
                .map(|m| m.replica_id.0)
                .collect();
            assert_eq!(
                remaining,
                vec![1002],
                "the acknowledged departing member is gone; the other survives"
            );
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ReplicaRemoved { replica_id } if *replica_id == 1003
                )),
                "the removal is reported to the application; got {events:?}"
            );
        });
    }

    /// A member flagged as leaving that has **not** acknowledged keeps its row.
    ///
    /// Its departure is not complete until it has seen the excluding version,
    /// and dropping it early would stop the publisher addressing the very
    /// member it still needs to reach.
    #[test]
    fn a_departing_member_that_has_not_answered_is_kept() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 7, &[9001], &[1002]).await;

            protocol
                .channel_store
                .save(
                    SECRET_ID,
                    crate::protocol::types::ChannelRecord::Replica(
                        crate::protocol::types::ReplicaMember {
                            channel_id: ChannelId(5001),
                            replica_id: ReplicaId(1003),
                            transport: derec_proto::TransportProtocol {
                                uri: "https://peer.example".to_owned(),
                                protocol: derec_proto::Protocol::Https as i32,
                            },
                            communication_info: std::collections::HashMap::new(),
                            role: crate::protocol::types::ReplicaRole::Destination,
                            status: crate::protocol::types::ChannelStatus::Unpairing,
                            created_at: 0,
                        },
                    ),
                )
                .await
                .expect("seed member");

            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 7,
                },
                DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1002,
                    secret_id: SECRET_ID,
                    version: 7,
                    status: 0,
                    memo: String::new(),
                },
            ];
            protocol.update_sharing_round(&mut events).await;

            let remaining: Vec<u64> = protocol
                .channel_store
                .replicas(SECRET_ID)
                .await
                .expect("roster")
                .into_iter()
                .map(|m| m.replica_id.0)
                .collect();
            assert_eq!(
                remaining,
                vec![1003],
                "an unacknowledged departure leaves the row in place"
            );
        });
    }

    /// The regression a shared group channel creates: two members answering on
    /// one channel must settle independently. Keyed on `ChannelId` they would
    /// collapse, and the first ack would complete the round for both.
    #[test]
    fn members_on_one_channel_settle_independently() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 4, &[9001], &[1002, 1003]).await;

            // Only member 1002 answers.
            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 4,
                },
                DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1002,
                    secret_id: SECRET_ID,
                    version: 4,
                    status: 0,
                    memo: String::new(),
                },
            ];
            protocol.update_sharing_round(&mut events).await;

            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { .. })),
                "the round must stay open while member 1003 has not answered"
            );

            // 1003 answers on the same channel; now the round closes.
            let mut events = vec![DeRecEvent::ReplicaSecretAcked {
                channel_id: ChannelId(5001),
                from_replica_id: 1003,
                secret_id: SECRET_ID,
                version: 4,
                status: 0,
                memo: String::new(),
            }];
            protocol.update_sharing_round(&mut events).await;

            let sync = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::ReplicaSyncComplete { synced, behind, .. } => {
                        Some((synced.clone(), behind.clone()))
                    }
                    _ => None,
                })
                .expect("replica leg must report its own completion");
            assert_eq!(sync, (vec![1002, 1003], vec![]));
        });
    }

    /// F2: a member that never answers is `behind`, and does not fail the
    /// round — the helper leg alone decides `threshold_met`.
    #[test]
    fn an_unreachable_member_leaves_the_round_successful() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 4, &[9001, 9002], &[1003]).await;

            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 4,
                },
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9002),
                    version: 4,
                },
                DeRecEvent::ReplicaSyncFailed {
                    replica_id: 1003,
                    version: 4,
                    reason: "transport unreachable".to_owned(),
                },
            ];
            // A dispatch failure never entered `pending_replicas`, so the round
            // is settled by the helper leg alone; drain the member by hand to
            // mirror what `start` records at dispatch time.
            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: 4,
                        pending: HashSet::from([ChannelId(9001), ChannelId(9002)]),
                        confirmed: HashSet::new(),
                        failed: HashSet::new(),
                        pending_replicas: HashSet::new(),
                        synced_replicas: HashSet::new(),
                        behind_replicas: HashSet::from([ReplicaId(1003)]),
                        started_at: now_secs(),
                    })),
                )
                .await
                .expect("seed");
            protocol.update_sharing_round(&mut events).await;

            let complete = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::SharingComplete { threshold_met, .. } => Some(*threshold_met),
                    _ => None,
                })
                .expect("helper leg must complete");
            assert!(
                complete,
                "an unreachable replica must not fail the helper round"
            );

            let sync = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::ReplicaSyncComplete { synced, behind, .. } => {
                        Some((synced.clone(), behind.clone()))
                    }
                    _ => None,
                })
                .expect("replica leg must report its own completion");
            assert_eq!(sync, (vec![], vec![1003]), "the member is reported behind");
        });
    }

    /// F1: a member refusing with a conflict lands in `behind`, reported
    /// separately from the helper leg's own verdict.
    #[test]
    fn a_conflicting_member_is_reported_behind() {
        run_async(async {
            let mut protocol = build(3);
            seed_round(&mut protocol, 4, &[9001, 9002, 9003], &[1002, 1003]).await;

            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 4,
                },
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9002),
                    version: 4,
                },
                DeRecEvent::ShareRejected {
                    channel_id: ChannelId(9003),
                    version: 4,
                    status: derec_proto::StatusEnum::VersionConflict as i32,
                    memo: "conflict".to_owned(),
                },
                DeRecEvent::ReplicaSyncRejected {
                    replica_id: 1002,
                    secret_id: SECRET_ID,
                    version: 4,
                    status: derec_proto::StatusEnum::VersionConflict as i32,
                    memo: "conflict".to_owned(),
                },
                DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1003,
                    secret_id: SECRET_ID,
                    version: 4,
                    status: 0,
                    memo: String::new(),
                },
            ];
            protocol.update_sharing_round(&mut events).await;

            let (confirmed, failed, threshold_met) = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::SharingComplete {
                        confirmed_count,
                        failed_count,
                        threshold_met,
                        ..
                    } => Some((*confirmed_count, *failed_count, *threshold_met)),
                    _ => None,
                })
                .expect("helper leg must complete");
            assert_eq!((confirmed, failed), (2, 1));
            assert!(!threshold_met, "2 of 3 helpers is under a threshold of 3");

            let sync = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::ReplicaSyncComplete { synced, behind, .. } => {
                        Some((synced.clone(), behind.clone()))
                    }
                    _ => None,
                })
                .expect("replica leg must report its own completion");
            assert_eq!(sync, (vec![1003], vec![1002]));
        });
    }

    /// A publish with no replica group stays silent on the replica leg rather
    /// than reporting an empty one.
    #[test]
    fn a_helpers_only_round_emits_no_replica_summary() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 2, &[9001], &[]).await;

            let mut events = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(9001),
                version: 2,
            }];
            protocol.update_sharing_round(&mut events).await;

            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { .. })),
                "the helper leg still completes"
            );
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ReplicaSyncComplete { .. })),
                "a round with no replica leg must not report one"
            );
        });
    }
}

#[cfg(test)]
mod helper_fingerprint_gate_tests {
    use super::*;
    use crate::protocol::test::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel, SecretValue};

    const SECRET_ID: u64 = 0xF1;
    const CHANNEL: ChannelId = ChannelId(77);

    fn endpoint() -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: "https://helper.example.com".to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    /// A helper channel mid-gate: pairing completed, fingerprint not yet
    /// compared. This is the state a `NoKeys` helper pairing now lands in.
    async fn seed_pending_helper(
        channels: &mut InMemChannelStore,
        secrets: &mut InMemSecretStore,
        status: ChannelStatus,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: CHANNEL,
                    transport: endpoint(),
                    communication_info: std::collections::HashMap::new(),
                    status,
                    created_at: now_secs(),
                    peer_role: derec_proto::SenderKind::Helper,
                }),
            )
            .await
            .expect("seed helper channel");
        secrets
            .save(SECRET_ID, CHANNEL, SecretValue::SharedKey([7u8; 32]))
            .await
            .expect("seed shared key");
    }

    fn build(
        channels: InMemChannelStore,
        secrets: InMemSecretStore,
    ) -> DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
        NoopTransport,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels)
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets)
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transport("https://owner.example.com")
            .with_threshold(2)
            .build()
            .expect("test protocol builds")
    }

    async fn status_of(channels: &mut InMemChannelStore) -> ChannelStatus {
        channels
            .load(
                SECRET_ID,
                crate::protocol::types::ChannelQuery::Helper {
                    channel_id: CHANNEL,
                },
            )
            .await
            .expect("load helper")
            .expect("helper row present")
            .status()
    }

    /// The gate opens. Without this the `Pending` status a `NoKeys` helper
    /// pairing lands in would be terminal — `verify_fingerprint` only ever
    /// walked `replicas()`, so the channel could never become usable.
    #[test]
    fn a_matching_fingerprint_promotes_a_pending_helper() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let (mut seeded_ch, mut seeded_se) = (channels.clone(), secrets.clone());
            seed_pending_helper(&mut seeded_ch, &mut seeded_se, ChannelStatus::Pending).await;

            let mut protocol = build(channels.clone(), secrets.clone());
            let fingerprint = protocol
                .get_fingerprint(CHANNEL)
                .await
                .expect("fingerprint derives from the shared key");

            assert!(
                protocol
                    .verify_fingerprint(CHANNEL, &fingerprint)
                    .await
                    .expect("verify_fingerprint"),
                "a matching fingerprint must verify"
            );

            let mut check = channels.clone();
            assert_eq!(
                status_of(&mut check).await,
                ChannelStatus::Paired,
                "a verified helper channel must become usable"
            );
        });
    }

    /// A mismatch is the MITM case the gate exists for: the channel stays
    /// inert so nothing can be shared over it.
    #[test]
    fn a_wrong_fingerprint_leaves_the_helper_pending() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let (mut seeded_ch, mut seeded_se) = (channels.clone(), secrets.clone());
            seed_pending_helper(&mut seeded_ch, &mut seeded_se, ChannelStatus::Pending).await;

            let mut protocol = build(channels.clone(), secrets.clone());
            assert!(
                !protocol
                    .verify_fingerprint(CHANNEL, "not-the-fingerprint")
                    .await
                    .expect("verify_fingerprint"),
                "a mismatched fingerprint must not verify"
            );

            let mut check = channels.clone();
            assert_eq!(
                status_of(&mut check).await,
                ChannelStatus::Pending,
                "a failed comparison must leave the channel inert"
            );
        });
    }

    /// An already-`Paired` helper — the `InlineKeys` / `HashedKeys` case — is
    /// untouched, so re-confirming a channel is harmless and the promotion
    /// branch cannot re-fire the publish hook.
    #[test]
    fn verifying_an_already_paired_helper_changes_nothing() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let (mut seeded_ch, mut seeded_se) = (channels.clone(), secrets.clone());
            seed_pending_helper(&mut seeded_ch, &mut seeded_se, ChannelStatus::Paired).await;

            let mut protocol = build(channels.clone(), secrets.clone());
            let fingerprint = protocol
                .get_fingerprint(CHANNEL)
                .await
                .expect("fingerprint");
            assert!(
                protocol
                    .verify_fingerprint(CHANNEL, &fingerprint)
                    .await
                    .expect("verify_fingerprint")
            );

            let mut check = channels.clone();
            assert_eq!(status_of(&mut check).await, ChannelStatus::Paired);
        });
    }
}

/// The four waiting periods, and the property that makes them four rather
/// than one: each governs only its own concern.
///
/// They were a single `timeout_in_secs` until it forced a bad trade —
/// shortening the sharing round so a stalled publish surfaced sooner also
/// narrowed the replay window every inbound message is judged against. The
/// independence asserted here is the whole reason the split exists, so it is
/// tested directly rather than left implied.
#[cfg(test)]
mod timeout_tests {
    use super::*;
    use crate::protocol::test::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::protocol::types::Timeouts;
    use std::time::Duration;

    const SECRET_ID: u64 = 0x7180;

    type TestProtocol = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        NoopTransport,
    >;

    fn build_with(timeouts: Timeouts) -> TestProtocol {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transport("https://owner.example.com")
            .with_threshold(2)
            .with_timeouts(timeouts)
            .build()
            .expect("test protocol builds")
    }

    /// An envelope whose timestamp is `age_secs` in the past.
    fn envelope_aged(age_secs: u64) -> DeRecMessage {
        DeRecMessage {
            timestamp: Some(prost_types::Timestamp {
                seconds: now_secs().saturating_sub(age_secs) as i64,
                nanos: 0,
            }),
            ..Default::default()
        }
    }

    /// The defaults are load-bearing — every binding omits fields and relies
    /// on these, so a change here changes behaviour for all seven surfaces.
    #[test]
    fn defaults_are_the_documented_values() {
        let d = Timeouts::default();
        assert_eq!(d.inbound_message, Duration::from_secs(300));
        assert_eq!(d.sharing_round, Duration::from_secs(60));
        assert_eq!(d.unpair_ack, Duration::from_secs(60));
        assert_eq!(
            d.expired_channels,
            crate::protocol::ExpiredChannelCleanup::Enabled {
                timeout_in_secs: 300
            }
        );
    }

    /// The staleness boundary had no test at all before the split, despite
    /// being the replay-defence window.
    #[test]
    fn inbound_message_bounds_how_stale_an_envelope_may_be() {
        let protocol = build_with(Timeouts {
            inbound_message: Duration::from_secs(120),
            ..Default::default()
        });

        assert!(
            !protocol.is_message_expired(&envelope_aged(60), ChannelId(1)),
            "an envelope inside the window is accepted"
        );
        assert!(
            !protocol.is_message_expired(&envelope_aged(120), ChannelId(1)),
            "the boundary itself is inclusive"
        );
        assert!(
            protocol.is_message_expired(&envelope_aged(121), ChannelId(1)),
            "an envelope past the window is discarded"
        );
    }

    /// A timestampless envelope is not judged stale — the timestamp
    /// invariant is enforced elsewhere, and treating "absent" as "expired"
    /// here would mask it.
    #[test]
    fn an_envelope_without_a_timestamp_is_not_expired() {
        let protocol = build_with(Timeouts::default());
        let envelope = DeRecMessage {
            timestamp: None,
            ..Default::default()
        };
        assert!(!protocol.is_message_expired(&envelope, ChannelId(1)));
    }

    /// **The point of the split.** Shortening the liveness budgets must not
    /// narrow the security boundary. Under the old single knob, asking for a
    /// 1-second sharing round also meant refusing every message more than a
    /// second old.
    #[test]
    fn shortening_the_liveness_budgets_leaves_the_replay_window_alone() {
        let protocol = build_with(Timeouts {
            sharing_round: Duration::from_secs(1),
            unpair_ack: Duration::from_secs(1),
            ..Default::default()
        });

        assert_eq!(protocol.timeouts.inbound_message, Duration::from_secs(300));
        assert!(
            !protocol.is_message_expired(&envelope_aged(290), ChannelId(1)),
            "a message well inside the default replay window is still accepted \
             even though both liveness budgets are one second"
        );
    }

    /// And the converse: a long replay window does not keep a stalled round
    /// open. Both directions matter — one knob meant either mistake was
    /// reachable by tuning the other concern.
    #[test]
    fn a_long_replay_window_does_not_extend_the_sharing_round() {
        run_async(async {
            let mut protocol = build_with(Timeouts {
                inbound_message: Duration::from_secs(3600),
                sharing_round: Duration::from_secs(1),
                ..Default::default()
            });

            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: 1,
                        pending: [ChannelId(9001)].into_iter().collect(),
                        confirmed: HashSet::new(),
                        failed: HashSet::new(),
                        pending_replicas: HashSet::new(),
                        synced_replicas: HashSet::new(),
                        behind_replicas: HashSet::new(),
                        started_at: now_secs().saturating_sub(30),
                    })),
                )
                .await
                .expect("seed round");

            let events = protocol.tick().await;
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 1, .. })),
                "the round times out on its own budget, not the replay window; got {events:?}"
            );
        });
    }
}

/// The scheme policy as the orchestrator applies it, rather than as
/// [`crate::transport::TransportPolicy`] defines it in isolation.
///
/// Three things can introduce a transport endpoint, and only one of them is
/// pairing — which is why validating at pairing alone would leave two doors
/// open. All three are funnelled through `handlers::peer_supplied_endpoints`
/// so the rule has one definition; these tests check the funnel is wired, not
/// that the rule is right (`transport_policy_tests` does that).
#[cfg(test)]
mod transport_gate_tests {
    use super::*;
    use crate::protocol::test::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };

    const SECRET_ID: u64 = 0x60A7;

    fn builder_with(
        own: &str,
        unsafe_http: bool,
    ) -> crate::Result<
        DeRecProtocol<
            InMemChannelStore,
            InMemShareStore,
            InMemSecretStore,
            InMemUserSecretStore,
            InMemPersistedStateStore,
            NoopTransport,
        >,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transport(own)
            .with_threshold(2)
            .with_unsafe_http(unsafe_http)
            .build()
    }

    /// The zero-config developer case: a loopback dev server just works.
    #[test]
    fn own_loopback_needs_no_configuration() {
        run_async(async {
            for uri in [
                "http://localhost:8080",
                "http://127.0.0.1:8080",
                "http://[::1]:8080",
            ] {
                assert!(builder_with(uri, false).is_ok(), "{uri} should build");
            }
        });
    }

    /// The LAN case — a phone talking to a laptop — is what the flag exists
    /// for, and it is refused until you ask for it.
    #[test]
    fn own_lan_plaintext_needs_the_flag() {
        run_async(async {
            let Err(err) = builder_with("http://192.168.1.42:8080", false) else {
                panic!("LAN plaintext must not build by default");
            };
            assert!(
                matches!(
                    err,
                    crate::Error::Transport(
                        crate::transport::TransportValidationError::PlaintextRefused { .. }
                    )
                ),
                "expected a plaintext refusal, got {err:?}"
            );
            assert!(builder_with("http://192.168.1.42:8080", true).is_ok());
        });
    }

    /// Order of the two setters must not matter — the policy is applied at
    /// `build`, not when either one is called.
    #[test]
    fn setter_order_does_not_matter() {
        run_async(async {
            let built = DeRecProtocolBuilder::new(SECRET_ID)
                .with_unsafe_http(true)
                .with_channel_store(InMemChannelStore::default())
                .with_share_store(InMemShareStore::default())
                .with_secret_store(InMemSecretStore::default())
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_transport(NoopTransport)
                .with_state_store(InMemPersistedStateStore::default())
                .with_own_transport("http://192.168.1.42:8080")
                .with_threshold(2)
                .build();
            assert!(built.is_ok(), "unsafe_http set before the endpoint");
        });
    }

    /// `https` is unaffected by any of this.
    #[test]
    fn https_builds_under_either_setting() {
        run_async(async {
            assert!(builder_with("https://owner.example.com", false).is_ok());
            assert!(builder_with("https://owner.example.com", true).is_ok());
        });
    }

    /// The accessor the funnel depends on must actually see every field a
    /// peer controls. If a new message type gains a `reply_to` or a
    /// transport, this is what should fail first.
    #[test]
    fn every_peer_supplied_endpoint_is_reachable_from_the_funnel() {
        use derec_proto::{MessageBody, TransportProtocol};
        let ep = || {
            Some(TransportProtocol {
                uri: "http://127.0.0.1:9999".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            })
        };

        let bodies = [
            MessageBody::StoreShareRequest(derec_proto::StoreShareRequestMessage {
                reply_to: ep(),
                ..Default::default()
            }),
            MessageBody::VerifyShareRequest(derec_proto::VerifyShareRequestMessage {
                reply_to: ep(),
                ..Default::default()
            }),
            MessageBody::GetSecretIdsVersionsRequest(
                derec_proto::GetSecretIdsVersionsRequestMessage {
                    reply_to: ep(),
                    ..Default::default()
                },
            ),
            MessageBody::GetShareRequest(derec_proto::GetShareRequestMessage {
                reply_to: ep(),
                ..Default::default()
            }),
            MessageBody::UnpairRequest(derec_proto::UnpairRequestMessage {
                reply_to: ep(),
                ..Default::default()
            }),
            MessageBody::UpdateChannelInfoRequest(derec_proto::UpdateChannelInfoRequestMessage {
                transport_protocol: ep(),
                ..Default::default()
            }),
            MessageBody::PairRequest(derec_proto::PairRequestMessage {
                transport_protocol: ep(),
                ..Default::default()
            }),
            MessageBody::PrePairRequest(derec_proto::PrePairRequestMessage {
                transport_protocol: ep(),
                ..Default::default()
            }),
        ];

        for body in &bodies {
            let found: Vec<_> = handlers::peer_supplied_endpoints(body).collect();
            assert_eq!(
                found.len(),
                1,
                "the funnel missed the peer endpoint on {body:?}"
            );
            // And the strict policy refuses it — peer loopback is not free.
            assert!(
                crate::transport::TransportPolicy::new(false)
                    .check_peer(found[0])
                    .is_err()
            );
        }
    }
}
