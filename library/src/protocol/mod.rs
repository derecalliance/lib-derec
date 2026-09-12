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
//!   governed by [`DeRecProtocolBuilder::with_unpair_ack`](crate::protocol::DeRecProtocolBuilder::with_unpair_ack).
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
pub mod transport_adapters;
pub mod types;
pub mod utils;

pub(crate) mod actions;
pub(crate) mod builder;
pub(crate) mod config;
pub(crate) mod context;
pub(crate) mod fingerprint;
pub(crate) mod flows;
mod handlers;
pub(crate) mod process;
pub(crate) mod stores;
pub(crate) mod sweeps;

/// In-memory store and transport doubles shared by the unit tests
/// throughout this module. Lives at the `protocol` level because the
/// doubles implement the [`traits`] store interfaces and the rigs build
/// a whole [`DeRecProtocol`] — neither is specific to [`handlers`].
#[cfg(test)]
pub(crate) mod test;

pub use builder::{DEFAULT_KEEP_VERSIONS_COUNT, DEFAULT_THRESHOLD, DeRecProtocolBuilder};
use derec_proto::TransportProtocol;
pub use error::{
    ChannelStoreError, ProcessError, SecretStoreError, ShareStoreError, StateStoreError,
};
use std::collections::HashMap;
pub use traits::{
    ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore,
    DeRecTransport, DeRecUserSecretStore, SecretStoreFuture, ShareStoreFuture, StateStoreFuture,
    TransportFuture,
};
pub use transport_adapters::{SendOne, SequentialFailover, SingleEndpointTransport};
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
///   │                                                               [`DeRecProtocolBuilder::with_unpair_ack`](crate::protocol::DeRecProtocolBuilder::with_unpair_ack))
///   ├── start(ReplicaDiscovery)                         → replica catch-up (replica-only; asks the
///   │                                                                group whether this device
///   │                                                                is behind)
///   └── start(UnpairReplica)                     → replica removal (replica-only; voluntary
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
    /// Set via [`DeRecProtocolBuilder::with_channel_store`](crate::protocol::DeRecProtocolBuilder::with_channel_store).
    pub channel_store: ChannelStore,
    /// Set via [`DeRecProtocolBuilder::with_share_store`](crate::protocol::DeRecProtocolBuilder::with_share_store).
    pub share_store: ShareStore,
    /// Set via [`DeRecProtocolBuilder::with_secret_store`](crate::protocol::DeRecProtocolBuilder::with_secret_store).
    pub secret_store: SecretStore,
    /// Set via [`DeRecProtocolBuilder::with_user_secret_store`](crate::protocol::DeRecProtocolBuilder::with_user_secret_store).
    pub user_secret_store: UserSecretStore,
    /// Set via [`DeRecProtocolBuilder::with_state_store`](crate::protocol::DeRecProtocolBuilder::with_state_store). Holds
    /// in-flight orchestrator state (verification challenges, recovery
    /// accumulators, pending unpair acks) so stateless / load-balanced
    /// deployments preserve it across process restarts.
    pub state_store: StateStore,
    /// Set via [`DeRecProtocolBuilder::with_transport`](crate::protocol::DeRecProtocolBuilder::with_transport).
    pub transport: Transport,
    /// Set via [`DeRecProtocolBuilder::with_own_transport`](crate::protocol::DeRecProtocolBuilder::with_own_transport) or
    /// [`DeRecProtocolBuilder::with_own_transports`](crate::protocol::DeRecProtocolBuilder::with_own_transports), in preference order.
    /// Never empty — the typestate builder cannot reach `build()` without
    /// this slot filled. The order is the application's and is never
    /// reinterpreted; the first entry is this device's primary endpoint, and
    /// is what fills the legacy singular `transportProtocol` field for peers
    /// predating the offer list.
    pub own_transports: Vec<TransportProtocol>,
    /// Configured via [`DeRecProtocolBuilder::with_unpair_ack`](crate::protocol::DeRecProtocolBuilder::with_unpair_ack).
    pub(crate) unpair_ack: UnpairAck,
    /// Configured via [`DeRecProtocolBuilder::with_threshold`](crate::protocol::DeRecProtocolBuilder::with_threshold).
    threshold: usize,
    /// Configured via [`DeRecProtocolBuilder::with_keep_versions_count`](crate::protocol::DeRecProtocolBuilder::with_keep_versions_count).
    keep_versions_count: usize,
    /// Configured via [`Timeouts`](crate::protocol::types::Timeouts).
    /// Configured via [`DeRecProtocolBuilder::with_timeouts`](crate::protocol::DeRecProtocolBuilder::with_timeouts).
    pub(crate) timeouts: crate::protocol::types::Timeouts,
    /// Configured via [`DeRecProtocolBuilder::with_unsafe_http`](crate::protocol::DeRecProtocolBuilder::with_unsafe_http).
    pub(crate) unsafe_http: bool,
    /// Configured via [`DeRecProtocolBuilder::with_communication_info`](crate::protocol::DeRecProtocolBuilder::with_communication_info).
    pub(crate) communication_info: HashMap<String, String>,
    /// Configured via [`DeRecProtocolBuilder::with_auto_respond_on_failure`](crate::protocol::DeRecProtocolBuilder::with_auto_respond_on_failure).
    pub(crate) auto_respond_on_failure: bool,
    /// Configured via [`DeRecProtocolBuilder::with_auto_reply_to`](crate::protocol::DeRecProtocolBuilder::with_auto_reply_to).
    ///
    /// When `true`, every outbound request envelope carries
    /// [`own_transports`](Self::own_transports) in full, so the responder can
    /// fail over rather than being given one address to try. When `false`
    /// (the default), outbound requests leave it unset and the responder
    /// falls back to the channel's stored peer endpoint. See
    /// `replyToTransports` on each request proto for the wire-level
    /// semantics, and `replyTo` beside it for the singular field kept for
    /// peers predating the list.
    pub(crate) auto_reply_to: bool,
    /// Configured via [`DeRecProtocolBuilder::with_auto_accept`](crate::protocol::DeRecProtocolBuilder::with_auto_accept).
    ///
    /// When a flow's field on the policy is `true`, [`Self::process`]
    /// invokes the equivalent of [`Self::accept`] internally for that
    /// flow and emits [`DeRecEvent::AutoAccepted`](crate::protocol::DeRecEvent::AutoAccepted) in place of
    /// [`DeRecEvent::ActionRequired`](crate::protocol::DeRecEvent::ActionRequired).
    pub(crate) auto_accept: AutoAcceptPolicy,
    /// Configured via [`DeRecProtocolBuilder::with_replica_id`](crate::protocol::DeRecProtocolBuilder::with_replica_id).
    ///
    /// `Some(id)` enables this node to participate in replica-mode pairings
    /// (the id is auto-injected under `derec.replica_id` in outbound
    /// `PairRequest`/`PairResponse`, and required to honour inbound replica
    /// pairings). `None` disables replica flows entirely — any attempt to
    /// initiate or accept a replica-mode pairing returns
    /// [`Error::ReplicaIdNotConfigured`](crate::Error::ReplicaIdNotConfigured).
    pub(crate) replica_id: Option<u64>,
    /// Configured via [`DeRecProtocolBuilder::with_parameter_range`](crate::protocol::DeRecProtocolBuilder::with_parameter_range).
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
