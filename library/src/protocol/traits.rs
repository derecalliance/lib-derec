// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::error::{ChannelStoreError, SecretStoreError, ShareStoreError, StateStoreError};
use crate::Result;
use crate::protocol::types::{
    ChannelQuery, ChannelRecord, HelperChannel, MissingPolicy, ReplicaMember, SecretKind,
    SecretValue, Share, StateItem, StateKey, StateKind, UserSecrets,
};
use crate::types::ChannelId;
use derec_proto::TransportProtocol;
use std::{future::Future, pin::Pin};

/// Type-erased future returned by [`DeRecSecretStore`] methods.
///
/// `Send` on every native target so multi-threaded executors (e.g.
/// `tokio::spawn`, an axum handler pool) can take it. Only `wasm32` drops the
/// bound, because its store adapters hold `JsValue`, which is not `Send`.
///
/// The condition is deliberately **`target_arch` alone, never a Cargo
/// feature** — see the `Send` contract note below. Sync backends can return
/// `Box::pin(std::future::ready(...))` at zero cost.
#[cfg(target_arch = "wasm32")]
pub type SecretStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, SecretStoreError>> + 'a>>;
/// Type-erased future returned by [`DeRecSecretStore`] methods.
///
/// `Send` on every native target so multi-threaded executors (e.g.
/// `tokio::spawn`, an axum handler pool) can take it. Only `wasm32` drops the
/// bound, because its store adapters hold `JsValue`, which is not `Send`.
///
/// The condition is deliberately **`target_arch` alone, never a Cargo
/// feature** — see the `Send` contract note below. Sync backends can return
/// `Box::pin(std::future::ready(...))` at zero cost.
#[cfg(not(target_arch = "wasm32"))]
pub type SecretStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, SecretStoreError>> + Send + 'a>>;

/// Type-erased future returned by [`DeRecChannelStore`] methods. See
/// [`SecretStoreFuture`] for the `Send` rules.
#[cfg(target_arch = "wasm32")]
pub type ChannelStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ChannelStoreError>> + 'a>>;
/// Type-erased future returned by [`DeRecChannelStore`] methods. See
/// [`SecretStoreFuture`] for the `Send` rules.
#[cfg(not(target_arch = "wasm32"))]
pub type ChannelStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ChannelStoreError>> + Send + 'a>>;

/// Type-erased future returned by [`DeRecShareStore`] methods. See
/// [`SecretStoreFuture`] for the `Send` rules.
#[cfg(target_arch = "wasm32")]
pub type ShareStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ShareStoreError>> + 'a>>;
/// Type-erased future returned by [`DeRecShareStore`] methods. See
/// [`SecretStoreFuture`] for the `Send` rules.
#[cfg(not(target_arch = "wasm32"))]
pub type ShareStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ShareStoreError>> + Send + 'a>>;

/// Type-erased future returned by [`DeRecTransport::send`]. See
/// [`SecretStoreFuture`] for the `Send` rules.
#[cfg(target_arch = "wasm32")]
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + 'a>>;
/// Type-erased future returned by [`DeRecTransport::send`]. See
/// [`SecretStoreFuture`] for the `Send` rules.
#[cfg(not(target_arch = "wasm32"))]
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Type-erased future returned by [`DeRecStateStore`] methods. See
/// [`SecretStoreFuture`] for the `Send` rules.
#[cfg(target_arch = "wasm32")]
pub type StateStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, StateStoreError>> + 'a>>;
/// Type-erased future returned by [`DeRecStateStore`] methods. See
/// [`SecretStoreFuture`] for the `Send` rules.
#[cfg(not(target_arch = "wasm32"))]
pub type StateStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, StateStoreError>> + Send + 'a>>;

/// Fails to compile if any store future loses `Send` on a native target.
///
/// The bound is load-bearing for every threaded host — `tokio::spawn`, axum
/// and actix all require it.
///
/// The `Send` distinction must stay keyed on `target_arch`, never on a Cargo
/// feature. Features are additive and unified across an entire build graph, so
/// a feature-keyed bound is not a property of the crate that requested it: any
/// crate anywhere in the graph enabling it would strip `Send` from every other
/// consumer of the same build, and the resulting error would point at that
/// consumer's own code rather than at the cause. This assertion turns that
/// mistake into a build failure here instead.
#[cfg(not(target_arch = "wasm32"))]
const _: () = {
    const fn require_send<T: Send>() {}
    require_send::<SecretStoreFuture<'static, ()>>();
    require_send::<ChannelStoreFuture<'static, ()>>();
    require_send::<ShareStoreFuture<'static, ()>>();
    require_send::<StateStoreFuture<'static, ()>>();
    require_send::<TransportFuture<'static>>();
};

/// Keychain-grade storage for the protocol's per-channel cryptographic state.
///
/// Holds three kinds of material (see [`SecretKind`]):
/// [`SecretKind::SharedKey`] and [`SecretKind::PairingSecret`] are
/// sensitive — implementations should persist them with keychain-grade
/// protection. [`SecretKind::PairingContact`] is a transient public-key blob
/// that only needs durable storage.
///
/// # VSS guarantee
///
/// Individual Verifiable Secret Sharing shares reveal **zero** information
/// about the original secret (information-theoretic security), so share
/// storage does **not** require this trait.
///
/// # Executor independence
///
/// Methods return [`SecretStoreFuture`] — a type-erased [`std::future::Future`]
/// that any executor can poll. Sync implementations return
/// `Box::pin(std::future::ready(...))` at zero cost; async implementations
/// return `Box::pin(async move { ... })`. No runtime is prescribed; see
/// [`SecretStoreFuture`] for the per-target `Send` rules.
///
/// # Concurrency
///
/// The protocol holds each store by `&mut Self`, so implementations never
/// see overlapping calls and need no internal synchronization.
pub trait DeRecSecretStore {
    /// Load a secret for the given `(secret_id, channel_id)` pair.
    ///
    /// `secret_id` partitions storage so a single backend can serve many
    /// secrets on the same device (Owner of N secrets, or Helper for N
    /// Owners). Returns `Ok(None)` when no entry of the requested
    /// [`SecretKind`] exists for this partition key.
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>>;

    /// Load secrets of the same [`SecretKind`] for several channels in
    /// one call, scoped to `secret_id`.
    ///
    /// Used by the [`crate::protocol`] orchestrator when broadcasting a
    /// request (discovery, recovery, verification, sharing, unpairing) to
    /// keep the per-broadcast roundtrip count constant instead of linear
    /// in the number of paired channels.
    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>>;

    /// Persist a secret for the given `(secret_id, channel_id)` pair.
    ///
    /// The [`SecretKind`] is derived from the [`SecretValue`] variant.
    /// An existing entry of the same kind under the same partition is
    /// silently overwritten.
    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        value: SecretValue,
    ) -> SecretStoreFuture<'_, ()>;

    /// Remove a secret for the given `(secret_id, channel_id)` pair.
    /// Idempotent: removing a non-existent entry is `Ok(())`.
    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, ()>;
}

/// Storage backend for paired channels.
///
/// Holds two kinds of record, keyed differently: [`HelperChannel`] by
/// `(secret_id, channel_id)` and [`ReplicaMember`] by
/// `(secret_id, replica_id)`. Because the keys differ, an implementation may
/// back each kind with its own table.
///
/// # Channel linking
///
/// The channel store also owns the **channel-link graph**: a record that two
/// channels belong to the same Owner identity (e.g. after a recovery
/// re-pairing). [`link_channel`](DeRecChannelStore::link_channel) records one
/// undirected, idempotent, transitive edge;
/// [`linked_channels`](DeRecChannelStore::linked_channels) returns a channel's
/// whole connected component. Linking moves no share data — it is pure
/// relationship metadata. Recovery/discovery resolves the linked set here, then
/// loads the corresponding shares via [`DeRecShareStore::load_many`].
///
/// # Executor independence
///
/// Same as [`DeRecSecretStore`]; methods return [`ChannelStoreFuture`].
pub trait DeRecChannelStore {
    /// Load the record addressed by `query`, or `Ok(None)` when none exists.
    ///
    /// The query is typed because the two kinds are keyed differently:
    /// [`HelperChannel`] by `(secret_id, channel_id)`, [`ReplicaMember`] by
    /// `(secret_id, replica_id)` — every member of a group shares one
    /// `channel_id`, so it cannot identify them.
    fn load(
        &self,
        secret_id: u64,
        query: ChannelQuery,
    ) -> ChannelStoreFuture<'_, Option<ChannelRecord>>;

    /// Persist a record, replacing any entry with the same key.
    fn save(&mut self, secret_id: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()>;

    /// Remove the record addressed by `query`.
    ///
    /// Removing one [`ChannelQuery::Replica`] removes **that member only** —
    /// the group channel and every other member survive.
    fn remove(&mut self, secret_id: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool>;

    /// Every helper channel stored under `secret_id`.
    fn helpers(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<HelperChannel>>;

    /// Every replica-group member, **including this device's own row**.
    /// Callers fanning out exclude themselves by [`crate::types::ReplicaId`].
    ///
    /// # Order selects the successor when the source leaves
    ///
    /// The returned order is otherwise insignificant, with one exception that
    /// makes it worth defining deliberately.
    ///
    /// A replica group has exactly one member holding
    /// [`crate::protocol::types::ReplicaRole::Source`]. When that member is
    /// removed, a successor must be chosen, and the protocol takes **the first
    /// element of this list that is neither the departing member nor itself
    /// leaving**. Implementing `replicas` is therefore how an application
    /// chooses its own succession policy — order by an `added_at` column, by a
    /// user-chosen preference, by whatever a backend says — without the
    /// protocol having to model one.
    ///
    /// The choice is read **once**, on the single device that runs the removal,
    /// and is then published in the roster as
    /// [`crate::protocol::types::ReplicaInfo::role`]. Every other member reads
    /// the result rather than repeating the decision, so implementations on
    /// different devices need not — and generally will not — agree on order.
    /// Nothing else in the protocol consults it.
    ///
    /// An implementation that returns an arbitrary order is **correct**; it
    /// simply delegates the choice to whatever its storage happens to yield.
    /// Note that this is the default for the usual backings: `HashMap`
    /// iteration is unspecified and varies between runs, and so is a SQL
    /// `SELECT` with no `ORDER BY`. Add an explicit ordering to make the
    /// succession predictable.
    ///
    /// A source that is the group's only member leaves no successor, and the
    /// group dissolves with it.
    fn replicas(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<ReplicaMember>>;

    /// Link two channels as belonging to the same Owner identity.
    ///
    /// # Scope: the owner ↔ helper pair only
    ///
    /// The graph exists for one situation. An owner that lost its state
    /// re-pairs with a helper on a *fresh* channel, and the helper must still
    /// find the shares it stored under the old one. Linking the two lets
    /// [`Self::linked_channels`] reach them.
    ///
    /// **The library never writes links.** It is the helper-side application
    /// that recognises a returning owner — an out-of-band judgement the
    /// protocol cannot make — and records the link. The library only reads
    /// the graph, in exactly two places, both helper-side responders:
    /// answering `GetSecretIdsVersions` and answering `GetShare`.
    ///
    /// **Replica groups do not use it.** Members share one `channel_id` and
    /// are identified by [`crate::types::ReplicaId`], so there is nothing to link: a member
    /// that changes channel during an admission handover keeps its row, and a
    /// catch-up resolves peers through the roster. The replica paths never
    /// consult this graph, and wiring them into it would conflate two
    /// unrelated notions of "the same peer".
    fn link_channel(
        &mut self,
        secret_id: u64,
        a: ChannelId,
        b: ChannelId,
    ) -> ChannelStoreFuture<'_, ()>;

    /// Every channel linked to `channel_id`, **including itself**.
    ///
    /// Read only on the helper side, to reach shares stored under a channel
    /// the owner has since replaced. See [`Self::link_channel`] for scope.
    fn linked_channels(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Vec<ChannelId>>;
}

/// Storage backend for secret shares.
///
/// Each entry is opaque protobuf bytes keyed by `(channel_id, secret_id, version)`.
/// The byte format depends on which side stored it; the store itself never
/// decodes:
///
/// - **Helper** stores the encoded [`derec_proto::StoreShareRequestMessage`]
///   received from the Owner. Recovery returns this whole message to the
///   library, and verification derives the share content from
///   `StoreShareRequestMessage.share`.
/// - **Owner** stores the encoded [`derec_proto::CommittedDeRecShare`] it
///   sent to each helper, so that the verification handler can replay the
///   commitment when validating each helper's response.
///
/// # Relation to channel linking
///
/// This store is a **pure keyed store** — it never sees the channel-link
/// graph. Linking lives in [`DeRecChannelStore`]. Callers that need shares
/// across linked channels resolve the channel set via
/// [`DeRecChannelStore::linked_channels`] first, then pass it to
/// [`load_many`](DeRecShareStore::load_many).
///
/// # Why `secret_id` is required on filtered loads
///
/// Versions are namespaced by `secret_id`: the same `version` number can
/// legitimately exist for two different secrets (e.g. a helper holds v1 from
/// owner A and v1 from owner B). A version-only query would conflate them, so
/// [`load`](DeRecShareStore::load) and
/// [`load_many`](DeRecShareStore::load_many) both require `secret_id`.
/// [`load_all`](DeRecShareStore::load_all) — the lone exception — exists
/// for **discovery**, which by definition enumerates what's stored before any
/// `secret_id` is known.
///
/// # Executor independence
///
/// Same as [`DeRecSecretStore`]; methods return [`ShareStoreFuture`].
pub trait DeRecShareStore {
    /// Load shares stored for `(secret_id, channel_id)`.
    ///
    /// - **Specific versions**: pass the versions you need in `versions`.
    ///   Missing versions are silently skipped.
    /// - **All versions**: pass an empty slice.
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>>;

    /// Load shares for several channels in one call, scoped to
    /// `secret_id`. Recovery uses this with the set returned by
    /// [`DeRecChannelStore::linked_channels`], so it is a single
    /// round-trip regardless of how many channels are linked.
    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>>;

    /// Load every share stored under `secret_id` across the given
    /// channels and every version. Used by Discovery to enumerate the
    /// helper's holdings for the active secret.
    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>>;

    /// Return the highest version number stored for `secret_id` across
    /// all channels, or `None` if no shares exist yet for this secret.
    fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>>;

    /// Persist a share for `(secret_id, channel_id)`.
    ///
    /// # Storage key
    ///
    /// `(secret_id, channel_id, share.version)`. Exactly one share
    /// exists per key — a version has exactly one writer.
    ///
    /// The protocol enforces that before calling here: a second write
    /// at an existing version carrying **different** content is refused
    /// with [`derec_proto::StatusEnum::VersionConflict`] and never
    /// reaches the store, while a byte-identical re-send is an
    /// idempotent retry. Implementations therefore overwrite on the
    /// three-tuple key and need no notion of who wrote a version.
    ///
    /// Helpers in particular hold no replica identity: `replica_id` is
    /// omitted from helper-bound requests entirely, so there is no
    /// writer to disambiguate. See
    /// `StoreShareRequestMessage.replicaId`.
    ///
    /// `share.secret_id` is denormalized metadata and must match the
    /// partition key `secret_id` — implementations may assert this.
    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        share: Share,
    ) -> ShareStoreFuture<'_, ()>;

    /// Drop every share stored under `(secret_id, channel_id)`. Used
    /// when an unpair flow tears down a channel. Idempotent.
    fn remove_channel(&mut self, secret_id: u64, channel_id: ChannelId)
    -> ShareStoreFuture<'_, ()>;
}

/// Storage for the user-facing secret contents, keyed by `secret_id`.
///
/// One `secret_id` maps to at most one [`UserSecrets`] entry — the most
/// recent snapshot the application handed off via
/// `start(FlowKind::ProtectSecret)`. The pair-completion auto-publish
/// hook reads from here so a freshly-paired Helper or Replica receives
/// the current secret without an explicit re-publish from the app.
///
/// # Executor independence
///
/// Methods return [`ShareStoreFuture`] — same `Send` rules as the other
/// store traits. The error type is reused from [`ShareStoreError`]
/// because the persistence concerns overlap (latest-version bookkeeping,
/// IO failures); no separate error category was warranted.
///
/// # Concurrency
///
/// The protocol holds the store by `&mut Self`, so implementations never
/// see overlapping calls and need no internal synchronization.
pub trait DeRecUserSecretStore {
    /// Return the latest [`UserSecrets`] entry for `secret_id`, or
    /// `Ok(None)` if the application has never published for this
    /// `secret_id` on this instance.
    fn load_latest(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<UserSecrets>>;

    /// Persist `value` as the latest entry for `secret_id`, overwriting
    /// any prior entry. The store keeps only the latest snapshot — older
    /// versions are recoverable via the helper share quorum if needed.
    fn save_latest(&mut self, secret_id: u64, value: UserSecrets) -> ShareStoreFuture<'_, ()>;

    /// Drop the entry for `secret_id`. Idempotent: removing a
    /// non-existent entry is `Ok(())`.
    fn remove(&mut self, secret_id: u64) -> ShareStoreFuture<'_, ()>;
}

/// Outbound transport abstraction.
///
/// The library calls `send` whenever it needs to deliver bytes to a peer.
/// The `endpoint` value comes from the `TransportProtocol` stored during
/// pairing.
///
/// # This is a mailbox, not a phone call
///
/// The protocol is peer-to-peer and symmetric: **every participant has an
/// address, and answering someone means posting to their address.** There is
/// no notion of "the connection this message arrived on". A reply produced
/// while handling an inbound message is not returned to the caller — it is
/// handed to `send`, addressed to the peer's endpoint, and
/// [`DeRecProtocol::process`](super::DeRecProtocol::process) returns only
/// [`DeRecEvent`](super::DeRecEvent)s describing what happened.
///
/// When both sides are reachable services this is all that is needed, and the
/// natural implementation is a one-way push — an HTTP `POST` to
/// `endpoint.uri`, a queue publish, an email. A reply simply arrives at the
/// peer later as a fresh inbound message.
///
/// # When the peer has no address
///
/// A phone, a browser tab, or anything behind NAT cannot be posted to. It
/// advertised *something* as its endpoint during pairing, but nothing can
/// reach it, so a push-style `send` drops the reply and the exchange stalls.
/// Nothing errors: `process` returned events, the handler looks successful,
/// and the peer simply never hears back.
///
/// Such a deployment has to answer on the connection the request came in on,
/// which means capturing what the protocol emits instead of sending it. Two
/// things make that work:
///
/// 1. **Build the protocol per request**, giving it a transport that collects
///    into a buffer. Per-request construction is what makes a collector safe:
///    the buffer belongs to one exchange and cannot mix with another's.
/// 2. **Match the reply by `trace_id`.** A single `process` call can emit
///    *several* messages — admitting a helper also republishes to every other
///    helper — and only one of them answers the caller holding the connection.
///    Responses echo the inbound envelope's `trace_id`, so
///    [`read_trace_id`](crate::derec_message::read_trace_id) separates the
///    reply from genuine fan-out. Returning the whole buffer, or blindly
///    returning its first entry, is the mistake this exists to prevent;
///    everything that is not the reply still has to reach its own endpoint.
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use derec_library::derec_message::{apply_trace_id, read_trace_id};
/// use derec_library::protocol::{DeRecTransport, TransportFuture};
/// use derec_proto::{DeRecMessage, Protocol, TransportProtocol};
/// use prost::Message as _;
///
/// /// A transport that keeps what the protocol emitted instead of sending it.
/// #[derive(Clone, Default)]
/// struct Collector(Arc<Mutex<Vec<(TransportProtocol, Vec<u8>)>>>);
///
/// impl Collector {
///     fn take(&self) -> Vec<(TransportProtocol, Vec<u8>)> {
///         std::mem::take(&mut *self.0.lock().expect("collector poisoned"))
///     }
/// }
///
/// impl DeRecTransport for Collector {
///     fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_> {
///         let entry = (endpoint.clone(), message);
///         let out = Arc::clone(&self.0);
///         Box::pin(async move {
///             out.lock().expect("collector poisoned").push(entry);
///             Ok(())
///         })
///     }
/// }
///
/// /// Split what one `process` call emitted into the answer for this caller
/// /// and everything still owed to somebody else.
/// fn split_reply(
///     inbound: &[u8],
///     emitted: Vec<(TransportProtocol, Vec<u8>)>,
/// ) -> (Option<Vec<u8>>, Vec<(TransportProtocol, Vec<u8>)>) {
///     // A zero trace_id means "no correlation requested", so it never
///     // identifies a reply.
///     let wanted = read_trace_id(inbound).unwrap_or(0);
///     let (mut reply, mut elsewhere) = (None, Vec::new());
///     for (endpoint, bytes) in emitted {
///         let echoes = wanted != 0
///             && read_trace_id(&bytes).map(|t| t == wanted).unwrap_or(false);
///         if echoes && reply.is_none() {
///             reply = Some(bytes);
///         } else {
///             elsewhere.push((endpoint, bytes));
///         }
///     }
///     (reply, elsewhere)
/// }
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let envelope = || DeRecMessage::default().encode_to_vec();
/// let peer = TransportProtocol {
///     uri: "https://peer.example".to_owned(),
///     protocol: Protocol::Https as i32,
/// };
///
/// let inbound = apply_trace_id(&envelope(), 0xA11CE)?;
///
/// // Stand in for one `process` call: the answer to this caller, plus an
/// // unrelated message fanned out to another peer.
/// let collector = Collector::default();
/// let rt = tokio::runtime::Builder::new_current_thread().build()?;
/// rt.block_on(async {
///     collector.send(&peer, apply_trace_id(&envelope(), 0xA11CE).unwrap()).await.unwrap();
///     collector.send(&peer, apply_trace_id(&envelope(), 0xB0B).unwrap()).await.unwrap();
/// });
///
/// let (reply, elsewhere) = split_reply(&inbound, collector.take());
/// assert!(reply.is_some(), "the echoed trace_id identifies the answer");
/// assert_eq!(elsewhere.len(), 1, "fan-out still has to be delivered");
/// # Ok(())
/// # }
/// ```
///
/// The application then returns `reply` as the HTTP response body and pushes
/// `elsewhere` however it normally would. See the "Serving DeRec over
/// request/response transports" section of the crate README for the full
/// handler.
///
/// Every SDK exposes the same correlation primitive: `Envelope.ReadTraceId`
/// (.NET), `envelope.ReadTraceID` (Go), `envelope_read_trace_id` (WASM /
/// TypeScript), `read_trace_id_from_envelope` (C FFI).
///
/// # Executor independence
///
/// Same as [`DeRecSecretStore`]; `send` returns [`TransportFuture`].
pub trait DeRecTransport {
    /// Deliver `message` to `endpoint`.
    ///
    /// `endpoint` is the [`TransportProtocol`] the peer advertised during
    /// pairing. The library calls this from protocol handlers whenever an
    /// outbound envelope needs to reach a peer.
    fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_>;
}

/// Durable storage for the orchestrator's in-flight protocol state.
///
/// The `DeRecProtocol` orchestrator produces short-lived state during
/// every flow — outstanding verification challenges, in-progress recovery
/// accumulators, and pending unpair acknowledgements. In long-running
/// processes this state can live in memory; in stateless deployments
/// (serverless functions, load-balanced services with instance churn)
/// the state must survive across process boundaries or replies will
/// arrive to a live channel with nothing to bind them to.
///
/// Every backend chooses its own persistence layer — in-memory `HashMap`
/// for local development and tests, SQLite for edge or single-process
/// deployments, Redis / Postgres / DynamoDB for load-balanced or
/// serverless deployments.
///
/// # Contract
///
/// - [`save`](DeRecStateStore::save) is a **full-replacement upsert**.
///   No per-item merge or append semantic. Accumulator-style state
///   ([`StateItem::PendingRecovery`] and [`StateItem::SharingRound`])
///   grows via load-modify-save from the library.
/// - [`load`](DeRecStateStore::load) is a **pure read**. No side effects.
///   Returns `Ok(None)` when the row does not exist.
/// - [`remove`](DeRecStateStore::remove) is idempotent: removing a
///   missing entry is `Ok(false)`, and returning `Ok(true)` iff a row
///   was actually removed.
/// - [`load_all`](DeRecStateStore::load_all) returns every item of the
///   given kind under this `secret_id`, in no guaranteed order.
///
/// # Concurrency
///
/// The library guarantees at-most-once processing of any given inbound
/// response only in **single-instance deployments**. In multi-instance /
/// load-balanced deployments where two instances may hold a
/// [`DeRecProtocol`](super::DeRecProtocol) against the same
/// `secret_id` at once:
///
/// - `load` + `remove` is not atomic across calls (two round-trips).
/// - Two instances processing the same inbound response can each `load`
///   the entry, each `remove` it, and each proceed with response
///   handling — producing **duplicate events** to the application.
/// - All library-emitted events (`ShareVerified`, `Unpaired`, etc.) are
///   idempotent from the application's perspective: on-wire state has
///   already settled, and a duplicate event does not corrupt anything.
/// - Concurrent inbound shares racing to modify a
///   [`StateItem::PendingRecovery`] accumulator, or concurrent inbound
///   store-share responses racing to update a
///   [`StateItem::SharingRound`] tally, can clobber each other via naive
///   load-modify-save. **The application layer is responsible for
///   serializing concurrent `process()` calls that touch the same
///   `(recovered secret_id, version)`** if this matters. Recoveries of
///   different secrets occupy separate rows and do not contend.
///
/// # Executor independence
///
/// Same as [`DeRecSecretStore`]; methods return [`StateStoreFuture`].
///
/// # Concurrency (single-instance)
///
/// The protocol holds the store by `&mut Self`, so a single-instance
/// implementation never sees overlapping calls and needs no internal
/// synchronization. Multi-instance backends must provide their own
/// consistency guarantees.
pub trait DeRecStateStore {
    /// Insert or full-replace by `(secret_id, item.key())`. Idempotent —
    /// if the row already exists, the existing entry is replaced in place
    /// with the caller-supplied `item`.
    fn save(&mut self, secret_id: u64, item: StateItem) -> StateStoreFuture<'_, ()>;

    /// Read the item at `(secret_id, key)`. Returns `Ok(None)` when no
    /// row exists. No side effects.
    fn load(&self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, Option<StateItem>>;

    /// Remove the item at `(secret_id, key)`. Returns `Ok(true)` iff a
    /// row was removed. Idempotent — removing a missing entry is
    /// `Ok(false)`, not an error.
    fn remove(&mut self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, bool>;

    /// Return every item of the given `kind` under this `secret_id`, in
    /// no guaranteed order.
    ///
    /// Used by the library to sweep timeouts (walk
    /// [`StateKind::PendingUnpair`], filter by
    /// [`StateItem::PendingUnpair::started_at`]) and for
    /// recovery-accumulator introspection. Data volume per kind is
    /// bounded by the number of channels or active reconstruction
    /// targets and is expected to be small.
    fn load_all(&self, secret_id: u64, kind: StateKind) -> StateStoreFuture<'_, Vec<StateItem>>;
}

impl<T: DeRecSecretStore + ?Sized> DeRecSecretStore for Box<T> {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        (**self).load(secret_id, channel_id, kind)
    }
    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        (**self).load_many(secret_id, channel_ids, kind, missing_policy)
    }
    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        value: SecretValue,
    ) -> SecretStoreFuture<'_, ()> {
        (**self).save(secret_id, channel_id, value)
    }
    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, ()> {
        (**self).remove(secret_id, channel_id, kind)
    }
}

impl<T: DeRecChannelStore + ?Sized> DeRecChannelStore for Box<T> {
    fn load(
        &self,
        secret_id: u64,
        query: ChannelQuery,
    ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
        (**self).load(secret_id, query)
    }
    fn save(&mut self, secret_id: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
        (**self).save(secret_id, record)
    }
    fn remove(&mut self, secret_id: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
        (**self).remove(secret_id, query)
    }
    fn helpers(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
        (**self).helpers(secret_id)
    }
    fn replicas(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
        (**self).replicas(secret_id)
    }
    fn link_channel(
        &mut self,
        secret_id: u64,
        a: ChannelId,
        b: ChannelId,
    ) -> ChannelStoreFuture<'_, ()> {
        (**self).link_channel(secret_id, a, b)
    }
    fn linked_channels(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        (**self).linked_channels(secret_id, channel_id)
    }
}

impl<T: DeRecShareStore + ?Sized> DeRecShareStore for Box<T> {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        (**self).load(secret_id, channel_id, versions)
    }
    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        (**self).load_many(secret_id, channel_ids, versions)
    }
    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        (**self).load_all(secret_id, channel_ids)
    }
    fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>> {
        (**self).latest_version(secret_id)
    }
    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        share: Share,
    ) -> ShareStoreFuture<'_, ()> {
        (**self).save(secret_id, channel_id, share)
    }
    fn remove_channel(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, ()> {
        (**self).remove_channel(secret_id, channel_id)
    }
}

impl<T: DeRecUserSecretStore + ?Sized> DeRecUserSecretStore for Box<T> {
    fn load_latest(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        (**self).load_latest(secret_id)
    }
    fn save_latest(&mut self, secret_id: u64, value: UserSecrets) -> ShareStoreFuture<'_, ()> {
        (**self).save_latest(secret_id, value)
    }
    fn remove(&mut self, secret_id: u64) -> ShareStoreFuture<'_, ()> {
        (**self).remove(secret_id)
    }
}

impl<T: DeRecStateStore + ?Sized> DeRecStateStore for Box<T> {
    fn save(&mut self, secret_id: u64, item: StateItem) -> StateStoreFuture<'_, ()> {
        (**self).save(secret_id, item)
    }
    fn load(&self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, Option<StateItem>> {
        (**self).load(secret_id, key)
    }
    fn remove(&mut self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, bool> {
        (**self).remove(secret_id, key)
    }
    fn load_all(&self, secret_id: u64, kind: StateKind) -> StateStoreFuture<'_, Vec<StateItem>> {
        (**self).load_all(secret_id, kind)
    }
}

impl<T: DeRecTransport + ?Sized> DeRecTransport for Box<T> {
    fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_> {
        (**self).send(endpoint, message)
    }
}

impl<T: DeRecSecretStore + ?Sized> DeRecSecretStore for &mut T {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        (**self).load(secret_id, channel_id, kind)
    }
    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        (**self).load_many(secret_id, channel_ids, kind, missing_policy)
    }
    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        value: SecretValue,
    ) -> SecretStoreFuture<'_, ()> {
        (**self).save(secret_id, channel_id, value)
    }
    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, ()> {
        (**self).remove(secret_id, channel_id, kind)
    }
}

impl<T: DeRecChannelStore + ?Sized> DeRecChannelStore for &mut T {
    fn load(
        &self,
        secret_id: u64,
        query: ChannelQuery,
    ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
        (**self).load(secret_id, query)
    }
    fn save(&mut self, secret_id: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
        (**self).save(secret_id, record)
    }
    fn remove(&mut self, secret_id: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
        (**self).remove(secret_id, query)
    }
    fn helpers(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
        (**self).helpers(secret_id)
    }
    fn replicas(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
        (**self).replicas(secret_id)
    }
    fn link_channel(
        &mut self,
        secret_id: u64,
        a: ChannelId,
        b: ChannelId,
    ) -> ChannelStoreFuture<'_, ()> {
        (**self).link_channel(secret_id, a, b)
    }
    fn linked_channels(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        (**self).linked_channels(secret_id, channel_id)
    }
}

impl<T: DeRecShareStore + ?Sized> DeRecShareStore for &mut T {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        (**self).load(secret_id, channel_id, versions)
    }
    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        (**self).load_many(secret_id, channel_ids, versions)
    }
    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        (**self).load_all(secret_id, channel_ids)
    }
    fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>> {
        (**self).latest_version(secret_id)
    }
    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        share: Share,
    ) -> ShareStoreFuture<'_, ()> {
        (**self).save(secret_id, channel_id, share)
    }
    fn remove_channel(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, ()> {
        (**self).remove_channel(secret_id, channel_id)
    }
}

impl<T: DeRecUserSecretStore + ?Sized> DeRecUserSecretStore for &mut T {
    fn load_latest(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        (**self).load_latest(secret_id)
    }
    fn save_latest(&mut self, secret_id: u64, value: UserSecrets) -> ShareStoreFuture<'_, ()> {
        (**self).save_latest(secret_id, value)
    }
    fn remove(&mut self, secret_id: u64) -> ShareStoreFuture<'_, ()> {
        (**self).remove(secret_id)
    }
}

impl<T: DeRecStateStore + ?Sized> DeRecStateStore for &mut T {
    fn save(&mut self, secret_id: u64, item: StateItem) -> StateStoreFuture<'_, ()> {
        (**self).save(secret_id, item)
    }
    fn load(&self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, Option<StateItem>> {
        (**self).load(secret_id, key)
    }
    fn remove(&mut self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, bool> {
        (**self).remove(secret_id, key)
    }
    fn load_all(&self, secret_id: u64, kind: StateKind) -> StateStoreFuture<'_, Vec<StateItem>> {
        (**self).load_all(secret_id, kind)
    }
}

impl<T: DeRecTransport + ?Sized> DeRecTransport for &mut T {
    fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_> {
        (**self).send(endpoint, message)
    }
}

/// A transport can be shared; a store cannot.
///
/// `Arc` never yields `&mut T`, and every store trait has at least one
/// `&mut self` method, so `Arc<dyn DeRecChannelStore>` and friends cannot
/// exist. [`DeRecTransport`] is the one trait whose methods are all `&self`,
/// which is also why it is the one worth sharing — a transport is typically a
/// pooled client held across requests.
///
/// Use [`Box<T>`](Box) or `&mut T` for the stores; both are implemented for
/// every trait here.
impl<T: DeRecTransport + ?Sized> DeRecTransport for std::sync::Arc<T> {
    fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_> {
        (**self).send(endpoint, message)
    }
}

#[cfg(test)]
mod pointer_forwarding_tests {
    use super::*;
    use crate::protocol::test::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::protocol::{DeRecProtocol, DeRecProtocolBuilder};

    const SECRET_ID: u64 = 0x0B0_9ED;

    /// A protocol whose backends are all type-erased. Naming this type at all
    /// is the point: without the blanket impls it does not satisfy the
    /// builder's bounds, and an application cannot choose a backend at run
    /// time without threading six type parameters everywhere.
    type ErasedProtocol = DeRecProtocol<
        Box<dyn DeRecChannelStore>,
        Box<dyn DeRecShareStore>,
        Box<dyn DeRecSecretStore>,
        Box<dyn DeRecUserSecretStore>,
        Box<dyn DeRecStateStore>,
        std::sync::Arc<NoopTransport>,
    >;

    fn build_erased() -> ErasedProtocol {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(Box::new(InMemChannelStore::default()) as Box<dyn DeRecChannelStore>)
            .with_share_store(Box::new(InMemShareStore::default()) as Box<dyn DeRecShareStore>)
            .with_secret_store(Box::new(InMemSecretStore::default()) as Box<dyn DeRecSecretStore>)
            .with_user_secret_store(
                Box::new(InMemUserSecretStore::default()) as Box<dyn DeRecUserSecretStore>
            )
            .with_state_store(
                Box::new(InMemPersistedStateStore::default()) as Box<dyn DeRecStateStore>
            )
            .with_transport(std::sync::Arc::new(NoopTransport))
            .with_own_transport("https://erased.example.com")
            .with_threshold(2)
            .build()
            .expect("a fully type-erased protocol must build")
    }

    /// The forwarding has to work through the pointer, not merely compile.
    /// A `&mut self` method reached through a `Box<dyn _>` is the case that
    /// would break if the impls forwarded to the wrong receiver.
    #[test]
    fn an_erased_protocol_reads_back_what_it_wrote() {
        run_async(async {
            let mut protocol = build_erased();

            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::PendingUnpair {
                        channel_id: ChannelId(4242),
                        started_at: 1_700_000_000,
                    },
                )
                .await
                .expect("save through Box<dyn DeRecStateStore>");

            let loaded = protocol
                .state_store
                .load(
                    SECRET_ID,
                    StateKey::PendingUnpair {
                        channel_id: ChannelId(4242),
                    },
                )
                .await
                .expect("load through Box<dyn DeRecStateStore>");
            assert!(
                loaded.is_some(),
                "the write must be visible through the box"
            );

            let removed = protocol
                .state_store
                .remove(
                    SECRET_ID,
                    StateKey::PendingUnpair {
                        channel_id: ChannelId(4242),
                    },
                )
                .await
                .expect("remove through Box<dyn DeRecStateStore>");
            assert!(removed, "remove reports it deleted the row");
        });
    }

    /// `tick` exercises several backends behind their boxes in one call, so a
    /// forwarding mistake in any of them surfaces here.
    #[test]
    fn an_erased_protocol_ticks() {
        run_async(async {
            let mut protocol = build_erased();
            let events = protocol.tick().await;
            assert!(events.is_empty(), "idle tick; got {events:?}");
        });
    }

    /// `&mut T` satisfies the bounds too, which is what lets a caller lend a
    /// store it still owns.
    #[test]
    fn a_borrowed_store_satisfies_the_bound() {
        fn assert_store<S: DeRecStateStore>() {}
        assert_store::<&mut InMemPersistedStateStore>();
        assert_store::<Box<InMemPersistedStateStore>>();
        assert_store::<Box<dyn DeRecStateStore>>();
    }

    /// A transport is the one thing worth sharing, and the only trait whose
    /// methods are all `&self` — so `Arc` works there and nowhere else.
    #[test]
    fn a_transport_can_be_shared_behind_an_arc() {
        fn assert_transport<T: DeRecTransport>() {}
        assert_transport::<std::sync::Arc<NoopTransport>>();
        assert_transport::<std::sync::Arc<dyn DeRecTransport>>();
        assert_transport::<Box<dyn DeRecTransport>>();
    }
}
