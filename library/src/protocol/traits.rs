// SPDX-License-Identifier: Apache-2.0

use super::error::{ChannelStoreError, SecretStoreError, ShareStoreError};
use crate::Result;
use crate::protocol::types::{
    Channel, MissingPolicy, SecretKind, SecretValue, Share, UserSecrets,
};
use crate::types::ChannelId;
use derec_proto::TransportProtocol;
use std::{future::Future, pin::Pin};

/// Type-erased future returned by [`DeRecSecretStore`] methods.
///
/// `Send` on native targets so multi-threaded executors (e.g. `tokio::spawn`)
/// can take it; under the `ffi` feature or `wasm32` the `Send` bound is
/// dropped because callbacks cross an FFI boundary or run in a
/// single-threaded host. Sync backends can return
/// `Box::pin(std::future::ready(...))` at zero cost.
#[cfg(any(feature = "ffi", target_arch = "wasm32"))]
pub type SecretStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, SecretStoreError>> + 'a>>;
/// Type-erased future returned by [`DeRecSecretStore`] methods.
///
/// `Send` on native targets so multi-threaded executors (e.g. `tokio::spawn`)
/// can take it; under the `ffi` feature or `wasm32` the `Send` bound is
/// dropped because callbacks cross an FFI boundary or run in a
/// single-threaded host. Sync backends can return
/// `Box::pin(std::future::ready(...))` at zero cost.
#[cfg(not(any(feature = "ffi", target_arch = "wasm32")))]
pub type SecretStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, SecretStoreError>> + Send + 'a>>;

/// Type-erased future returned by [`DeRecChannelStore`] methods. See
/// [`SecretStoreFuture`] for the `Send`/non-`Send` rules.
#[cfg(any(feature = "ffi", target_arch = "wasm32"))]
pub type ChannelStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ChannelStoreError>> + 'a>>;
/// Type-erased future returned by [`DeRecChannelStore`] methods. See
/// [`SecretStoreFuture`] for the `Send`/non-`Send` rules.
#[cfg(not(any(feature = "ffi", target_arch = "wasm32")))]
pub type ChannelStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ChannelStoreError>> + Send + 'a>>;

/// Type-erased future returned by [`DeRecShareStore`] methods. See
/// [`SecretStoreFuture`] for the `Send`/non-`Send` rules.
#[cfg(any(feature = "ffi", target_arch = "wasm32"))]
pub type ShareStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ShareStoreError>> + 'a>>;
/// Type-erased future returned by [`DeRecShareStore`] methods. See
/// [`SecretStoreFuture`] for the `Send`/non-`Send` rules.
#[cfg(not(any(feature = "ffi", target_arch = "wasm32")))]
pub type ShareStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ShareStoreError>> + Send + 'a>>;

/// Type-erased future returned by [`DeRecTransport::send`]. See
/// [`SecretStoreFuture`] for the `Send`/non-`Send` rules.
#[cfg(any(feature = "ffi", target_arch = "wasm32"))]
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + 'a>>;
/// Type-erased future returned by [`DeRecTransport::send`]. See
/// [`SecretStoreFuture`] for the `Send`/non-`Send` rules.
#[cfg(not(any(feature = "ffi", target_arch = "wasm32")))]
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

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
    /// vaults on the same device (Owner of N vaults, or Helper for N
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
/// A [`Channel`] is the post-pairing representation of a peer relationship,
/// retaining only the fields needed for ongoing protocol operations — see
/// [`Channel`] for the per-field documentation. The full
/// [`derec_proto::ContactMessage`] — which carries ephemeral cryptographic
/// material — is discarded after pairing.
///
/// # Implementor notes
///
/// - [`load`](DeRecChannelStore::load) returns `Ok(None)` when no channel
///   exists for the given ID.
/// - [`save`](DeRecChannelStore::save) silently replaces any previously stored
///   channel with the same ID.
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
    /// Load the [`Channel`] for `(secret_id, channel_id)`.
    ///
    /// `secret_id` partitions storage so one backend can serve many
    /// vaults on the same device. Returns `Ok(None)` when no channel
    /// exists for this partition key.
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Option<Channel>>;

    /// Persist a [`Channel`] under `secret_id`. The channel ID is taken
    /// from [`Channel::id`]. Replaces any previously stored channel for
    /// the same `(secret_id, channel_id)`.
    fn save(&mut self, secret_id: u64, channel: Channel) -> ChannelStoreFuture<'_, ()>;

    /// Remove the channel for `(secret_id, channel_id)`. Returns `true`
    /// when an entry was removed, `false` when none existed.
    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, bool>;

    /// Return every channel stored under `secret_id`. Used by the
    /// protocol to enumerate paired peers when building the secret bag
    /// and when fanning out broadcast flows.
    fn channels(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<Channel>>;

    /// Link two channels under `secret_id` as belonging to the same
    /// Owner identity. The relation is **undirected, idempotent, and
    /// transitive** within the partition.
    fn link_channel(
        &mut self,
        secret_id: u64,
        a: ChannelId,
        b: ChannelId,
    ) -> ChannelStoreFuture<'_, ()>;

    /// Return the full set of channels linked to `channel_id` under
    /// `secret_id`, **including `channel_id` itself**. An unlinked
    /// channel returns `[channel_id]`.
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
    /// helper's holdings for the active vault.
    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>>;

    /// Return the highest version number stored for `secret_id` across
    /// all channels, or `None` if no shares exist yet for this vault.
    fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>>;

    /// Persist a share for `(secret_id, channel_id)`.
    ///
    /// # Conceptual storage key
    ///
    /// The protocol considers the full storage key to be
    /// `(secret_id, channel_id, share.version, share.replica_id)`.
    /// Replica destinations reuse the source's channel shared key with
    /// helpers (the key travels in the `ReplicaSecretPayload` vault), so
    /// two replicas writing the same `(secret_id, channel_id, version)`
    /// look cryptographically identical at the wire layer — only
    /// `share.replica_id` separates them. A naive helper that ignored
    /// `replica_id` and overwrote on the three-tuple key would silently
    /// lose one of the two writes.
    ///
    /// # Implementation freedom
    ///
    /// The trait does not dictate how implementations represent the
    /// `replica_id` discriminator (separate column, composite primary
    /// key, write-time conflict log, etc.). The contract is:
    ///
    /// - Writes from distinct `replica_id`s for the same
    ///   `(secret_id, channel_id, version)` MUST both survive — neither
    ///   may silently overwrite the other.
    /// - A write that matches an existing entry on all four fields
    ///   replaces it (idempotent re-send).
    /// - `load`, `load_many`, and `load_all` return every distinct
    ///   `(version, replica_id)` entry matching the requested filter;
    ///   the application performs any per-application coalescing.
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
    fn remove_channel(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, ()>;
}

/// Storage for the user-facing vault contents, keyed by `secret_id`.
///
/// One `secret_id` maps to at most one [`UserSecrets`] entry — the most
/// recent snapshot the application handed off via
/// `start(FlowKind::ProtectSecret)`. The pair-completion auto-publish
/// hook reads from here so a freshly-paired Helper or Replica receives
/// the current vault without an explicit re-publish from the app.
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
    fn save_latest(
        &mut self,
        secret_id: u64,
        value: UserSecrets,
    ) -> ShareStoreFuture<'_, ()>;

    /// Drop the entry for `secret_id`. Idempotent: removing a
    /// non-existent entry is `Ok(())`.
    fn remove(&mut self, secret_id: u64) -> ShareStoreFuture<'_, ()>;
}

/// Outbound transport abstraction.
///
/// The library calls `send` whenever it needs to deliver bytes to a peer.
/// The `endpoint` value comes from the `TransportProtocol` stored during pairing.
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
