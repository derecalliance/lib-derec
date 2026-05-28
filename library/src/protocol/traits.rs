// SPDX-License-Identifier: Apache-2.0

use super::error::{ChannelStoreError, SecretStoreError, ShareStoreError};
use crate::Result;
use crate::types::{Channel, ChannelId};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{ContactMessage, TransportProtocol};
use std::{future::Future, pin::Pin};

// When building for WASM or FFI targets, futures are `!Send` because the
// host environment is single-threaded or callbacks cross an FFI boundary.
// Pure-Rust consumers get `Send` futures so they can use `tokio::spawn` directly.

#[cfg(any(feature = "ffi", target_arch = "wasm32"))]
pub type SecretStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, SecretStoreError>> + 'a>>;
#[cfg(not(any(feature = "ffi", target_arch = "wasm32")))]
pub type SecretStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, SecretStoreError>> + Send + 'a>>;

#[cfg(any(feature = "ffi", target_arch = "wasm32"))]
pub type ChannelStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ChannelStoreError>> + 'a>>;
#[cfg(not(any(feature = "ffi", target_arch = "wasm32")))]
pub type ChannelStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ChannelStoreError>> + Send + 'a>>;

#[cfg(any(feature = "ffi", target_arch = "wasm32"))]
pub type ShareStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ShareStoreError>> + 'a>>;
#[cfg(not(any(feature = "ffi", target_arch = "wasm32")))]
pub type ShareStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ShareStoreError>> + Send + 'a>>;

#[cfg(any(feature = "ffi", target_arch = "wasm32"))]
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + 'a>>;
#[cfg(not(any(feature = "ffi", target_arch = "wasm32")))]
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// The post-pairing symmetric channel key (`SharedKey`).
    SharedKey = 0,
    /// The ephemeral ECIES / ML-KEM key material used during pairing.
    PairingSecret = 1,
    /// The initiator's [`ContactMessage`] stored transiently between
    /// `start` and pairing completion. Removed once the shared key
    /// is derived.
    PairingContact = 2,
}

/// How [`DeRecSecretStore::load_many`] handles channels with no stored secret
/// of the requested [`SecretKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingPolicy {
    /// Silently drop missing channels from the returned vector.
    ///
    /// Use when missing entries are an expected outcome — e.g. a `Target::Many`
    /// list that mixes paired and unpaired channels.
    Skip,
    /// Return [`SecretStoreError::MissingEntries`] carrying the channel ids
    /// that had no entry.
    ///
    /// Use when every input id is expected to have an entry — e.g. after
    /// filtering to channels already known to [`DeRecChannelStore`]. A miss
    /// signals a cross-store invariant violation.
    Fail,
}

pub enum SecretValue {
    SharedKey(crate::types::SharedKey),
    PairingSecret(PairingSecretKeyMaterial),
    /// The initiator's [`ContactMessage`], needed by `pairing_response::process`
    /// to derive the shared key. Ephemeral — removed after pairing completes.
    PairingContact(ContactMessage),
}

/// Keychain-grade storage for cryptographic secrets.
///
/// Only two kinds of material ever need special protection:
///
/// - [`SecretKind::SharedKey`] — the symmetric key that authenticates and
///   encrypts all post-pairing messages for a channel.
/// - [`SecretKind::PairingSecret`] — the ephemeral ECIES / ML-KEM key pair
///   that is alive only between a pairing request and its response.
///
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
/// that any executor can poll.  Sync implementations return
/// `Box::pin(std::future::ready(...))` at zero cost; async implementations
/// return `Box::pin(async move { ... })`.  No runtime is prescribed.
pub trait DeRecSecretStore {
    /// Load a secret for the given channel.
    ///
    /// Returns `Ok(None)` when no secret of the requested [`SecretKind`] exists
    /// for `channel_id`.  The returned [`SecretValue`] variant will always match
    /// the requested `kind`.
    fn load(
        &self,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>>;

    /// Load secrets of the same [`SecretKind`] for several channels in one call.
    ///
    /// Used by the [`crate::protocol`] orchestrator when broadcasting a request
    /// (discovery, recovery, verification, sharing, unpairing) to keep the
    /// per-broadcast roundtrip count constant instead of linear in the number
    /// of paired channels.
    ///
    /// Returns one `(ChannelId, SecretValue)` per channel that has a stored
    /// secret of the requested kind. `missing_policy` controls how channels
    /// with no stored entry are handled (see [`MissingPolicy`]). Order of the
    /// returned tuples is unspecified.
    fn load_many(
        &self,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>>;

    /// Persist a secret for the given channel.
    ///
    /// The [`SecretKind`] is derived from the [`SecretValue`] variant, so
    /// callers do not need to pass it explicitly.  An existing entry of the
    /// same kind is silently overwritten.
    fn save(&mut self, channel_id: ChannelId, value: SecretValue) -> SecretStoreFuture<'_, ()>;

    /// Remove a secret for the given channel.
    ///
    /// Idempotent: removing a non-existent entry is `Ok(())`.
    fn remove(&mut self, channel_id: ChannelId, kind: SecretKind) -> SecretStoreFuture<'_, ()>;
}

/// Storage backend for paired channels.
///
/// A [`Channel`] is the post-pairing representation of a peer relationship,
/// retaining only the fields needed for ongoing protocol operations (channel
/// ID, transport uri, and name). The full [`ContactMessage`] — which
/// carries ephemeral cryptographic material — is discarded after pairing.
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
/// loads the corresponding shares via
/// [`DeRecShareStore::load_many`](DeRecShareStore::load_many).
///
/// # Executor independence
///
/// Same as [`DeRecSecretStore`] — methods return [`ChannelStoreFuture`], a
/// type-erased future with no runtime dependency.
pub trait DeRecChannelStore {
    /// Load the [`Channel`] for the given channel ID.
    ///
    /// Returns `Ok(None)` when no channel has been stored for `channel_id`.
    fn load(&self, channel_id: ChannelId) -> ChannelStoreFuture<'_, Option<Channel>>;

    /// Persist a [`Channel`].
    ///
    /// The channel ID is taken from [`Channel::id`]. Replaces any previously
    /// stored channel for the same ID.
    fn save(&mut self, channel: Channel) -> ChannelStoreFuture<'_, ()>;

    /// Remove the channel for the given ID.
    ///
    /// Returns `true` if a channel was removed, `false` if no channel existed.
    fn remove(&mut self, channel_id: ChannelId) -> ChannelStoreFuture<'_, bool>;

    /// Return all stored channels.
    ///
    /// Used by the protocol to enumerate all paired peers when building the
    /// secret bag (to populate `HelperInfo` entries) and when fanning out
    /// recovery requests.
    fn channels(&self) -> ChannelStoreFuture<'_, Vec<Channel>>;

    /// Link two channels as belonging to the same Owner identity.
    ///
    /// The relation is **undirected, idempotent, and transitive** (an
    /// equivalence relation): the order of `a`/`b` is irrelevant, re-linking an
    /// existing pair (or linking a channel to itself) is a no-op, and if
    /// `A↔B` and `B↔C` then all three are in one group. Linking moves no share
    /// data — it only records the relationship.
    fn link_channel(&mut self, a: ChannelId, b: ChannelId) -> ChannelStoreFuture<'_, ()>;

    /// Return the full set of channels linked to `channel_id`, **including
    /// `channel_id` itself** (its transitive-closure / connected component).
    ///
    /// An unlinked channel returns `[channel_id]`. Order is unspecified. The
    /// returned IDs are typically fed to
    /// [`DeRecShareStore::load_many`](DeRecShareStore::load_many) (for a
    /// specific `secret_id`) or
    /// [`DeRecShareStore::load_all`](DeRecShareStore::load_all) (discovery) to
    /// aggregate shares across re-pairings without duplicating data.
    fn linked_channels(
        &self,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Vec<ChannelId>>;
}

/// A single stored share entry, fully self-describing.
///
/// - `secret_id` — numeric identifier of the secret this share belongs to.
/// - `version`   — version number of the secret.
/// - `bytes`     — raw encoded [`derec_proto::StoreShareRequestMessage`] bytes.
#[derive(Debug, Clone)]
pub struct Share {
    pub secret_id: u64,
    pub version: u32,
    pub bytes: Vec<u8>,
}

/// Storage backend for secret shares.
///
/// Stores raw encoded [`derec_proto::StoreShareRequestMessage`] protobuf bytes keyed by
/// `(channel_id, secret_id, version)`. The full request is stored rather than just the
/// share field because:
///
/// - **recovery** needs to return the whole `StoreShareRequestMessage` to the library
/// - **verification** derives the share content from `StoreShareRequestMessage.share`
///
/// Used by both sides:
///
/// - **Helper** stores the full encoded request received from the Owner.
/// - **Owner** stores an empty `bytes` field to record a tracking entry so that
///   [`super::DeRecProtocol::verify_shares`] can enumerate which helpers hold shares.
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
/// Methods return [`ShareStoreFuture`] — no runtime is prescribed.
pub trait DeRecShareStore {
    /// Load shares stored for a single channel, scoped to one secret.
    ///
    /// - **Specific versions**: pass the versions you need in `versions`.
    ///   Missing versions are silently skipped.
    /// - **All versions of `secret_id`**: pass an empty slice.
    fn load(
        &self,
        channel_id: ChannelId,
        secret_id: u64,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>>;

    /// Load shares for several channels in one call, scoped to one secret.
    ///
    /// Recovery uses this with the set returned by
    /// [`DeRecChannelStore::linked_channels`], so it is a single round-trip
    /// regardless of how many channels are linked.
    ///
    /// Returns a **flat** list — deduplication (e.g. by `version`) is the
    /// caller's concern. The `versions` filter has the same semantics as
    /// [`load`](Self::load) and applies uniformly across all `channel_ids`.
    fn load_many(
        &self,
        channel_ids: &[ChannelId],
        secret_id: u64,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>>;

    /// Load **every** share stored for the given channels, across all secrets
    /// and all versions.
    ///
    /// This is the only legitimate "no `secret_id`" load — and exists solely
    /// for **discovery**, which by definition enumerates the helper's holdings
    /// before any secret is known. Domain callers (recovery, verification)
    /// must use [`load`](Self::load) or [`load_many`](Self::load_many).
    fn load_all(
        &self,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>>;

    /// Return the highest version number stored across all channels,
    /// or `None` if no shares exist yet.
    fn latest_version(&self) -> ShareStoreFuture<'_, Option<u32>>;

    /// Persist a share for the given channel.
    ///
    /// Replaces any previously stored entry for the same
    /// `(channel_id, secret_id, version)` key.
    fn save(&mut self, channel_id: ChannelId, share: Share) -> ShareStoreFuture<'_, ()>;

    /// Drop **all** shares stored under `channel_id`.
    ///
    /// Used by the [`crate::protocol`] orchestrator when an unpair flow tears
    /// down a channel — every secret-id / version combination held for that
    /// channel is removed. Implementations should treat a non-existent channel
    /// as a no-op (idempotent).
    fn remove_channel(&mut self, channel_id: ChannelId) -> ShareStoreFuture<'_, ()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Transport
// ─────────────────────────────────────────────────────────────────────────────

/// Outbound transport abstraction.
///
/// The library calls `send` whenever it needs to deliver bytes to a peer.
/// The `endpoint` value comes from the `TransportProtocol` stored during pairing.
///
/// # Executor independence
///
/// `send` returns [`TransportFuture`] — a type-erased future.  A blocking HTTP
/// client wraps its call in `Box::pin(std::future::ready(...))`.  An async
/// client returns `Box::pin(async move { ... })`.  No executor is assumed.
pub trait DeRecTransport {
    fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_>;
}
