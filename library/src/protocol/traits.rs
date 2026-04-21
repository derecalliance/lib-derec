// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, pin::Pin};

use crate::types::ChannelId;
use crate::Result;
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{ContactMessage, TransportProtocol};

use super::error::{ContactStoreError, SecretStoreError, ShareStoreError};

// ── Future type aliases ───────────────────────────────────────────────────────
//
// Each alias is scoped to its own error type and carries a lifetime so the
// returned future may borrow from `&self` / `&mut self`.  No executor, runtime,
// or async-framework dependency is introduced: any code that can poll a
// `std::future::Future` can drive these, including a bare `block_on` loop.

/// Boxed future returned by [`DeRecSecretStore`] methods.
pub type SecretStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, SecretStoreError>> + 'a>>;

/// Boxed future returned by [`DeRecContactStore`] methods.
pub type ContactStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ContactStoreError>> + 'a>>;

/// Boxed future returned by [`DeRecShareStore`] methods.
pub type ShareStoreFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, ShareStoreError>> + 'a>>;

/// Boxed future returned by [`DeRecTransport::send`].
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + 'a>>;

// ─────────────────────────────────────────────────────────────────────────────
// Secret store
// ─────────────────────────────────────────────────────────────────────────────

/// Discriminator for the type of secret to load, save, or remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// The post-pairing symmetric channel key (`SharedKey`).
    SharedKey = 0,
    /// The ephemeral ECIES / ML-KEM key material used during pairing.
    PairingSecret = 1,
}

/// Typed container for a secret value, matching [`SecretKind`].
pub enum SecretValue {
    SharedKey(crate::types::SharedKey),
    PairingSecret(PairingSecretKeyMaterial),
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
    fn load(&self, channel_id: ChannelId, kind: SecretKind) -> SecretStoreFuture<'_, Option<SecretValue>>;

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

// ─────────────────────────────────────────────────────────────────────────────
// Contact store
// ─────────────────────────────────────────────────────────────────────────────

/// Storage backend for peer contacts.
///
/// All methods are `async` so implementations may perform I/O (disk, network)
/// without blocking the executor.
///
/// # Implementor notes
///
/// - [`load`](DeRecContactStore::load) returns `Ok(None)` when no contact exists for the channel.
/// - [`save`](DeRecContactStore::save) silently replaces any previously stored contact.
///
/// # Executor independence
///
/// Same as [`DeRecSecretStore`] — methods return [`ContactStoreFuture`], a
/// type-erased future with no runtime dependency.
pub trait DeRecContactStore {
    /// Load the peer's [`ContactMessage`] for the given channel.
    ///
    /// Returns `Ok(None)` when no contact has been stored for `channel_id`.
    fn load(&self, channel_id: ChannelId) -> ContactStoreFuture<'_, Option<ContactMessage>>;

    /// Persist the peer's [`ContactMessage`] for the given channel.
    ///
    /// Replaces any previously stored contact for the same `channel_id`.
    fn save(&mut self, channel_id: ChannelId, contact: ContactMessage) -> ContactStoreFuture<'_, ()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Share store
// ─────────────────────────────────────────────────────────────────────────────

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
/// - **Owner** stores an empty (`vec![]`) tracking record so that
///   [`super::DeRecProtocol::verify_shares`] can enumerate which helpers hold shares for
///   a given `(secret_id, version)` via [`load_channels_for_secret`].
///
/// # Executor independence
///
/// Methods return [`ShareStoreFuture`] — no runtime is prescribed.
pub trait DeRecShareStore {
    /// Load the encoded `StoreShareRequestMessage` for `(channel_id, secret_id, version)`.
    ///
    /// Returns `Ok(None)` when no share has been stored for that key.
    fn load(
        &self,
        channel_id: ChannelId,
        secret_id: &[u8],
        version: i32,
    ) -> ShareStoreFuture<'_, Option<Vec<u8>>>;

    /// Persist the encoded `StoreShareRequestMessage` for `(channel_id, secret_id, version)`.
    ///
    /// Replaces any previously stored entry for the same key.
    ///
    /// Owner-side callers may pass `vec![]` as `encoded` to record a tracking
    /// entry without storing full share bytes.
    fn save(
        &mut self,
        channel_id: ChannelId,
        secret_id: &[u8],
        version: i32,
        encoded: Vec<u8>,
    ) -> ShareStoreFuture<'_, ()>;

    /// Return all channel IDs that have a stored entry for `(secret_id, version)`.
    ///
    /// Used by the Owner side to fan-out verification challenges to only the helpers
    /// that participated in protecting a specific secret.
    fn load_channels_for_secret(
        &self,
        secret_id: &[u8],
        version: i32,
    ) -> ShareStoreFuture<'_, Vec<ChannelId>>;

    /// Return all secrets and their stored versions for the given channel.
    ///
    /// Each entry is `(secret_id, versions)` where `versions` lists every share
    /// version the Helper currently holds for that secret under this channel.
    ///
    /// Used by the Helper side to answer a
    /// [`GetSecretIdsVersionsRequestMessage`](derec_proto::GetSecretIdsVersionsRequestMessage)
    /// during the discovery flow: the Helper enumerates what it stores for the
    /// requesting Owner's recovery channel and returns the list.
    ///
    /// Returns `Ok(vec![])` when no shares are stored for `channel_id`.
    fn load_secrets_for_channel(
        &self,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, Vec<(Vec<u8>, Vec<i32>)>>;
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
