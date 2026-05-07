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
/// - **Owner** stores an empty (`vec![]`) tracking record so that
///   [`super::DeRecProtocol::verify_shares`] can enumerate which helpers hold shares for
///   a given `(secret_id, version)` via [`load_channels_for_secret`].
///
/// # Executor independence
///
/// Methods return [`ShareStoreFuture`] — no runtime is prescribed.
///
/// In the single-secret-bag model each channel holds shares for exactly one
/// secret, so `secret_id` is implicit and not part of the key.
pub trait DeRecShareStore {
    /// Load encoded `StoreShareRequestMessage` entries for a channel.
    ///
    /// - **Specific versions**: pass the versions you need in `versions`.
    ///   Missing versions are silently skipped (no error).
    /// - **All versions**: pass an empty slice to load every version stored
    ///   for `channel_id`.
    ///
    /// Returns `(version, encoded_bytes)` pairs.
    fn load(
        &self,
        channel_id: ChannelId,
        // TODO: add seccret id
        versions: &[i32],
    ) -> ShareStoreFuture<'_, Vec<(i32, Vec<u8>)>>;

    /// Return the highest version number stored across all channels,
    /// or `None` if no shares exist yet.
    fn latest_version(&self) -> ShareStoreFuture<'_, Option<i32>>;

    /// Persist the encoded `StoreShareRequestMessage` for `(channel_id, version)`.
    ///
    /// Replaces any previously stored entry for the same key.
    ///
    /// Owner-side callers may pass `vec![]` as `encoded` to record a tracking
    /// entry without storing full share bytes.
    fn save(
        &mut self,
        channel_id: ChannelId,
        // TODO: add secret id
        version: i32,
        encoded: Vec<u8>,
    ) -> ShareStoreFuture<'_, ()>;
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
