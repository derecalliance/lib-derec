// SPDX-License-Identifier: Apache-2.0

/// Errors produced by [`DeRecSecretStore`](super::DeRecSecretStore) implementations.
///
/// Individual Verifiable Secret Sharing shares are information-theoretically
/// secure, so "secret" here refers only to [`SharedKey`](crate::types::SharedKey) and
/// [`PairingSecretKeyMaterial`](derec_cryptography::pairing::PairingSecretKeyMaterial)
/// — the two kinds of data stored in this trait.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretStoreError {
    /// An I/O or serialization error in the underlying storage backend.
    ///
    /// Used when the implementation cannot categorise the failure more
    /// precisely (e.g., a file-system error, an SQLite constraint, or a
    /// serialization failure).
    ///
    /// The original error is preserved as the `source` so that callers can
    /// inspect the full error chain via [`std::error::Error::source`].
    #[error("secret store backend error")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Errors produced by [`DeRecChannelStore`](super::DeRecChannelStore) implementations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelStoreError {
    /// A channel with the given `channel_id` already exists.
    #[error("channel already exists for {channel_id}")]
    AlreadyExists { channel_id: u64 },

    /// No channel was found for the given `channel_id`.
    #[error("channel not found for {channel_id}")]
    NotFound { channel_id: u64 },

    /// An I/O or serialization error in the underlying storage backend.
    #[error("channel store backend error")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Errors produced by [`DeRecShareStore`](super::DeRecShareStore) implementations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ShareStoreError {
    /// A share for `(channel_id, version)` already exists.
    ///
    /// Returned by [`DeRecShareStore::save`](super::DeRecShareStore::save) when the
    /// implementation enforces immutability of versioned share slots.  The protocol treats each
    /// `(channel_id, version)` pair as write-once; overwriting a confirmed share
    /// is a protocol violation.
    #[error("share already exists for channel {channel_id} version {version}")]
    AlreadyExists { channel_id: u64, version: i32 },

    /// No share was found for `(channel_id, version)`.
    ///
    /// Implementations that prefer an explicit error over returning `Ok(None)`
    /// may return this variant from [`DeRecShareStore::load`](super::DeRecShareStore::load).
    #[error("share not found for channel {channel_id} version {version}")]
    NotFound { channel_id: u64, version: i32 },

    /// An I/O or serialization error in the underlying storage backend.
    ///
    /// The original error is preserved as the `source` so that callers can
    /// inspect the full error chain via [`std::error::Error::source`].
    #[error("share store backend error")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}
