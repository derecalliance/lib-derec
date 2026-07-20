// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::SecretKind;
use crate::types::ChannelId;

/// Error returned by [`DeRecProtocol::process`](super::DeRecProtocol::process).
///
/// Wraps the underlying [`crate::Error`] with the `channel_id` extracted from
/// the inbound message envelope, so consumers always know which channel
/// produced the error.
///
/// `channel_id` is `None` only when the envelope itself could not be decoded
/// (i.e. the raw bytes are not a valid protobuf `DeRecMessage`).
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct ProcessError {
    /// The channel that produced the error, if the envelope was decodable.
    pub channel_id: Option<ChannelId>,
    /// The underlying error.
    #[source]
    pub source: crate::Error,
}

impl ProcessError {
    /// Convenience: extract `(status, memo)` if the underlying error is a
    /// `NonOkStatus` from any primitive.
    pub fn as_non_ok_status(&self) -> Option<(i32, &str)> {
        self.source.as_non_ok_status()
    }
}

/// Errors produced by [`DeRecSecretStore`](super::DeRecSecretStore) implementations.
///
/// Individual Verifiable Secret Sharing shares are information-theoretically
/// secure, so "secret" here refers only to [`SharedKey`](crate::types::SharedKey) and
/// [`PairingKeyMaterial`](super::PairingKeyMaterial)
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

    /// Returned by [`super::DeRecSecretStore::load_many`] when one or more
    /// requested channels have no stored secret of the requested
    /// [`SecretKind`] and the caller requested
    /// [`super::MissingPolicy::Fail`].
    ///
    /// `channel_ids` carries the raw u64 ids of channels that came back empty;
    /// the protocol orchestrator logs them at `error!` level and surfaces
    /// the same list to consumers.
    #[error("secret store: missing {kind:?} entries for channel(s): {channel_ids:?}")]
    MissingEntries {
        kind: SecretKind,
        channel_ids: Vec<u64>,
    },
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

/// Errors produced by [`DeRecStateStore`](super::DeRecStateStore) implementations.
///
/// The state store holds in-flight orchestrator state (outstanding
/// verification challenges, in-progress recovery accumulators, pending unpair
/// acknowledgements) so that stateless or load-balanced deployments do not
/// lose it across process restarts.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StateStoreError {
    /// An I/O or serialization error in the underlying storage backend.
    ///
    /// The original error is preserved as the `source` so that callers can
    /// inspect the full error chain via [`std::error::Error::source`].
    #[error("state store backend error")]
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
    AlreadyExists { channel_id: u64, version: u32 },

    /// No share was found for `(channel_id, version)`.
    ///
    /// Implementations that prefer an explicit error over returning `Ok(None)`
    /// may return this variant from [`DeRecShareStore::load`](super::DeRecShareStore::load).
    #[error("share not found for channel {channel_id} version {version}")]
    NotFound { channel_id: u64, version: u32 },

    /// An I/O or serialization error in the underlying storage backend.
    ///
    /// The original error is preserved as the `source` so that callers can
    /// inspect the full error chain via [`std::error::Error::source`].
    #[error("share store backend error")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}
