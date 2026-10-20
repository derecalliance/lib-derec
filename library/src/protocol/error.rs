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
///
/// `events` holds what the call produced before it failed, such as sharing
/// round and unpair timeouts. Their state changes are already saved and are
/// not reported again, so handle them exactly as a successful call's events.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct ProcessError {
    /// The channel that produced the error, if the envelope was decodable.
    pub channel_id: Option<ChannelId>,
    /// The underlying error.
    #[source]
    pub source: crate::Error,
    /// Events produced before the failure.
    pub events: Vec<super::events::DeRecEvent>,
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

/// Reason an application's share store gives for refusing a write on a
/// helper channel, carried in [`ShareStoreError::Refused`].
///
/// The app picks the reason; the library alone decides the wire
/// [`derec_proto::StatusEnum`] and memo that reach the peer, so the app
/// cannot send an arbitrary status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The app's rate limit on share updates or verifications was hit.
    TooFrequent,
    /// The incoming share falls outside the helper's accepted size range.
    SizeLimitExceeded,
    /// The app declined the write for a reason outside the other variants.
    Rejected,
}

impl Refusal {
    /// The [`derec_proto::StatusEnum`] the helper answers the owner with.
    pub(crate) fn status(self) -> derec_proto::StatusEnum {
        match self {
            Self::TooFrequent => derec_proto::StatusEnum::TooFrequent,
            Self::SizeLimitExceeded => derec_proto::StatusEnum::SizeLimitExceeded,
            Self::Rejected => derec_proto::StatusEnum::Rejected,
        }
    }

    /// The memo the helper answers the owner with.
    pub(crate) fn memo(self) -> &'static str {
        match self {
            Self::TooFrequent => "refused by the helper: too frequent",
            Self::SizeLimitExceeded => "refused by the helper: size limit exceeded",
            Self::Rejected => "refused by the helper",
        }
    }
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

    /// The app's store refused the write on a helper channel.
    ///
    /// Returned from [`DeRecShareStore::save`](super::DeRecShareStore::save) or
    /// [`DeRecShareStore::record_verification`](super::DeRecShareStore::record_verification)
    /// to refuse a share update or verification on a helper channel
    /// (`peer_role == Owner`); the library answers the owner with the status
    /// and memo it maps the carried variant to. Returned anywhere else — a replica destination's mirror
    /// `save`, for instance — it is an ordinary store failure.
    #[error("share store refused the write: {0:?}")]
    Refused(Refusal),
}

/// Map an internal failure to the closest [`derec_proto::StatusEnum`] a peer
/// can act on.
///
/// Deliberately coarse: a peer can only decide whether to retry, correct its
/// request, or give up, and the memo carries the detail. `FAIL` is the honest
/// answer for anything that does not map cleanly, rather than inventing a
/// more specific-sounding status than the error actually supports.
///
/// Takes the error by reference because the caller still owns it — the status
/// goes out to the peer while the original error is returned to the
/// application unchanged.
impl From<&crate::Error> for derec_proto::StatusEnum {
    fn from(error: &crate::Error) -> Self {
        match error {
            crate::Error::ProtobufDecode(_) => Self::FormatError,
            crate::Error::RoleMismatch { .. } => Self::Rejected,
            crate::Error::NoUsableEndpoint { .. } => Self::UnsupportedTransportProtocol,
            _ => Self::Fail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_maps_to_status_and_memo() {
        assert_eq!(
            Refusal::TooFrequent.status(),
            derec_proto::StatusEnum::TooFrequent
        );
        assert_eq!(
            Refusal::TooFrequent.memo(),
            "refused by the helper: too frequent"
        );

        assert_eq!(
            Refusal::SizeLimitExceeded.status(),
            derec_proto::StatusEnum::SizeLimitExceeded
        );
        assert_eq!(
            Refusal::SizeLimitExceeded.memo(),
            "refused by the helper: size limit exceeded"
        );

        assert_eq!(
            Refusal::Rejected.status(),
            derec_proto::StatusEnum::Rejected
        );
        assert_eq!(Refusal::Rejected.memo(), "refused by the helper");
    }
}
