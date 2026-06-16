// SPDX-License-Identifier: Apache-2.0

//! # Error Types
//!
//! This module defines the top-level error type returned by the public APIs
//! of the library.
//!
//! ## Error model
//!
//! The crate exposes a unified [`Error`] type that wraps the error types
//! produced by each protocol flow:
//!
//! - pairing
//! - sharing
//! - verification
//! - recovery
//! - discovery
//!
//! Each flow defines its own specialized error type, which is converted into
//! [`Error`] using `From` conversions. This allows public functions to return
//! `Result<T, crate::Error>` while still preserving the precise cause of the
//! failure.
//!
//! Applications consuming this library may pattern match on the [`Error`]
//! variants to determine which protocol phase produced the error.
//!
//! ## Non-exhaustive
//!
//! The [`Error`] enum is marked `#[non_exhaustive]`, meaning additional variants
//! may be introduced in future versions without breaking API compatibility.
//! Consumers should include a fallback match arm when matching on this type.
//!
//! ## Internal invariants
//!
//! Some variants represent violations of internal invariants. These indicate
//! logic errors or unexpected states and should normally not occur in correct
//! usage of the library.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Pairing(#[from] crate::primitives::pairing::PairingError),

    #[error(transparent)]
    Recovery(#[from] crate::primitives::recovery::RecoveryError),

    #[error(transparent)]
    Discovery(#[from] crate::primitives::discovery::DiscoveryError),

    #[error(transparent)]
    Sharing(#[from] crate::primitives::sharing::SharingError),

    #[error(transparent)]
    Verification(#[from] crate::primitives::verification::VerificationError),

    #[error(transparent)]
    Unpairing(#[from] crate::primitives::unpairing::UnpairingError),

    #[error(transparent)]
    DeRecMessage(#[from] crate::derec_message::DeRecMessageBuilderError),

    #[error(transparent)]
    SecretStore(#[from] crate::protocol::SecretStoreError),

    #[error(transparent)]
    ChannelStore(#[from] crate::protocol::ChannelStoreError),

    #[error(transparent)]
    ShareStore(#[from] crate::protocol::ShareStoreError),

    #[error(transparent)]
    Transport(#[from] crate::transport::TransportValidationError),

    #[error("invalid input: {0}")]
    InvalidInput(&'static str),

    #[error("protobuf decode error")]
    ProtobufDecode(#[source] prost::DecodeError),

    #[error("protobuf encode error")]
    ProtobufEncode(#[source] prost::EncodeError),

    #[error("internal invariant violated: {0}")]
    Invariant(&'static str),

    #[error(
        "role mismatch on channel {channel_id:?}: expected {expected:?}, got {actual:?}"
    )]
    RoleMismatch {
        channel_id: crate::types::ChannelId,
        expected: derec_proto::SenderKind,
        actual: derec_proto::SenderKind,
    },

    /// A replica-mode flow was attempted but the protocol was built without
    /// [`DeRecProtocolBuilder::with_replica_id`](crate::protocol::DeRecProtocolBuilder::with_replica_id).
    /// Surfaces at the entry points of every flow that requires a local
    /// replica identity (initiating a replica-mode pairing, handling an
    /// inbound `PairRequest` whose `sender_kind` is `ReplicaSource` or
    /// `ReplicaDestination`, etc.).
    #[error("replica id not configured: build the protocol with .with_replica_id(..) to enable replica flows")]
    ReplicaIdNotConfigured,
}

impl Error {
    pub fn as_non_ok_status(&self) -> Option<(i32, &str)> {
        match self {
            Error::Pairing(crate::primitives::pairing::PairingError::NonOkStatus {
                status,
                memo,
            }) => Some((*status, memo)),
            Error::Sharing(crate::primitives::sharing::SharingError::NonOkStatus {
                status,
                memo,
            }) => Some((*status, memo)),
            Error::Verification(
                crate::primitives::verification::VerificationError::NonOkStatus { status, memo },
            ) => Some((*status, memo)),
            Error::Discovery(crate::primitives::discovery::DiscoveryError::NonOkStatus {
                status,
                memo,
            }) => Some((*status, memo)),
            Error::Recovery(crate::primitives::recovery::RecoveryError::NonOkStatus {
                status,
                memo,
            }) => Some((*status, memo)),
            Error::Unpairing(crate::primitives::unpairing::UnpairingError::NonOkStatus {
                status,
                memo,
            }) => Some((*status, memo)),
            _ => None,
        }
    }
}
