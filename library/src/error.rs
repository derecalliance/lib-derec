// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Pairing(#[from] crate::pairing::PairingError),

    #[error(transparent)]
    Recovery(#[from] crate::recovery::RecoveryError),

    #[error(transparent)]
    Sharing(#[from] crate::sharing::SharingError),

    #[error(transparent)]
    Verification(#[from] crate::verification::VerificationError),

    #[error("invalid input: {0}")]
    InvalidInput(&'static str),

    #[error("protobuf decode error")]
    ProtobufDecode(#[source] prost::DecodeError),

    #[error("protobuf encode error")]
    ProtobufEncode(#[source] prost::EncodeError),

    #[error("internal invariant violated: {0}")]
    Invariant(&'static str),
}
