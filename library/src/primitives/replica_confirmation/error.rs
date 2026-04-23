// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplicaConfirmationError {
    #[error("fingerprint mismatch")]
    FingerprintMismatch,

    #[error("replica confirmation response does not contain a result")]
    MissingResult,

    #[error("replica confirmation response indicates a non-OK status (status={status})")]
    NonOkStatus { status: i32 },
}
