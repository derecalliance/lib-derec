// SPDX-License-Identifier: Apache-2.0

/// Errors that can occur during the DeRec replica confirmation flow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplicaConfirmationError {
    /// The fingerprint in the request does not match the locally derived value.
    #[error("fingerprint mismatch")]
    FingerprintMismatch,

    /// The response message does not include the required `result` field.
    #[error("replica confirmation response does not contain a result")]
    MissingResult,

    /// The peer reported a non-OK result status.
    #[error("replica confirmation response indicates a non-OK status (status={status})")]
    NonOkStatus { status: i32 },
}
