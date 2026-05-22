// SPDX-License-Identifier: Apache-2.0

//! Errors produced by the DeRec *unpairing* flow primitive.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnpairingError {
    /// The response carried no `result` field.
    #[error("unpair response missing result")]
    MissingResult,

    /// The peer answered with a non-`Ok` status. The local state was **not**
    /// deleted by the responder; the application decides how to proceed
    /// (retry, escalate, mark the relationship stale, …).
    #[error("unpair response indicates a non-OK status (status={status}): {memo}")]
    NonOkStatus { status: i32, memo: String },

    /// The decoded inner request is missing a required field.
    #[error("invalid unpair request message: {0}")]
    InvalidUnpairRequestMessage(&'static str),

    /// The decoded inner response is missing a required field.
    #[error("invalid unpair response message: {0}")]
    InvalidUnpairResponseMessage(&'static str),
}
