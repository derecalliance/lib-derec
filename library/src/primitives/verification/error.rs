// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("verification response missing result")]
    MissingResult,

    #[error("verification response indicates failure (status={status})")]
    NonOkStatus { status: i32 },
}
