// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("verification response indicates a non-OK status (status={status}): {memo}")]
    NonOkStatus { status: i32, memo: String },
}
