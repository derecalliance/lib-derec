// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("verification response indicates a non-OK status (status={status}): {memo}")]
    NonOkStatus { status: i32, memo: String },

    #[error(
        "verification response does not match the outstanding request: \
         field={field} expected={expected} got={got}"
    )]
    ResponseBindingMismatch {
        field: &'static str,
        expected: u64,
        got: u64,
    },
}
