// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnpairingError {
    #[error("unpair response indicates a non-OK status (status={status}): {memo}")]
    NonOkStatus { status: i32, memo: String },
}
