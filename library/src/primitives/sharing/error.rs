// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SharingError {
    #[error("no channels provided")]
    EmptyChannels,

    #[error("duplicate channel id: {0}")]
    DuplicateChannelId(u64),

    #[error(
        "invalid threshold (threshold={threshold}, channels={channels}); must satisfy 2 <= threshold <= channels"
    )]
    InvalidThreshold { threshold: usize, channels: usize },

    #[error("secret_data is empty")]
    EmptySecretData,

    #[error("VSS failed to generate shares")]
    VssShareFailed {
        #[source]
        source: derec_cryptography::vss::DerecVSSError,
    },

    #[error("share response indicates a non-OK status (status={status}): {memo}")]
    NonOkStatus { status: i32, memo: String },

    #[error("share version mismatch in share response (expected={expected}, got={got})")]
    VersionMismatch { expected: u32, got: u32 },
}
