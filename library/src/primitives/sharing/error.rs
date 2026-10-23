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
        "invalid threshold (threshold={threshold}, subshares={subshares} across {channels} channels); must satisfy 2 <= threshold <= subshares"
    )]
    InvalidThreshold {
        threshold: usize,
        channels: usize,
        subshares: u64,
    },

    #[error(
        "weight {weight} for channel {channel_id} is invalid: it must be at least 1, below the threshold, and name a channel being shared with"
    )]
    InvalidWeight { channel_id: u64, weight: u32 },

    /// The round's total subshares (the sum of every paired Helper's weight)
    /// exceeds the cap set with
    /// [`DeRecProtocolBuilder::with_max_subshares`](crate::protocol::DeRecProtocolBuilder::with_max_subshares).
    #[error("too many subshares ({subshares}) for the configured cap ({max})")]
    TooManySubshares { subshares: u64, max: u64 },

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
