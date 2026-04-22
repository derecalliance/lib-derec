// SPDX-License-Identifier: Apache-2.0

/// Errors that can occur during the DeRec channels discovery flow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelsDiscoveryError {
    /// A channel entry contains an empty `shared_key`.
    #[error("shared_key is empty in channel entry at index {index}")]
    EmptySharedKey { index: usize },

    /// A channel entry contains a `shared_key` that is not 32 bytes.
    #[error("shared_key has invalid length {len} (expected 32) in channel entry at index {index}")]
    InvalidSharedKeyLength { index: usize, len: usize },

    /// `totalBatches` or `currentBatch` is invalid.
    #[error("invalid batch metadata: totalBatches={total}, currentBatch={current}")]
    InvalidBatchMetadata { total: i32, current: i32 },
}
