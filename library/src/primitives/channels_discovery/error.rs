// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelsDiscoveryError {
    #[error("shared_key is empty in channel entry at index {index}")]
    EmptySharedKey { index: usize },

    #[error("shared_key has invalid length {len} (expected 32) in channel entry at index {index}")]
    InvalidSharedKeyLength { index: usize, len: usize },

    #[error("invalid batch metadata: totalBatches={total}, currentBatch={current}")]
    InvalidBatchMetadata { total: i32, current: i32 },
}
