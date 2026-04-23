// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    #[error("secret_id is empty in secret list entry at index {index}")]
    EmptySecretId { index: usize },

    #[error("discovery response does not contain a result")]
    MissingResult,

    #[error("discovery response indicates a non-OK status (status={status})")]
    NonOkStatus { status: i32 },
}
