// SPDX-License-Identifier: Apache-2.0

/// Errors that can occur during the DeRec discovery flow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// A `secret_id` supplied to the response producer is empty.
    ///
    /// Every entry in the secret list must carry a non-empty `secret_id`
    /// so that the recovering Owner can unambiguously identify each secret.
    #[error("secret_id is empty in secret list entry at index {index}")]
    EmptySecretId { index: usize },

    /// The response message does not include the required `result` field.
    #[error("discovery response does not contain a result")]
    MissingResult,

    /// The Helper reported a non-OK result status.
    ///
    /// The contained `status` value is the raw [`derec_proto::StatusEnum`] integer.
    #[error("discovery response indicates a non-OK status (status={status})")]
    NonOkStatus { status: i32 },
}
