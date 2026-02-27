// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SharingError {
    #[error("no channels provided")]
    EmptyChannels,

    #[error(
        "invalid threshold (threshold={threshold}, channels={channels}); must satisfy 2 <= threshold <= channels"
    )]
    InvalidThreshold { threshold: usize, channels: usize },

    #[error("secret_id is empty")]
    EmptySecretId,

    #[error("secret_data is empty")]
    EmptySecretData,

    #[error("VSS failed to generate shares")]
    VssShareFailed {
        #[source]
        source: derec_cryptography::vss::DerecVSSError,
    },
}
