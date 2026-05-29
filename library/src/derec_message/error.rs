// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeRecMessageBuilderError {
    #[error("missing channel_id")]
    MissingChannelId,

    #[error("missing timestamp")]
    MissingTimestamp,

    #[error("missing message")]
    MissingMessage,

    #[error("invalid timestamp: {0:?}")]
    InvalidTimestamp(SystemTime),

    #[error(transparent)]
    Encryption(#[from] derec_cryptography::channel::DerecChannelError),

    #[error(transparent)]
    PairingEncryption(#[from] derec_cryptography::pairing::envelope::DerecEncryptionError),
}
