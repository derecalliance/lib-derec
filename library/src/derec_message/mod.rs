// SPDX-License-Identifier: Apache-2.0

use crate::{primitives::pairing::PairingError, types::SharedKey};

mod builder;
pub use builder::*;

mod error;
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::MessageBody;
pub use error::*;

#[cfg(test)]
mod tests;

pub fn extract_inner_message(
    message_bytes: &[u8],
    shared_key: &SharedKey,
) -> Result<MessageBody, crate::Error> {
    let decrypted = derec_cryptography::channel::decrypt_message(message_bytes, shared_key)
        .map_err(DeRecMessageBuilderError::Encryption)?;

    let inner = MessageBody::decode_from_vec(&decrypted).map_err(crate::Error::ProtobufDecode)?;

    Ok(inner)
}

pub fn extract_inner_pairing_message(
    message_bytes: &[u8],
    pairing_secret: &PairingSecretKeyMaterial,
) -> Result<MessageBody, crate::Error> {
    let decrypted = derec_cryptography::pairing::envelope::decrypt(
        message_bytes,
        pairing_secret.ecies_secret_key(),
    )
    .map_err(PairingError::PairingEncryption)?;

    let inner = MessageBody::decode_from_vec(&decrypted).map_err(crate::Error::ProtobufDecode)?;

    Ok(inner)
}
