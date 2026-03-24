// SPDX-License-Identifier: Apache-2.0

use derec_proto::DeRecMessage;
use prost::Message;

mod builder;
pub use builder::*;

// mod wire;
// pub use wire::*;

mod error;
pub use error::*;

// #[cfg(target_arch = "wasm32")]
// pub mod wasm;

#[cfg(test)]
mod tests;

pub fn extract_inner_message<M>(
    wire_bytes: impl AsRef<[u8]>,
    shared_key: &[u8; 32],
) -> Result<(DeRecMessage, M), crate::Error>
where
    M: Message + Default,
{
    let derec_message =
        DeRecMessage::decode(wire_bytes.as_ref()).map_err(crate::Error::ProtobufDecode)?;

    let plaintext =
        derec_cryptography::channel::decrypt_message(&derec_message.message, shared_key)
            .map_err(DeRecMessageBuilderError::Encryption)?;

    let message = M::decode(plaintext.as_slice()).map_err(crate::Error::ProtobufDecode)?;

    Ok((derec_message, message))
}
