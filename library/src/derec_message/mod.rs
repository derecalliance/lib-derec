// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Outer-envelope (`DeRecMessage`) parsing, building, and trace-id plumbing.
//!
//! # Security: no upper bound on inbound *byte size*
//!
//! This section is **only about how many bytes the parser will accept**.
//! Semantic validation of decoded content — transport-protocol scheme
//! consistency, contact-mode/field invariants, timestamp pairing,
//! `(nonce, secret_id, version)` binding for verification responses,
//! etc. — runs at the primitive `extract` layer and at the FFI/WASM
//! seams regardless of how big or small the envelope is. Don't read
//! this note as "the library skips validation"; it skips one specific
//! thing: a maximum-byte-length check.
//!
//! Every function in this module that ingests peer wire bytes —
//! [`extract_inner_message`], [`extract_inner_pairing_message`],
//! [`extract_inner_plaintext_message`], [`apply_trace_id`], [`read_trace_id`] —
//! parses whatever it's handed. No caller-side size cap is enforced anywhere
//! in the library, by design: legitimate envelopes span tens of bytes (acks)
//! through many MB (replica-secret sync), so any cap tight enough to be useful
//! against DoS would risk silently truncating a legitimate share or secret and
//! making the secret unrecoverable.
//!
//! The application's transport layer MUST bound inbound message size at a
//! ceiling consistent with its deployment's max secret size, helper count,
//! and replica fan-out before handing bytes to the library. See the security
//! note on [`crate::protocol::DeRecProtocol::process`] for the canonical
//! statement of this contract.
//!
//! Malformed bytes surface as [`crate::Error::ProtobufDecode`]; recursion
//! depth is bounded by `prost`'s decoder, and the DeRec schema is shallow
//! enough that no additional caller-side recursion limit is needed.

use crate::{primitives::pairing::PairingError, types::SharedKey};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{DeRecMessage, MessageBody};
use prost::Message;

mod builder;
pub use builder::*;
mod error;
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

/// Re-stamp the `trace_id` field on an already-produced DeRecMessage envelope.
///
/// The envelope's outer layer is plaintext, so this just decodes the
/// `DeRecMessage` protobuf, overwrites the `trace_id` field, and re-encodes.
/// The inner encrypted `message` payload is untouched — no crypto work.
///
/// Useful for consumers using primitives directly: the `*::request::produce`
/// functions emit envelopes with `trace_id = 0` (the protobuf default), so
/// callers who want correlation can produce + then [`apply_trace_id`] to set
/// their own. The orchestrator (`DeRecProtocol`) already does this
/// automatically on every outbound request.
pub fn apply_trace_id(envelope_bytes: &[u8], trace_id: u64) -> Result<Vec<u8>, crate::Error> {
    let mut envelope =
        DeRecMessage::decode(envelope_bytes).map_err(crate::Error::ProtobufDecode)?;
    envelope.trace_id = trace_id;
    Ok(envelope.encode_to_vec())
}

/// Read the `trace_id` field off an inbound DeRecMessage envelope without
/// touching the encrypted inner payload.
///
/// Pair with [`apply_trace_id`] for request/response correlation when
/// driving the protocol through primitives directly.
pub fn read_trace_id(envelope_bytes: &[u8]) -> Result<u64, crate::Error> {
    let envelope = DeRecMessage::decode(envelope_bytes).map_err(crate::Error::ProtobufDecode)?;
    Ok(envelope.trace_id)
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

/// Decodes the inner [`MessageBody`] from a plaintext envelope.
///
/// Used by the `HashedKeys` pre-pair leg, where the `message` field of the
/// outer [`DeRecMessage`] envelope carries a serialized `MessageBody`
/// directly — no encryption, because no shared or asymmetric key exists
/// yet at that point in the protocol.
///
/// Counterpart to the plaintext PrePair envelope builder path —
/// see [`crate::primitives::pairing::request::produce_pre_pair_request`]
/// and [`crate::primitives::pairing::response::produce_pre_pair`] for the
/// producers that emit the bytes this function decodes.
pub fn extract_inner_plaintext_message(
    message_bytes: &[u8],
) -> Result<MessageBody, crate::Error> {
    MessageBody::decode_from_vec(message_bytes).map_err(crate::Error::ProtobufDecode)
}
