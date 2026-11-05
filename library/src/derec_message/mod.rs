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
//!
//! # Security: replay detection belongs to the transport
//!
//! The library processes a copy of a message as often as it is delivered
//! within the inbound window. The application's transport layer MUST detect
//! copies, of what it received and of what it sent, keyed on
//! [`message_id`]; see the security note on
//! [`crate::protocol::DeRecProtocol::process`] for the full contract.

use crate::{Error, primitives::pairing::PairingError, types::SharedKey, utils::random_u64};
use derec_cryptography::channel;
use derec_cryptography::pairing::{PairingSecretKeyMaterial, envelope};
use derec_proto::{DeRecMessage, MessageBody};
use prost::Message;
use sha2::{Digest, Sha256};

mod builder;
pub use builder::*;
mod error;
pub use error::*;

#[cfg(test)]
mod tests;

pub fn extract_inner_message(
    message_bytes: &[u8],
    shared_key: &SharedKey,
) -> Result<MessageBody, Error> {
    let decrypted = decrypt_inner_message(message_bytes, shared_key)?;

    let inner = MessageBody::decode_from_vec(&decrypted).map_err(Error::ProtobufDecode)?;

    Ok(inner)
}

/// Decrypt a channel envelope's `message` under `shared_key`, without
/// decoding the plaintext.
///
/// Success authenticates the sender as the holder of the channel key, which
/// is what separates an undecryptable message (no one to answer) from an
/// authenticated one whose body cannot be decoded (answered with an
/// `ErrorResponseMessage`).
pub(crate) fn decrypt_inner_message(
    message_bytes: &[u8],
    shared_key: &SharedKey,
) -> Result<Vec<u8>, Error> {
    Ok(channel::decrypt_message(message_bytes, shared_key)
        .map_err(DeRecMessageBuilderError::Encryption)?)
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
pub fn apply_trace_id(envelope_bytes: &[u8], trace_id: u64) -> Result<Vec<u8>, Error> {
    let mut envelope = DeRecMessage::decode(envelope_bytes).map_err(Error::ProtobufDecode)?;
    envelope.trace_id = trace_id;
    Ok(envelope.encode_to_vec())
}

/// Draw a fresh correlation token for an outbound request envelope.
///
/// Mirrors [`DeRecMessageBuilder::auto_trace_id`] but for the case where the
/// envelope was built by a primitive and is then re-stamped via
/// [`apply_trace_id`]. A `0` return is indistinguishable from "unset", so
/// there is a 2^-64 chance of drawing a token downstream code might read as
/// "no correlation requested" — not worth coding around.
pub(crate) fn fresh_trace_id() -> u64 {
    random_u64()
}

/// Read the `trace_id` field off an inbound DeRecMessage envelope without
/// touching the encrypted inner payload.
///
/// Pair with [`apply_trace_id`] for request/response correlation when
/// driving the protocol through primitives directly.
pub fn read_trace_id(envelope_bytes: &[u8]) -> Result<u64, Error> {
    let envelope = DeRecMessage::decode(envelope_bytes).map_err(Error::ProtobufDecode)?;
    Ok(envelope.trace_id)
}

/// The identity of one delivered message, read off its envelope without the
/// channel key. See [`message_id`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MessageId {
    /// SHA-256 of the envelope's encrypted `message` field.
    pub id: [u8; 32],
    /// The envelope's send time, in seconds since the Unix epoch.
    pub timestamp: u64,
}

/// Identify an envelope for replay and reflection detection.
///
/// Detecting a message delivered twice is the application's job, since it
/// owns the transport. `id` is the same for every copy of one message and
/// different for every other message:
///
/// - It covers only the encrypted `message` field. The cleartext fields
///   around it (`sequence`, `traceId`, the protocol version) are not
///   authenticated, and protobuf accepts more than one encoding of the same
///   envelope, so a copy can arrive as different bytes and still be
///   accepted. A hash of the raw envelope therefore does not identify it.
/// - Changing the `message` field fails decryption, and every message is
///   sealed under a fresh random nonce, so no other message, not even one
///   with the same body, has the same `id`.
///
/// `timestamp` is the envelope's cleartext send time. Once
/// [`process`](crate::protocol::DeRecProtocol::process) accepts the message
/// it is proven equal to the authenticated time inside it.
///
/// The plaintext `PrePair` leg of `HashedKeys` pairing is the exception: its
/// `message` field is not encrypted, so a copy re-encoded inside it gets a
/// different `id`. That leg is not authenticated at all; the contact's nonce
/// is what binds it.
///
/// # Errors
///
/// [`Error::ProtobufDecode`] when the bytes are not an envelope, and
/// [`Error::InvalidInput`] when it carries no timestamp, which the protocol
/// never accepts.
pub fn message_id(envelope_bytes: &[u8]) -> Result<MessageId, Error> {
    let envelope = DeRecMessage::decode(envelope_bytes).map_err(Error::ProtobufDecode)?;
    let timestamp = envelope
        .timestamp
        .ok_or(Error::InvalidInput("envelope carries no timestamp"))?;
    Ok(MessageId {
        id: Sha256::digest(&envelope.message).into(),
        timestamp: u64::try_from(timestamp.seconds).unwrap_or(0),
    })
}

pub fn extract_inner_pairing_message(
    message_bytes: &[u8],
    pairing_secret: &PairingSecretKeyMaterial,
) -> Result<MessageBody, Error> {
    let decrypted = envelope::decrypt(message_bytes, pairing_secret.ecies_secret_key())
        .map_err(PairingError::PairingEncryption)?;

    let inner = MessageBody::decode_from_vec(&decrypted).map_err(Error::ProtobufDecode)?;

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
pub fn extract_inner_plaintext_message(message_bytes: &[u8]) -> Result<MessageBody, Error> {
    MessageBody::decode_from_vec(message_bytes).map_err(Error::ProtobufDecode)
}
