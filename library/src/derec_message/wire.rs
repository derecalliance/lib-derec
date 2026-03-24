//! Wire encoding and decoding utilities for DeRec messages.
//!
//! This module defines the transformation between structured [`DeRecMessage`]
//! envelopes and their transport representation.
//!
//! At a high level, the wire pipeline is:
//!
//! ## Encoding
//!
//! ```text
//! DeRecMessage body
//!     ↓ wrap in DeRecMessage envelope
//! DeRecMessage
//!     ↓ serialize (prost)
//! serialized bytes
//!     ↓ sign
//! signed bytes
//!     ↓ encrypt
//! encrypted payload
//!     ↓ prepend recipient key id
//! WireMessage / raw wire bytes
//! ```
//!
//! ## Decoding
//!
//! ```text
//! raw wire bytes
//!     ↓ parse recipient key id + payload
//! WireMessage
//!     ↓ decrypt
//! signed bytes
//!     ↓ verify signature
//! serialized DeRecMessage
//!     ↓ deserialize (prost)
//! DeRecMessage
//! ```
//!
//! # Responsibilities
//!
//! This module is responsible for:
//!
//! - Building a [`DeRecMessage`] envelope around a flow-specific message body
//! - Serializing and deserializing protobuf data
//! - Invoking the signing and encryption primitives from the `derec_cryptography` crate
//! - Framing and parsing the transport payload as a [`WireMessage`]
//!
//! This module does **not**:
//!
//! - implement cryptographic primitives directly
//! - define protocol flow logic such as pairing, sharing, verification, or recovery
//! - resolve sender/receiver keys from application state or network metadata
//!
//! # Wire format
//!
//! The transport representation used by this module is:
//!
//! ```text
//! recipient_key_id (4-byte big-endian i32) || encrypted_payload
//! ```
//!
//! The `recipient_key_id` identifies which decryption key the recipient should use
//! to process the payload.
//!
//! # Notes
//!
//! - Messages are **signed before encryption**
//! - Sender and receiver identifiers embedded in [`DeRecMessage`] are computed as
//!   SHA-384 hashes of the corresponding public keys
//! - The caller is responsible for supplying the correct sender and receiver key material

use crate::derec_message::{DeRecEnvelopeBody, DeRecMessageBuilder, WireError};
use derec_cryptography::envelope::{encryption, signing};
use derec_proto::{DeRecMessage, de_rec_message::message_bodies::Messages};
use prost::Message;
use prost_types::Timestamp;
use sha2::{Digest, Sha384};
use std::time::{SystemTime, UNIX_EPOCH};

/// Fully encoded DeRec transport payload.
///
/// According to the protocol, the wire format is:
///
/// `recipient_key_id (4-byte big-endian i32) || encrypted_payload`
///
/// The `recipient_key_id` identifies which decryption key the recipient should use
/// for the enclosed encrypted payload.
///
/// # Fields
///
/// * `recipient_key_id` - Big-endian 32-bit identifier of the recipient decryption key
/// * `payload` - Encrypted transport payload bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireMessage {
    pub recipient_key_id: i32,
    pub payload: Vec<u8>,
}

impl WireMessage {
    /// Serializes this [`WireMessage`] into raw transport bytes.
    ///
    /// The returned bytes are the exact wire representation expected by the
    /// DeRec transport layer:
    ///
    /// `recipient_key_id (big-endian i32) || payload`
    ///
    /// # Returns
    ///
    /// Returns the full transportable byte representation of this wire message.
    ///
    /// # Example
    ///
    /// ```rust
    /// use derec_library::derec_message::WireMessage;
    ///
    /// let wire = WireMessage {
    ///     recipient_key_id: 7,
    ///     payload: vec![1, 2, 3],
    /// };
    ///
    /// let bytes = wire.to_bytes();
    ///
    /// assert_eq!(&bytes[..4], &7_i32.to_be_bytes());
    /// assert_eq!(&bytes[4..], &[1, 2, 3]);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.payload.len());
        out.extend_from_slice(&self.recipient_key_id.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parses a [`WireMessage`] from raw transport bytes.
    ///
    /// This function interprets the first 4 bytes as a big-endian `i32`
    /// recipient key ID and treats the remaining bytes as the encrypted payload.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw transport bytes in the format
    ///   `recipient_key_id (big-endian i32) || encrypted_payload`
    ///
    /// # Returns
    ///
    /// On success returns the parsed [`WireMessage`].
    ///
    /// # Errors
    ///
    /// Returns [`WireDecodeError`] in the following cases:
    ///
    /// - [`WireDecodeError::WireMessageTooShort`] if fewer than 4 bytes are provided
    /// - [`WireDecodeError::InvalidWirePrefix`] if the recipient key prefix cannot be parsed
    ///
    /// # Example
    ///
    /// ```rust
    /// use derec_library::derec_message::WireMessage;
    ///
    /// let raw = [0, 0, 0, 7, 10, 20, 30];
    /// let wire = WireMessage::from_bytes(&raw).expect("wire should parse");
    ///
    /// assert_eq!(wire.recipient_key_id, 7);
    /// assert_eq!(wire.payload, vec![10, 20, 30]);
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < 4 {
            return Err(WireError::WireMessageTooShort(bytes.len()));
        }

        let (key_id_bytes, payload) = bytes.split_at(4);
        let key_id = i32::from_be_bytes(
            key_id_bytes
                .try_into()
                .map_err(|_| WireError::InvalidWirePrefix)?,
        );

        Ok(Self {
            recipient_key_id: key_id,
            payload: payload.to_vec(),
        })
    }
}

/// Encodes a flow-specific DeRec message body into a structured [`WireMessage`].
///
/// This function performs the full wire encoding pipeline:
///
/// 1. Compute sender and receiver identifiers as SHA-384 hashes of the provided public keys
/// 2. Build a top-level [`DeRecMessage`] envelope around the provided body
/// 3. Serialize the envelope as protobuf bytes
/// 4. Sign the serialized bytes using the sender's signing key
/// 5. Encrypt the signed payload to the receiver's public key
/// 6. Return a [`WireMessage`] containing the caller-provided `recipient_key_id`
///
/// # Arguments
///
/// * `recipient_key_id` - Transport-level identifier of the recipient decryption key
/// * `sender_key` - Sender private key used for signing
/// * `sender_pk` - Sender public key used to derive the `sender` field in the envelope
/// * `receiver_pk` - Receiver public key used both to derive the `receiver` field and to encrypt the payload
/// * `secret_id` - Secret identifier to embed in the envelope
/// * `body` - Flow-specific message body to wrap into the envelope
///
/// # Returns
///
/// On success returns a [`WireMessage`] whose payload is the encrypted signed envelope.
///
/// # Errors
///
/// Returns [`WireEncodeError`] in the following cases:
///
/// - envelope construction fails
/// - signing fails
/// - encryption fails
///
/// # Security Notes
///
/// - The message is signed **before** encryption
/// - The caller is responsible for supplying key material that matches the intended sender and receiver
/// - `recipient_key_id` is not derived internally; it is supplied by the caller as transport metadata
///
/// # Example
///
/// ```rust,ignore
/// let wire = encode(
///     recipient_key_id,
///     sender_secret_key,
///     sender_public_key,
///     receiver_public_key,
///     secret_id,
///     message_body,
/// )?;
/// ```
pub fn encode<M>(
    recipient_key_id: i32,
    sender_private_key: &[u8],
    sender_public_key: &[u8],
    receiver_public_key: &[u8],
    secret_id: &[u8],
    body: M,
) -> Result<WireMessage, WireError>
where
    M: Into<DeRecEnvelopeBody>,
{
    let sender_hash = sha384(sender_public_key);
    let receiver_hash = sha384(receiver_public_key);

    let message = DeRecMessageBuilder::new()
        .sender(sender_hash)
        .receiver(receiver_hash)
        .secret_id(secret_id)?
        .message(body)?
        .timestamp(current_timestamp())
        .build()?;

    let serialized = message.encode_to_vec();
    let signed = signing::sign(&serialized, sender_private_key)?;
    let encrypted = encryption::encrypt(&signed, receiver_public_key)?;

    Ok(WireMessage {
        recipient_key_id,
        payload: encrypted,
    })
}

/// Encodes a flow-specific DeRec message body directly into raw wire bytes.
///
/// This is a convenience wrapper around [`encode`] followed by [`WireMessage::to_bytes`].
///
/// # Arguments
///
/// * `recipient_key_id` - Transport-level identifier of the recipient decryption key
/// * `sender_key` - Sender private key used for signing
/// * `sender_pk` - Sender public key used to derive the `sender` field in the envelope
/// * `receiver_pk` - Receiver public key used both to derive the `receiver` field and to encrypt the payload
/// * `secret_id` - Secret identifier to embed in the envelope
/// * `body` - Flow-specific message body to wrap into the envelope
///
/// # Returns
///
/// On success returns the final transport representation:
///
/// `recipient_key_id (big-endian i32) || encrypted_payload`
///
/// # Errors
///
/// Propagates the same errors as [`encode`].
///
/// # Example
///
/// ```rust,ignore
/// let wire_bytes = encode_to_bytes(
///     recipient_key_id,
///     sender_secret_key,
///     sender_public_key,
///     receiver_public_key,
///     secret_id,
///     message_body,
/// )?;
/// ```
pub fn encode_to_bytes<M>(
    recipient_key_id: i32,
    sender_private_key: &[u8],
    sender_public_key: &[u8],
    receiver_public_key: &[u8],
    secret_id: &[u8],
    body: M,
) -> Result<Vec<u8>, WireError>
where
    M: Into<DeRecEnvelopeBody>,
{
    Ok(encode(
        recipient_key_id,
        sender_private_key,
        sender_public_key,
        receiver_public_key,
        secret_id,
        body,
    )?
    .to_bytes())
}

/// Decodes a structured [`WireMessage`] back into a [`DeRecMessage`].
///
/// This function performs the reverse wire decoding pipeline:
///
/// 1. Decrypt the encrypted payload using the receiver's private key
/// 2. Verify the resulting signed payload using the sender's public key
/// 3. Deserialize the verified bytes into a [`DeRecMessage`]
///
/// # Arguments
///
/// * `wire_message` - Parsed wire message containing the recipient key ID and encrypted payload
/// * `receiver_sk` - Receiver private key used for decryption
/// * `sender_pk` - Sender public key used for signature verification
///
/// # Returns
///
/// On success returns the decoded [`DeRecMessage`].
///
/// # Errors
///
/// Returns [`WireDecodeError`] in the following cases:
///
/// - decryption fails
/// - signature verification fails
/// - protobuf deserialization fails
///
/// # Security Notes
///
/// - This function verifies authenticity using the provided `sender_pk`
/// - It does not resolve keys from the message contents or application context
/// - The caller is responsible for ensuring that `sender_pk` is the correct key for the sender
///
/// # Example
///
/// ```rust,ignore
/// let message = decode(&wire_message, receiver_secret_key, sender_public_key)?;
/// ```
pub fn decode(
    wire_message: &WireMessage,
    receiver_secret_key: &[u8],
) -> Result<DeRecMessage, WireError> {
    // 1. Decrypt the payload
    let decrypted = encryption::decrypt(&wire_message.payload, receiver_secret_key)?;

    // 2. Extract unsigned plaintext bytes from the signed payload format
    let payload = extract_signed_payload_bytes(&decrypted)?;

    // 3. Decode the message once so we can inspect the body
    let message = DeRecMessage::decode(payload)?;

    // 4. Extract sender public key from the decoded message
    let sender_public_key = extract_sender_public_key(&message)?;

    // 5. Verify the signed payload using the extracted sender public key
    let verified = signing::verify(&decrypted, &sender_public_key)?;

    // 6. Decode the verified payload
    let verified_message = DeRecMessage::decode(&*verified)?;

    // 7. Validate sender hash binding
    let expected_sender_hash = sha384(&sender_public_key);
    if verified_message.sender != expected_sender_hash {
        return Err(WireError::SenderHashMismatch);
    }

    Ok(verified_message)
}

/// Decodes raw transport bytes back into a [`DeRecMessage`].
///
/// This is a convenience wrapper around [`WireMessage::from_bytes`] followed by [`decode`].
///
/// # Arguments
///
/// * `receiver_sk` - Receiver private key used for decryption
/// * `sender_pk` - Sender public key used for signature verification
/// * `wire_bytes` - Raw transport bytes in the format
///   `recipient_key_id (big-endian i32) || encrypted_payload`
///
/// # Returns
///
/// On success returns the decoded [`DeRecMessage`].
///
/// # Errors
///
/// Returns [`WireDecodeError`] if:
///
/// - the raw bytes cannot be parsed as a valid [`WireMessage`]
/// - decryption fails
/// - signature verification fails
/// - the verified payload is not a valid serialized [`DeRecMessage`]
///
/// # Example
///
/// ```rust,ignore
/// let message = decode_from_bytes(
///     receiver_secret_key,
///     sender_public_key,
///     &wire_bytes,
/// )?;
/// ```
pub fn decode_from_bytes(
    receiver_secret_key: &[u8],
    wire_bytes: &[u8],
) -> Result<DeRecMessage, WireError> {
    let wire_message = WireMessage::from_bytes(wire_bytes)?;
    decode(&wire_message, receiver_secret_key)
}

/// Computes the SHA-384 hash of the provided bytes.
///
/// This helper is used internally to derive the `sender` and `receiver` fields
/// embedded in a [`DeRecMessage`] from the corresponding public keys.
///
/// # Arguments
///
/// * `data` - Input bytes, typically a serialized public key
///
/// # Returns
///
/// A 48-byte SHA-384 digest.
pub(crate) fn sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn extract_signed_payload_bytes(signed_payload: &[u8]) -> Result<&[u8], WireError> {
    if signed_payload.len() < 4 {
        return Err(signing::DerecSigningError::InvalidFormat.into());
    }

    let sig_len = u32::from_le_bytes(
        signed_payload[0..4]
            .try_into()
            .map_err(|_| signing::DerecSigningError::InvalidFormat)?,
    ) as usize;

    if signed_payload.len() < 4 + sig_len {
        return Err(signing::DerecSigningError::InvalidFormat.into());
    }

    Ok(&signed_payload[4 + sig_len..])
}

fn extract_sender_public_key(message: &DeRecMessage) -> Result<Vec<u8>, WireError> {
    let bodies = message
        .message_bodies
        .as_ref()
        .ok_or(WireError::UnsupportedSenderKeyExtraction)?;

    match bodies
        .messages
        .as_ref()
        .ok_or(WireError::UnsupportedSenderKeyExtraction)?
    {
        Messages::SharerMessageBodies(sharer_bodies) => {
            if sharer_bodies.sharer_message_body.len() != 1 {
                return Err(WireError::UnsupportedSenderKeyExtraction);
            }

            let body = sharer_bodies.sharer_message_body[0]
                .body
                .as_ref()
                .ok_or(WireError::UnsupportedSenderKeyExtraction)?;

            match body {
                OwnerBody::PairRequestMessage(request) => Ok(request.ecies_public_key.clone()),
                _ => Err(WireError::UnsupportedSenderKeyExtraction),
            }
        }
        _ => Err(WireError::UnsupportedSenderKeyExtraction),
    }
}
