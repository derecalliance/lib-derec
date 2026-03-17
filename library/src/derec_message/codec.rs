//! Helpers for encoding and decoding the top-level [`derec_proto::DeRecMessage`] transport
//! envelope.
//!
//! In the DeRec protocol, all protocol messages except `ContactMessage` are first wrapped inside
//! a [`derec_proto::DeRecMessage`] envelope. That envelope is then:
//!
//! 1. Serialized as protobuf bytes
//! 2. Signed using the sender’s signing key
//! 3. Encrypted for the receiver
//! 4. Prefixed with the receiver key ID to form the final wire payload
//!
//! This module provides the transport-layer helpers for that process:
//!
//! - [`WireMessage`] represents the final transport payload structure
//! - [`DeRecMessageCodec`] performs the encode/decode flow
//! - [`DeRecMessageSigner`], [`DeRecMessageVerifier`], [`DeRecMessageEncrypter`], and
//!   [`DeRecMessageDecrypter`] define the cryptographic backend contracts
//! - [`VerifiedPayload`] carries the verified plaintext and sender identity returned by signature
//!   verification
//!
//! At a high level, the codec lifecycle is:
//!
//! 1. Start from a constructed [`derec_proto::DeRecMessage`]
//! 2. Call [`DeRecMessageCodec::encode`] or [`DeRecMessageCodec::encode_to_bytes`] to produce a
//!    transport-ready payload
//! 3. On the receiving side, parse the raw wire bytes with [`WireMessage::from_bytes`] or call
//!    [`DeRecMessageCodec::decode_from_bytes`]
//! 4. Recover the validated [`derec_proto::DeRecMessage`] after decryption and signature
//!    verification
//!
//! # Security Model
//!
//! This module does not implement cryptography directly. Instead, it delegates signing,
//! verification, encryption, and decryption to backend traits. This keeps the codec independent
//! of any particular cryptographic implementation while still enforcing protocol invariants such as:
//!
//! - the sender hash in the envelope must match the verified signing identity
//! - the receiver hash in the envelope must match the decryption/encryption target
//! - the prefixed recipient key ID must match the decryption key in use
//!
//! # Notes
//!
//! * This module operates on fully constructed [`derec_proto::DeRecMessage`] values.
//!   Envelope construction is handled separately by the DeRecMessage builder.
//! * The wire format represented here is:
//!
//!   `recipient_key_id (4-byte big-endian i32) || encrypted_payload`
//! * `ContactMessage` is not handled by this module because it is exchanged out-of-band and is
//!   not wrapped in a `DeRecMessage`.
//!
//! # Example
//!
//! ```rust,ignore
//! let wire_bytes = DeRecMessageCodec::encode_to_bytes(
//!     &message,
//!     &signer,
//!     &encrypter,
//! )?;
//!
//! let decoded = DeRecMessageCodec::decode_from_bytes(
//!     &wire_bytes,
//!     &decrypter,
//!     &verifier,
//! )?;
//! ```

use derec_proto::DeRecMessage;
use prost::Message;
use thiserror::Error;

/// Fully encoded DeRec transport payload.
///
/// In the DeRec protocol, once a [`DeRecMessage`] has been serialized, signed,
/// and encrypted, the final wire representation is transmitted as:
///
/// `recipient_key_id (4-byte big-endian i32) || encrypted_payload`
///
/// The `recipient_key_id` identifies which decryption key the recipient should
/// use to decrypt the enclosed payload.
///
/// This type represents that final transport-level structure after envelope
/// construction and cryptographic processing.
///
/// # Fields
///
/// * `recipient_key_id` - Big-endian 32-bit identifier of the recipient’s
///   decryption key.
/// * `payload` - The encrypted payload bytes that follow the key ID prefix.
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
    ///   `recipient_key_id (big-endian i32) || encrypted_payload`.
    ///
    /// # Returns
    ///
    /// On success returns the parsed [`WireMessage`].
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageCodecError`] in the following cases:
    ///
    /// - [`DeRecMessageCodecError::WireMessageTooShort`] if fewer than 4 bytes are provided.
    /// - [`DeRecMessageCodecError::InvalidWirePrefix`] if the recipient key prefix cannot be parsed.
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeRecMessageCodecError> {
        if bytes.len() < 4 {
            return Err(DeRecMessageCodecError::WireMessageTooShort(bytes.len()));
        }

        let (key_id_bytes, payload) = bytes.split_at(4);
        let key_id = i32::from_be_bytes(
            key_id_bytes
                .try_into()
                .map_err(|_| DeRecMessageCodecError::InvalidWirePrefix)?,
        );

        Ok(Self {
            recipient_key_id: key_id,
            payload: payload.to_vec(),
        })
    }
}

/// Result of signature verification used during [`DeRecMessageCodec::decode`].
///
/// After a transport payload is decrypted, the signed content must be verified.
/// On success, verification yields:
///
/// - the original serialized [`DeRecMessage`] protobuf bytes
/// - the sender key hash associated with the verified signature
///
/// The `signer_key_hash` must use the same scheme as [`DeRecMessage::sender`],
/// namely the SHA-384 hash of the sender’s public key.
///
/// # Fields
///
/// * `payload` - The original serialized `DeRecMessage` bytes recovered after
///   successful signature verification.
/// * `signer_key_hash` - The verified sender key hash that should match
///   `DeRecMessage.sender`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayload {
    pub payload: Vec<u8>,
    pub signer_key_hash: Vec<u8>,
}

/// Signing backend used by [`DeRecMessageCodec::encode`].
///
/// Implement this trait using the actual signing mechanism provided by the SDK
/// or host environment, such as OpenPGP signed payload generation.
///
/// The codec uses this trait to:
///
/// 1. confirm that the envelope’s `sender` hash matches the signing identity
/// 2. sign the serialized protobuf envelope bytes
pub trait DeRecMessageSigner {
    /// Returns the sender key hash that should match [`DeRecMessage::sender`].
    fn sender_key_hash(&self) -> &[u8];

    /// Signs the serialized protobuf envelope bytes.
    ///
    /// # Arguments
    ///
    /// * `payload` - Serialized [`DeRecMessage`] protobuf bytes.
    ///
    /// # Returns
    ///
    /// On success returns the signed payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageCodecError::Signing`] or another implementation-specific
    /// codec error if signing fails.
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError>;
}

/// Signature verification backend used by [`DeRecMessageCodec::decode`].
///
/// Implement this trait using the actual signature verification mechanism
/// provided by the SDK or host environment.
///
/// The codec relies on verification to recover both:
///
/// - the original serialized envelope bytes
/// - the sender key hash bound to the verified signature
pub trait DeRecMessageVerifier {
    /// Verifies a signed payload and returns the recovered plaintext bytes plus
    /// the sender key hash associated with the verified signature.
    ///
    /// # Arguments
    ///
    /// * `signed_payload` - Signed payload bytes recovered after decryption.
    ///
    /// # Returns
    ///
    /// On success returns [`VerifiedPayload`].
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageCodecError::Verification`] or another implementation-specific
    /// codec error if signature verification fails.
    fn verify(&self, signed_payload: &[u8]) -> Result<VerifiedPayload, DeRecMessageCodecError>;
}

/// Encryption backend used by [`DeRecMessageCodec::encode`].
///
/// Implement this trait using the actual encryption mechanism provided by the SDK
/// or host environment, such as OpenPGP encryption to the intended receiver.
///
/// The codec uses this trait to:
///
/// 1. confirm that the envelope’s `receiver` hash matches the encryption target
/// 2. encrypt the signed payload
/// 3. determine the key ID that must prefix the final wire message
pub trait DeRecMessageEncrypter {
    /// Returns the recipient key ID that must prefix the final wire payload.
    fn recipient_key_id(&self) -> i32;

    /// Returns the receiver key hash that should match [`DeRecMessage::receiver`].
    fn recipient_key_hash(&self) -> &[u8];

    /// Encrypts the signed payload.
    ///
    /// # Arguments
    ///
    /// * `signed_payload` - Signed bytes produced after protobuf serialization
    ///   and signature generation.
    ///
    /// # Returns
    ///
    /// On success returns the encrypted payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageCodecError::Encryption`] or another implementation-specific
    /// codec error if encryption fails.
    fn encrypt(&self, signed_payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError>;
}

/// Decryption backend used by [`DeRecMessageCodec::decode`].
///
/// Implement this trait using the actual decryption mechanism provided by the SDK
/// or host environment.
///
/// The codec uses this trait to:
///
/// 1. validate the incoming `recipient_key_id`
/// 2. decrypt the encrypted transport payload
/// 3. confirm that the decoded envelope was actually intended for the current recipient
pub trait DeRecMessageDecrypter {
    /// Returns the recipient key ID expected by the current decryption key.
    fn recipient_key_id(&self) -> i32;

    /// Returns the receiver key hash that should match [`DeRecMessage::receiver`].
    fn recipient_key_hash(&self) -> &[u8];

    /// Decrypts the encrypted payload and returns the signed payload.
    ///
    /// # Arguments
    ///
    /// * `encrypted_payload` - Encrypted transport payload bytes.
    ///
    /// # Returns
    ///
    /// On success returns the signed payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageCodecError::Decryption`] or another implementation-specific
    /// codec error if decryption fails.
    fn decrypt(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError>;
}

/// Errors that can occur while encoding or decoding a [`DeRecMessage`] with
/// [`DeRecMessageCodec`].
///
/// These errors cover transport parsing, sender/receiver identity checks,
/// protobuf decoding, and backend cryptographic failures.
#[derive(Debug, Error)]
pub enum DeRecMessageCodecError {
    #[error("wire message too short: expected at least 4 bytes, got {0}")]
    WireMessageTooShort(usize),

    #[error("invalid wire prefix")]
    InvalidWirePrefix,

    #[error("recipient key id mismatch: wire={wire}, expected={expected}")]
    RecipientKeyIdMismatch { wire: i32, expected: i32 },

    #[error("sender hash mismatch between envelope and verified signature")]
    SenderHashMismatch,

    #[error("receiver hash mismatch between envelope and recipient key")]
    ReceiverHashMismatch,

    #[error("protobuf encode failed: {0}")]
    ProtobufEncode(String),

    #[error("protobuf decode failed: {0}")]
    ProtobufDecode(String),

    #[error("signing failed: {0}")]
    Signing(String),

    #[error("verification failed: {0}")]
    Verification(String),

    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: {0}")]
    Decryption(String),
}

/// Encodes and decodes the top-level [`DeRecMessage`] transport envelope.
///
/// In the DeRec protocol, the transport lifecycle for an envelope is:
///
/// 1. Serialize a [`DeRecMessage`] as protobuf bytes
/// 2. Sign the serialized bytes using the sender’s signing key
/// 3. Encrypt the signed payload for the receiver
/// 4. Prefix the encrypted payload with the recipient key ID
///
/// This codec implements that wire transformation in both directions.
///
/// At a high level:
///
/// - [`DeRecMessageCodec::encode`] turns a constructed envelope into a [`WireMessage`]
/// - [`DeRecMessageCodec::encode_to_bytes`] returns the raw transport bytes
/// - [`DeRecMessageCodec::decode`] turns a parsed [`WireMessage`] back into a [`DeRecMessage`]
/// - [`DeRecMessageCodec::decode_from_bytes`] parses and decodes raw transport bytes
///
/// The actual signing, verification, encryption, and decryption logic is delegated
/// to backend traits so that the codec remains protocol-correct without being tied
/// to a specific cryptographic implementation such as OpenPGP.
///
/// # Security Notes
///
/// - [`DeRecMessageCodec::encode`] validates that the sender and receiver hashes already
///   present in the envelope match the identities exposed by the signing and encryption backends.
/// - [`DeRecMessageCodec::decode`] validates the prefixed recipient key ID and verifies the
///   sender/receiver binding after decryption and signature verification.
/// - The codec assumes that the verifier returns the correct sender key hash associated with
///   the verified signature.
///
/// # Example
///
/// ```rust,ignore
/// let wire_bytes = DeRecMessageCodec::encode_to_bytes(
///     &message,
///     &signer,
///     &encrypter,
/// )?;
///
/// let decoded = DeRecMessageCodec::decode_from_bytes(
///     &wire_bytes,
///     &decrypter,
///     &verifier,
/// )?;
/// ```
pub struct DeRecMessageCodec;

impl DeRecMessageCodec {
    /// Encodes a [`DeRecMessage`] into a transportable [`WireMessage`].
    ///
    /// This method performs the protocol-prescribed sequence:
    ///
    /// 1. Serialize the protobuf envelope
    /// 2. Sign the serialized bytes with the sender signing backend
    /// 3. Encrypt the signed payload with the receiver encryption backend
    /// 4. Prefix the encrypted payload with the receiver key ID
    ///
    /// # Arguments
    ///
    /// * `message` - Fully constructed DeRec envelope to encode.
    /// * `signer` - Signing backend corresponding to the sender.
    /// * `encrypter` - Encryption backend corresponding to the receiver.
    ///
    /// # Returns
    ///
    /// On success returns a [`WireMessage`] containing:
    ///
    /// - `recipient_key_id`: the key ID that must prefix the wire payload
    /// - `payload`: the encrypted signed protobuf payload
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageCodecError`] in the following cases:
    ///
    /// - [`DeRecMessageCodecError::SenderHashMismatch`] if `message.sender` does not match the
    ///   sender hash exposed by the signer.
    /// - [`DeRecMessageCodecError::ReceiverHashMismatch`] if `message.receiver` does not match the
    ///   receiver hash exposed by the encrypter.
    /// - [`DeRecMessageCodecError::Signing`] or another backend-provided signing failure.
    /// - [`DeRecMessageCodecError::Encryption`] or another backend-provided encryption failure.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let wire = DeRecMessageCodec::encode(
    ///     &message,
    ///     &signer,
    ///     &encrypter,
    /// )?;
    /// ```
    pub fn encode<S, E>(
        message: &DeRecMessage,
        signer: &S,
        encrypter: &E,
    ) -> Result<WireMessage, DeRecMessageCodecError>
    where
        S: DeRecMessageSigner,
        E: DeRecMessageEncrypter,
    {
        if message.sender != signer.sender_key_hash() {
            return Err(DeRecMessageCodecError::SenderHashMismatch);
        }

        if message.receiver != encrypter.recipient_key_hash() {
            return Err(DeRecMessageCodecError::ReceiverHashMismatch);
        }

        let protobuf_bytes = message.encode_to_vec();

        let signed_payload = signer.sign(&protobuf_bytes)?;
        let encrypted_payload = encrypter.encrypt(&signed_payload)?;

        Ok(WireMessage {
            recipient_key_id: encrypter.recipient_key_id(),
            payload: encrypted_payload,
        })
    }

    /// Encodes a [`DeRecMessage`] directly into raw transport bytes.
    ///
    /// This is a convenience wrapper around [`DeRecMessageCodec::encode`] followed by
    /// [`WireMessage::to_bytes`].
    ///
    /// # Arguments
    ///
    /// * `message` - Fully constructed DeRec envelope to encode.
    /// * `signer` - Signing backend corresponding to the sender.
    /// * `encrypter` - Encryption backend corresponding to the receiver.
    ///
    /// # Returns
    ///
    /// On success returns the full transport byte representation:
    ///
    /// `recipient_key_id (big-endian i32) || encrypted_payload`
    ///
    /// # Errors
    ///
    /// Propagates the same errors as [`DeRecMessageCodec::encode`].
    pub fn encode_to_bytes<S, E>(
        message: &DeRecMessage,
        signer: &S,
        encrypter: &E,
    ) -> Result<Vec<u8>, DeRecMessageCodecError>
    where
        S: DeRecMessageSigner,
        E: DeRecMessageEncrypter,
    {
        Ok(Self::encode(message, signer, encrypter)?.to_bytes())
    }

    /// Decodes a parsed [`WireMessage`] back into a [`DeRecMessage`].
    ///
    /// This method performs the reverse protocol sequence:
    ///
    /// 1. Validate the prefixed recipient key ID
    /// 2. Decrypt the encrypted payload
    /// 3. Verify the signed payload
    /// 4. Decode the contained protobuf envelope
    /// 5. Validate the sender and receiver hashes against the verified identity and
    ///    the recipient key in use
    ///
    /// # Arguments
    ///
    /// * `wire_message` - Parsed wire message containing the key ID prefix and encrypted payload.
    /// * `decrypter` - Decryption backend corresponding to the recipient.
    /// * `verifier` - Signature verification backend corresponding to the sender.
    ///
    /// # Returns
    ///
    /// On success returns the decoded [`DeRecMessage`].
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageCodecError`] in the following cases:
    ///
    /// - [`DeRecMessageCodecError::RecipientKeyIdMismatch`] if the wire prefix does not match the
    ///   decrypter’s expected key ID.
    /// - [`DeRecMessageCodecError::SenderHashMismatch`] if the verified signer hash does not match
    ///   `message.sender`.
    /// - [`DeRecMessageCodecError::ReceiverHashMismatch`] if `message.receiver` does not match the
    ///   recipient key hash exposed by the decrypter.
    /// - [`DeRecMessageCodecError::Decryption`] or another backend-provided decryption failure.
    /// - [`DeRecMessageCodecError::Verification`] or another backend-provided signature verification failure.
    /// - [`DeRecMessageCodecError::ProtobufDecode`] if the verified payload is not a valid serialized
    ///   `DeRecMessage`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let decoded = DeRecMessageCodec::decode(
    ///     &wire_message,
    ///     &decrypter,
    ///     &verifier,
    /// )?;
    /// ```
    pub fn decode<D, V>(
        wire_message: &WireMessage,
        decrypter: &D,
        verifier: &V,
    ) -> Result<DeRecMessage, DeRecMessageCodecError>
    where
        D: DeRecMessageDecrypter,
        V: DeRecMessageVerifier,
    {
        if wire_message.recipient_key_id != decrypter.recipient_key_id() {
            return Err(DeRecMessageCodecError::RecipientKeyIdMismatch {
                wire: wire_message.recipient_key_id,
                expected: decrypter.recipient_key_id(),
            });
        }

        let signed_payload = decrypter.decrypt(&wire_message.payload)?;
        let verified = verifier.verify(&signed_payload)?;

        let message = DeRecMessage::decode(verified.payload.as_slice())
            .map_err(|e| DeRecMessageCodecError::ProtobufDecode(e.to_string()))?;

        if message.sender != verified.signer_key_hash {
            return Err(DeRecMessageCodecError::SenderHashMismatch);
        }

        if message.receiver != decrypter.recipient_key_hash() {
            return Err(DeRecMessageCodecError::ReceiverHashMismatch);
        }

        Ok(message)
    }

    /// Decodes raw transport bytes back into a [`DeRecMessage`].
    ///
    /// This is a convenience wrapper around [`WireMessage::from_bytes`] followed by
    /// [`DeRecMessageCodec::decode`].
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw transport bytes in the format
    ///   `recipient_key_id (big-endian i32) || encrypted_payload`.
    /// * `decrypter` - Decryption backend corresponding to the recipient.
    /// * `verifier` - Signature verification backend corresponding to the sender.
    ///
    /// # Returns
    ///
    /// On success returns the decoded [`DeRecMessage`].
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageCodecError`] if:
    ///
    /// - the wire bytes cannot be parsed as a valid [`WireMessage`]
    /// - decryption fails
    /// - signature verification fails
    /// - the verified payload is not a valid `DeRecMessage`
    /// - sender or receiver identity checks fail
    pub fn decode_from_bytes<D, V>(
        bytes: &[u8],
        decrypter: &D,
        verifier: &V,
    ) -> Result<DeRecMessage, DeRecMessageCodecError>
    where
        D: DeRecMessageDecrypter,
        V: DeRecMessageVerifier,
    {
        let wire_message = WireMessage::from_bytes(bytes)?;
        Self::decode(&wire_message, decrypter, verifier)
    }
}
