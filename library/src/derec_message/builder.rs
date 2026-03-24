// SPDX-License-Identifier: Apache-2.0

//! Helpers for constructing the top-level [`DeRecMessage`] protocol envelope.
//!
//! In the current DeRec protocol model, all flow messages except `ContactMessage`
//! are transported inside a [`DeRecMessage`] envelope.
//!
//! ## Design
//!
//! The outer [`DeRecMessage`] envelope carries protocol metadata such as:
//!
//! - protocol version
//! - channel ID
//! - sequence
//! - timestamp
//!
//! The `message` field contains the serialized bytes of an inner flow message.
//! In practice, those bytes are typically encrypted before being wrapped in the
//! envelope.
//!
//! ## Responsibilities
//!
//! This module is responsible for:
//!
//! - building a valid [`DeRecMessage`] protobuf envelope
//! - attaching protocol metadata
//! - enforcing, at the type level, that encryption happens before [`build`](DeRecMessageBuilder::build)
//! - restricting which encryption method can be used depending on the builder mode
//!
//! This module does **not**:
//!
//! - serialize flow-specific messages beyond encoding the provided protobuf message
//! - decrypt payloads
//! - verify signatures
//! - interpret the meaning of the inner flow message
//!
//! ## Builder modes
//!
//! The builder supports two distinct modes:
//!
//! - [`PairingMode`] for pairing-envelope encryption using [`encrypt_pairing`](DeRecMessageBuilder::<NotEncrypted, PairingMode>::encrypt_pairing)
//! - [`ChannelMode`] for channel-message encryption using [`encrypt`](DeRecMessageBuilder::<NotEncrypted, ChannelMode>::encrypt)
//!
//! The mode is part of the builder type, so the wrong encryption method cannot
//! be called by mistake.
//!
//! ## Lifecycle
//!
//! ```text
//! flow message (e.g. PairRequestMessage)
//!     ↓ serialize (protobuf)
//! encoded bytes
//!     ↓ encrypt (pairing or channel, depending on flow)
//! encrypted bytes
//!     ↓ wrap using DeRecMessageBuilder
//! DeRecMessage { message = encrypted_bytes }
//!     ↓ serialize (protobuf)
//! wire bytes
//! ```
//!
//! ## Notes
//!
//! - `ContactMessage` is not wrapped in a [`DeRecMessage`]
//! - the `message` field is treated as opaque payload bytes by this module
//! - envelope fields are used only for routing, sequencing, and protocol metadata

use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    derec_message::DeRecMessageBuilderError, protocol_version::ProtocolVersion, types::ChannelId,
};
use derec_proto::DeRecMessage;
use prost::Message;
use prost_types::Timestamp;

/// Typestate marker indicating that the payload has not yet been encrypted.
#[derive(Debug)]
pub struct NotEncrypted;

/// Typestate marker indicating that the payload has already been encrypted and
/// the envelope may be built.
#[derive(Debug)]
pub struct Encrypted;

/// Builder mode for pairing messages.
///
/// In this mode, the builder only exposes [`encrypt_pairing`](DeRecMessageBuilder::<NotEncrypted, PairingMode>::encrypt_pairing).
#[derive(Debug)]
pub struct PairingMode;

/// Builder mode for channel messages.
///
/// In this mode, the builder only exposes [`encrypt`](DeRecMessageBuilder::<NotEncrypted, ChannelMode>::encrypt).
#[derive(Debug)]
pub struct ChannelMode;

/// Builds a [`DeRecMessage`] envelope containing protocol metadata and an
/// encrypted payload.
///
/// The builder uses typestate and mode generics:
///
/// - `State` controls whether the payload is ready to build
/// - `Mode` controls which encryption method is permitted
///
/// This ensures at compile time that:
///
/// - [`build`](DeRecMessageBuilder::build) cannot be called before encryption
/// - a pairing builder cannot call channel encryption
/// - a channel builder cannot call pairing encryption
///
/// # Type parameters
///
/// * `State` - encryption state marker, typically [`NotEncrypted`] or [`Encrypted`]
/// * `Mode` - builder mode marker, either [`PairingMode`] or [`ChannelMode`]
///
/// # Required fields
///
/// Before calling [`build`](DeRecMessageBuilder::build), the builder must have:
///
/// - `channel_id`
/// - `timestamp`
/// - `message`
/// - the appropriate encryption method applied
///
/// # Typical usage
///
/// Pairing mode:
///
/// ```rust,ignore
/// let envelope = DeRecMessageBuilder::new()
///     .channel_id(channel_id)
///     .timestamp(current_timestamp())
///     .message(&pair_request)
///     .encrypt_pairing(helper_public_key)?
///     .build()?;
/// ```
///
/// Channel mode:
///
/// ```rust,ignore
/// let envelope = DeRecMessageBuilder::channel()
///     .channel_id(channel_id)
///     .timestamp(current_timestamp())
///     .message(&store_share_request)
///     .encrypt(shared_key)?
///     .build()?;
/// ```
#[derive(Debug)]
pub struct DeRecMessageBuilder<State, Mode> {
    pub(crate) sequence: Option<u32>,
    pub(crate) channel_id: Option<ChannelId>,
    pub(crate) timestamp: Option<Timestamp>,
    pub(crate) message: Vec<u8>,
    _state: PhantomData<State>,
    _mode: PhantomData<Mode>,
}

impl<State, Mode> DeRecMessageBuilder<State, Mode> {
    /// Sets the channel identifier for the envelope.
    ///
    /// In the DeRec protocol, `channel_id` identifies the logical communication
    /// channel associated with the message.
    ///
    /// # Arguments
    ///
    /// * `channel_id` - channel identifier to embed in the envelope
    ///
    /// # Returns
    ///
    /// The updated builder.
    pub fn channel_id(mut self, channel_id: ChannelId) -> Self {
        self.channel_id = Some(channel_id);
        self
    }

    /// Sets the sequence number for the envelope.
    ///
    /// The sequence number tracks message ordering and may also be used by
    /// higher-level protocol logic such as key rotation or replay detection.
    ///
    /// # Arguments
    ///
    /// * `sequence` - monotonically increasing message counter
    ///
    /// # Returns
    ///
    /// The updated builder.
    pub fn sequence(mut self, sequence: u32) -> Self {
        self.sequence = Some(sequence);
        self
    }

    /// Sets the timestamp for the envelope.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - protobuf [`Timestamp`] representing message creation time
    ///
    /// # Returns
    ///
    /// The updated builder.
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Encodes and sets the inner payload message.
    ///
    /// The provided protobuf message is serialized with `prost` and its encoded
    /// bytes become the payload later stored in the outer [`DeRecMessage`]
    /// envelope.
    ///
    /// The builder does not interpret the content of this payload. It only stores
    /// the encoded bytes.
    ///
    /// # Arguments
    ///
    /// * `message` - inner protobuf message to serialize and store
    ///
    /// # Returns
    ///
    /// The updated builder.
    pub fn message<M>(mut self, message: &M) -> Self
    where
        M: Message + Sized,
    {
        self.message = message.encode_to_vec();
        self
    }
}

impl DeRecMessageBuilder<NotEncrypted, PairingMode> {
    /// Creates a new pairing-mode [`DeRecMessageBuilder`].
    ///
    /// This constructor is intended for flows that use pairing-envelope
    /// encryption. Builders created with this constructor can call
    /// [`encrypt_pairing`](Self::encrypt_pairing) but cannot call channel
    /// encryption.
    ///
    /// # Returns
    ///
    /// A new empty builder in pairing mode.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let builder = DeRecMessageBuilder::new();
    /// ```
    pub fn pairing() -> Self {
        Self {
            sequence: None,
            channel_id: None,
            timestamp: None,
            message: Vec::new(),
            _state: PhantomData,
            _mode: PhantomData,
        }
    }

    /// Encrypts the encoded payload using pairing-envelope encryption.
    ///
    /// This method is only available on builders created in [`PairingMode`].
    /// After successful encryption, the builder transitions to the [`Encrypted`]
    /// state, enabling [`build`](DeRecMessageBuilder::build).
    ///
    /// # Arguments
    ///
    /// * `public_key` - recipient public key used for asymmetric pairing encryption
    ///
    /// # Returns
    ///
    /// On success, returns a new builder in the [`Encrypted`] state.
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageBuilderError`] if:
    ///
    /// - [`DeRecMessageBuilderError::MissingMessage`] if no payload was set
    /// - the underlying pairing encryption routine fails
    pub fn encrypt_pairing(
        self,
        public_key: impl AsRef<[u8]>,
    ) -> Result<DeRecMessageBuilder<Encrypted, PairingMode>, DeRecMessageBuilderError> {
        if self.message.is_empty() {
            return Err(DeRecMessageBuilderError::MissingMessage);
        }

        let encrypted =
            derec_cryptography::pairing::envelope::encrypt(&self.message, public_key.as_ref())?;

        Ok(DeRecMessageBuilder {
            message: encrypted,
            timestamp: self.timestamp,
            sequence: self.sequence,
            channel_id: self.channel_id,
            _state: PhantomData,
            _mode: PhantomData,
        })
    }
}

impl DeRecMessageBuilder<NotEncrypted, ChannelMode> {
    /// Creates a new channel-mode [`DeRecMessageBuilder`].
    ///
    /// This constructor is intended for flows that use symmetric channel
    /// encryption. Builders created with this constructor can call
    /// [`encrypt`](Self::encrypt) but cannot call pairing encryption.
    ///
    /// # Returns
    ///
    /// A new empty builder in channel mode.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let builder = DeRecMessageBuilder::channel();
    /// ```
    pub fn channel() -> Self {
        Self {
            sequence: None,
            channel_id: None,
            timestamp: None,
            message: Vec::new(),
            _state: PhantomData,
            _mode: PhantomData,
        }
    }

    /// Encrypts the encoded payload using channel encryption.
    ///
    /// This method is only available on builders created in [`ChannelMode`].
    /// The nonce is derived from the channel ID by placing the big-endian
    /// `u64` channel identifier into the last 8 bytes of a 32-byte nonce.
    ///
    /// After successful encryption, the builder transitions to the
    /// [`Encrypted`] state, enabling [`build`](DeRecMessageBuilder::build).
    ///
    /// # Arguments
    ///
    /// * `shared_key` - 32-byte symmetric channel key
    ///
    /// # Returns
    ///
    /// On success, returns a new builder in the [`Encrypted`] state.
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageBuilderError`] if:
    ///
    /// - [`DeRecMessageBuilderError::MissingMessage`] if no payload was set
    /// - [`DeRecMessageBuilderError::MissingChannelId`] if `channel_id` was not set
    /// - the underlying channel encryption routine fails
    pub fn encrypt(
        self,
        shared_key: &[u8; 32],
    ) -> Result<DeRecMessageBuilder<Encrypted, ChannelMode>, DeRecMessageBuilderError> {
        if self.message.is_empty() {
            return Err(DeRecMessageBuilderError::MissingMessage);
        }

        let channel_id = self
            .channel_id
            .ok_or(DeRecMessageBuilderError::MissingChannelId)?;

        let mut nonce = [0u8; 32];
        nonce[24..].copy_from_slice(&u64::from(channel_id).to_be_bytes());

        let encrypted =
            derec_cryptography::channel::encrypt_message(&self.message, shared_key, &nonce)?;

        Ok(DeRecMessageBuilder {
            message: encrypted,
            timestamp: self.timestamp,
            sequence: self.sequence,
            channel_id: Some(channel_id),
            _state: PhantomData,
            _mode: PhantomData,
        })
    }
}

impl<Mode> DeRecMessageBuilder<Encrypted, Mode> {
    /// Builds the final [`DeRecMessage`] envelope.
    ///
    /// This method is only available after one of the permitted encryption
    /// methods has been called successfully.
    ///
    /// # Returns
    ///
    /// On success returns a [`DeRecMessage`] containing:
    ///
    /// - protocol version from [`ProtocolVersion::current`]
    /// - `channel_id`
    /// - `sequence` or `0` if no sequence was set
    /// - `timestamp`
    /// - `message` containing the encrypted payload bytes
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageBuilderError`] if:
    ///
    /// - [`DeRecMessageBuilderError::MissingChannelId`] if `channel_id` was not set
    /// - [`DeRecMessageBuilderError::MissingTimestamp`] if `timestamp` was not set
    /// - [`DeRecMessageBuilderError::MissingMessage`] if the encrypted payload is empty
    ///
    /// # Notes
    ///
    /// This function does not perform any additional cryptographic validation.
    /// It only validates that the required envelope fields are present.
    pub fn build(self) -> Result<DeRecMessage, DeRecMessageBuilderError> {
        let protocol_version = ProtocolVersion::current();

        if self.timestamp.is_none() {
            return Err(DeRecMessageBuilderError::MissingTimestamp);
        }

        if self.message.is_empty() {
            return Err(DeRecMessageBuilderError::MissingMessage);
        }

        Ok(DeRecMessage {
            protocol_version_major: protocol_version.major,
            protocol_version_minor: protocol_version.minor,
            sequence: self.sequence.unwrap_or_default(),
            channel_id: self
                .channel_id
                .ok_or(DeRecMessageBuilderError::MissingChannelId)?
                .into(),
            timestamp: Some(
                self.timestamp
                    .ok_or(DeRecMessageBuilderError::MissingTimestamp)?,
            ),
            message: self.message,
        })
    }
}

/// Returns the current system time as a protobuf [`Timestamp`].
///
/// This helper converts the current system time into a UTC timestamp suitable
/// for embedding into a [`DeRecMessage`] envelope.
///
/// # Returns
///
/// A [`Timestamp`] containing:
///
/// - `seconds`: whole seconds since the Unix epoch
/// - `nanos`: nanosecond offset within the current second
///
/// # Panics
///
/// Panics if the system clock is earlier than the Unix epoch.
pub fn current_timestamp() -> Timestamp {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards");

    Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    }
}
