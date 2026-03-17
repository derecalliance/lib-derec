//! Helpers for constructing and encoding the top-level [`DeRecMessage`] protocol envelope.
//!
//! In the DeRec protocol, all flow messages except `ContactMessage` are transported inside a
//! [`DeRecMessage`] envelope. This module provides two main helpers:
//!
//! - [`DeRecMessageBuilder`] for constructing the protobuf envelope
//! - [`DeRecMessageCodec`] for turning the envelope into wire bytes and back
//!
//! The intended lifecycle is:
//!
//! 1. Produce a flow message such as [`PairRequestMessage`] or [`StoreShareRequestMessage`]
//! 2. Wrap it in a [`DeRecMessage`] using [`DeRecMessageBuilder`]
//! 3. Serialize, sign, and encrypt it using [`DeRecMessageCodec`]
//! 4. Send the resulting wire bytes through the chosen transport
//!
//! This module does **not** define the cryptographic backend. Instead, the codec relies on traits
//! that can be implemented by an OpenPGP-based or equivalent crypto layer.

use crate::protocol_version::ProtocolVersion;
use derec_proto::{
    DeRecMessage, ErrorResponseMessage, GetSecretIdsVersionsRequestMessage,
    GetSecretIdsVersionsResponseMessage, GetShareRequestMessage, GetShareResponseMessage,
    PairRequestMessage, PairResponseMessage, StoreShareRequestMessage, StoreShareResponseMessage,
    UnpairRequestMessage, UnpairResponseMessage, VerifyShareRequestMessage,
    VerifyShareResponseMessage,
};
use prost_types::Timestamp;
use std::fmt;
use std::time::SystemTime;

/// Errors that can occur while constructing a [`DeRecMessage`] with
/// [`DeRecMessageBuilder`].
///
/// These errors represent missing required envelope fields or structural
/// violations such as mixing Owner-side and Helper-side message bodies
/// in the same envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeRecMessageBuilderError {
    MissingSender,
    MissingReceiver,
    MissingSecretId,
    MissingTimestamp,
    MissingMessageBodies,
    MixedMessageSides,
    InvalidSecretIdLength(usize),
    InvalidTimestamp(SystemTime),
}

impl fmt::Display for DeRecMessageBuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSender => write!(f, "missing sender"),
            Self::MissingReceiver => write!(f, "missing receiver"),
            Self::MissingSecretId => write!(f, "missing secret_id"),
            Self::MissingTimestamp => write!(f, "missing timestamp"),
            Self::MissingMessageBodies => write!(f, "missing message bodies"),
            Self::MixedMessageSides => {
                write!(
                    f,
                    "cannot mix owner and helper message bodies in one DeRecMessage"
                )
            }
            Self::InvalidSecretIdLength(len) => {
                write!(f, "secret_id must be between 1 and 16 bytes, got {len}")
            }
            Self::InvalidTimestamp(system_time) => {
                write!(
                    f,
                    "failed to convert SystemTime {:?} into protobuf Timestamp",
                    system_time
                )
            }
        }
    }
}

impl std::error::Error for DeRecMessageBuilderError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeSide {
    Owner,
    Helper,
}

pub enum DeRecEnvelopeBody {
    Owner(OwnerEnvelopeBody),
    Helper(HelperEnvelopeBody),
}

pub enum OwnerEnvelopeBody {
    Pair(PairRequestMessage),
    Unpair(UnpairRequestMessage),
    StoreShare(StoreShareRequestMessage),
    VerifyShare(VerifyShareRequestMessage),
    GetSecretIdsVersions(GetSecretIdsVersionsRequestMessage),
    GetShare(GetShareRequestMessage),
}

pub enum HelperEnvelopeBody {
    Pair(PairResponseMessage),
    Unpair(UnpairResponseMessage),
    StoreShare(StoreShareResponseMessage),
    VerifyShare(VerifyShareResponseMessage),
    GetSecretIdsVersions(GetSecretIdsVersionsResponseMessage),
    GetShare(GetShareResponseMessage),
    Error(ErrorResponseMessage),
}

macro_rules! impl_owner_message_from {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for DeRecEnvelopeBody {
            fn from(value: $ty) -> Self {
                Self::Owner(OwnerEnvelopeBody::$variant(value))
            }
        }
    };
}

macro_rules! impl_helper_message_from {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for DeRecEnvelopeBody {
            fn from(value: $ty) -> Self {
                Self::Helper(HelperEnvelopeBody::$variant(value))
            }
        }
    };
}

impl_owner_message_from!(PairRequestMessage, Pair);
impl_owner_message_from!(UnpairRequestMessage, Unpair);
impl_owner_message_from!(StoreShareRequestMessage, StoreShare);
impl_owner_message_from!(VerifyShareRequestMessage, VerifyShare);
impl_owner_message_from!(GetSecretIdsVersionsRequestMessage, GetSecretIdsVersions);
impl_owner_message_from!(GetShareRequestMessage, GetShare);

impl_helper_message_from!(PairResponseMessage, Pair);
impl_helper_message_from!(UnpairResponseMessage, Unpair);
impl_helper_message_from!(StoreShareResponseMessage, StoreShare);
impl_helper_message_from!(VerifyShareResponseMessage, VerifyShare);
impl_helper_message_from!(GetSecretIdsVersionsResponseMessage, GetSecretIdsVersions);
impl_helper_message_from!(GetShareResponseMessage, GetShare);
impl_helper_message_from!(ErrorResponseMessage, Error);

impl OwnerEnvelopeBody {
    fn into_proto(self) -> derec_proto::de_rec_message::SharerMessageBody {
        use derec_proto::de_rec_message::sharer_message_body::Body;

        let body = match self {
            Self::Pair(v) => Body::PairRequestMessage(v),
            Self::Unpair(v) => Body::UnpairRequestMessage(v),
            Self::StoreShare(v) => Body::StoreShareRequestMessage(v),
            Self::VerifyShare(v) => Body::VerifyShareRequestMessage(v),
            Self::GetSecretIdsVersions(v) => Body::GetSecretIdsVersionsRequestMessage(v),
            Self::GetShare(v) => Body::GetShareRequestMessage(v),
        };

        derec_proto::de_rec_message::SharerMessageBody { body: Some(body) }
    }
}

impl HelperEnvelopeBody {
    fn into_proto(self) -> derec_proto::de_rec_message::HelperMessageBody {
        use derec_proto::de_rec_message::helper_message_body::Body;

        let body = match self {
            Self::Pair(v) => Body::PairResponseMessage(v),
            Self::Unpair(v) => Body::UnpairResponseMessage(v),
            Self::StoreShare(v) => Body::StoreShareResponseMessage(v),
            Self::VerifyShare(v) => Body::VerifyShareResponseMessage(v),
            Self::GetSecretIdsVersions(v) => Body::GetSecretIdsVersionsResponseMessage(v),
            Self::GetShare(v) => Body::GetShareResponseMessage(v),
            Self::Error(v) => Body::ErrorResponseMessage(v),
        };

        derec_proto::de_rec_message::HelperMessageBody { body: Some(body) }
    }
}

/// Builds a top-level [`DeRecMessage`] envelope around one or more DeRec flow messages.
///
/// In the DeRec protocol, all protocol messages except `ContactMessage` must be wrapped in a
/// [`DeRecMessage`] before they are serialized, signed, encrypted, and sent through the wire.
///
/// This builder is responsible only for constructing the protobuf envelope. It does **not**
/// perform any cryptographic processing. Once the envelope is built, it can be passed to
/// [`DeRecMessageCodec`] for serialization and transport encoding.
///
/// At a high level, the builder performs the following steps:
///
/// 1. Capture the sender and receiver key identifiers (SHA-384 hashes of public keys)
/// 2. Set the protocol metadata such as secret ID and timestamp
/// 3. Collect one or more Owner-side or Helper-side flow messages
/// 4. Validate that the envelope is structurally consistent
/// 5. Produce the final [`DeRecMessage`]
///
/// # Notes
///
/// * `ContactMessage` is intentionally **not** supported because it is the only DeRec message
///   that is exchanged out-of-band and not wrapped in a `DeRecMessage`.
/// * A single envelope may contain multiple message bodies, but they must all belong to the same
///   side: either **Owner** or **Helper**.
/// * [`DeRecMessageBuilder::new`] does **not** assign a timestamp automatically.
///   The timestamp must be provided explicitly via [`DeRecMessageBuilder::timestamp`]
///   or injected by higher-level bindings (e.g. WASM).
/// * The builder will fail at [`DeRecMessageBuilder::build`] if no timestamp is set.
/// * The current protocol version is automatically taken from [`ProtocolVersion::current`].
///
/// # Example
///
/// ```rust,ignore
/// use derec_library::derec_message::DeRecMessageBuilder;
/// use prost_types::Timestamp;
///
/// let envelope = DeRecMessageBuilder::new()
///     .sender(sender_hash)
///     .receiver(receiver_hash)
///     .secret_id(secret_id)?
///     .timestamp(Timestamp {
///         seconds: 1700000000,
///         nanos: 0,
///     })
///     .message(pair_request_message)?
///     .build()?;
/// ```
#[derive(Debug)]
pub struct DeRecMessageBuilder {
    pub(crate) sender: Option<Vec<u8>>,
    pub(crate) receiver: Option<Vec<u8>>,
    pub(crate) secret_id: Option<Vec<u8>>,
    pub(crate) timestamp: Option<Timestamp>,
    pub(crate) side: Option<EnvelopeSide>,
    pub(crate) sharer_bodies: Vec<derec_proto::de_rec_message::SharerMessageBody>,
    pub(crate) helper_bodies: Vec<derec_proto::de_rec_message::HelperMessageBody>,
}

impl DeRecMessageBuilder {
    /// Creates a new [`DeRecMessageBuilder`] with the current system time as the default timestamp.
    ///
    /// # Returns
    ///
    /// Returns a new empty builder with:
    ///
    /// - no sender or receiver hashes set
    /// - no secret ID set
    /// - no message bodies yet attached
    ///
    /// # Example
    ///
    /// ```rust
    /// use derec_library::derec_message::DeRecMessageBuilder;
    ///
    /// let builder = DeRecMessageBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            sender: None,
            receiver: None,
            secret_id: None,
            timestamp: None,
            side: None,
            sharer_bodies: Vec::new(),
            helper_bodies: Vec::new(),
        }
    }

    /// Sets the sender key identifier.
    ///
    /// The protocol expects `sender` to contain the SHA-384 hash of the sender’s public key.
    /// This value is later used by the recipient to identify the sender and validate that
    /// the signed payload corresponds to the expected public key.
    ///
    /// # Arguments
    ///
    /// * `sender` - SHA-384 hash of the sender’s public key.
    ///
    /// # Returns
    ///
    /// Returns the builder with the sender field set.
    pub fn sender(mut self, sender: impl AsRef<[u8]>) -> Self {
        self.sender = Some(sender.as_ref().to_vec());
        self
    }

    /// Sets the receiver key identifier.
    ///
    /// The protocol expects `receiver` to contain the SHA-384 hash of the receiver’s public key.
    /// This protects against signature-replacement attacks by binding the message to the intended
    /// recipient.
    ///
    /// # Arguments
    ///
    /// * `receiver` - SHA-384 hash of the receiver’s public key.
    ///
    /// # Returns
    ///
    /// Returns the builder with the receiver field set.
    pub fn receiver(mut self, receiver: impl AsRef<[u8]>) -> Self {
        self.receiver = Some(receiver.as_ref().to_vec());
        self
    }

    /// Sets the secret identifier for the envelope.
    ///
    /// In the DeRec protocol, `secretId` must have a length from 1 to 16 bytes and uniquely
    /// identify a secret created by a sharer/owner.
    ///
    /// # Arguments
    ///
    /// * `secret_id` - Secret ID bytes to place in the envelope.
    ///
    /// # Returns
    ///
    /// Returns the updated builder on success.
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageBuilderError::InvalidSecretIdLength`] if the provided secret ID is
    /// not between 1 and 16 bytes long.
    pub fn secret_id(
        mut self,
        secret_id: impl AsRef<[u8]>,
    ) -> Result<Self, DeRecMessageBuilderError> {
        let secret_id = secret_id.as_ref();

        if !(1..=16).contains(&secret_id.len()) {
            return Err(DeRecMessageBuilderError::InvalidSecretIdLength(
                secret_id.len(),
            ));
        }

        self.secret_id = Some(secret_id.to_vec());
        Ok(self)
    }

    /// Overrides the envelope timestamp with an explicit protobuf [`Timestamp`].
    ///
    /// This is useful in tests or when the caller wants full control over the timestamp value
    /// rather than using the default current system time.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Explicit protobuf timestamp to attach to the envelope.
    ///
    /// # Returns
    ///
    /// Returns the builder with the timestamp replaced.
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Adds a protocol message body to the envelope.
    ///
    /// This method accepts any supported flow message that can legally appear inside a
    /// [`DeRecMessage`]. The builder automatically places the message into the appropriate
    /// Owner-side or Helper-side repeated body list.
    ///
    /// # Arguments
    ///
    /// * `message` - Any supported DeRec flow message that implements `Into<DeRecEnvelopeBody>`.
    ///
    /// # Returns
    ///
    /// Returns the updated builder on success.
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageBuilderError::MixedMessageSides`] if the caller attempts to mix
    /// Owner-side and Helper-side message bodies in the same envelope.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let builder = DeRecMessageBuilder::new()
    ///     .sender(sender_hash)
    ///     .receiver(receiver_hash)
    ///     .secret_id(secret_id)?
    ///     .message(pair_request_message)?;
    /// ```
    pub fn message<M>(mut self, message: M) -> Result<Self, DeRecMessageBuilderError>
    where
        M: Into<DeRecEnvelopeBody>,
    {
        match message.into() {
            DeRecEnvelopeBody::Owner(body) => {
                if self.side == Some(EnvelopeSide::Helper) {
                    return Err(DeRecMessageBuilderError::MixedMessageSides);
                }

                self.side = Some(EnvelopeSide::Owner);
                self.sharer_bodies.push(body.into_proto());
            }
            DeRecEnvelopeBody::Helper(body) => {
                if self.side == Some(EnvelopeSide::Owner) {
                    return Err(DeRecMessageBuilderError::MixedMessageSides);
                }

                self.side = Some(EnvelopeSide::Helper);
                self.helper_bodies.push(body.into_proto());
            }
        }

        Ok(self)
    }

    /// Builds the final [`DeRecMessage`] envelope.
    ///
    /// This finalizes the builder state, validates that all required envelope fields are present,
    /// and assembles the corresponding protobuf `messageBodies` structure.
    ///
    /// # Returns
    ///
    /// On success returns a [`DeRecMessage`] containing:
    ///
    /// - `protocol_version_major` and `protocol_version_minor` from
    ///   [`ProtocolVersion::current`]
    /// - the configured `sender`, `receiver`, `secret_id`, and `timestamp`
    /// - one or more Owner-side or Helper-side message bodies
    ///
    /// # Errors
    ///
    /// Returns [`DeRecMessageBuilderError`] in the following cases:
    ///
    /// - [`DeRecMessageBuilderError::MissingSender`] if the sender hash was not set
    /// - [`DeRecMessageBuilderError::MissingReceiver`] if the receiver hash was not set
    /// - [`DeRecMessageBuilderError::MissingSecretId`] if the secret ID was not set
    /// - [`DeRecMessageBuilderError::MissingTimestamp`] if the timestamp is absent
    /// - [`DeRecMessageBuilderError::MissingMessageBodies`] if no message body was added
    ///
    /// # Security Notes
    ///
    /// - `sender` and `receiver` should be derived from the correct public keys before calling
    ///   `build`, since they are later used by the codec to enforce sender/receiver binding.
    /// - This method does not perform signing or encryption. Those operations belong to
    ///   [`DeRecMessageCodec`].
    pub fn build(self) -> Result<DeRecMessage, DeRecMessageBuilderError> {
        let protocol_version = ProtocolVersion::current();

        if self.timestamp.is_none() {
            return Err(DeRecMessageBuilderError::MissingTimestamp);
        }

        let message_bodies = match self.side {
            Some(EnvelopeSide::Owner) => {
                let sharer_message_bodies = derec_proto::de_rec_message::SharerMessageBodies {
                    sharer_message_body: self.sharer_bodies,
                };

                derec_proto::de_rec_message::MessageBodies {
                    messages: Some(
                        derec_proto::de_rec_message::message_bodies::Messages::SharerMessageBodies(
                            sharer_message_bodies,
                        ),
                    ),
                }
            }
            Some(EnvelopeSide::Helper) => {
                let helper_message_bodies = derec_proto::de_rec_message::HelperMessageBodies {
                    helper_message_body: self.helper_bodies,
                };

                derec_proto::de_rec_message::MessageBodies {
                    messages: Some(
                        derec_proto::de_rec_message::message_bodies::Messages::HelperMessageBodies(
                            helper_message_bodies,
                        ),
                    ),
                }
            }
            None => return Err(DeRecMessageBuilderError::MissingMessageBodies),
        };

        Ok(DeRecMessage {
            protocol_version_major: protocol_version.major,
            protocol_version_minor: protocol_version.minor,
            sender: self.sender.ok_or(DeRecMessageBuilderError::MissingSender)?,
            receiver: self
                .receiver
                .ok_or(DeRecMessageBuilderError::MissingReceiver)?,
            secret_id: self
                .secret_id
                .ok_or(DeRecMessageBuilderError::MissingSecretId)?,
            timestamp: Some(
                self.timestamp
                    .ok_or(DeRecMessageBuilderError::MissingTimestamp)?,
            ),
            message_bodies: Some(message_bodies),
        })
    }
}

impl Default for DeRecMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}
