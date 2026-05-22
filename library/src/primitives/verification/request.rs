// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::*,
};
use derec_proto::{DeRecMessage, MessageBody, VerifyShareRequestMessage};
use prost::Message;
use rand::{Rng, rng};

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope with the encrypted request payload.
    pub envelope: Vec<u8>,
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// Decrypted inner [`derec_proto::VerifyShareRequestMessage`].
    pub request: VerifyShareRequestMessage,
}

/// Creates a verification request envelope to initiate the DeRec *verification* flow.
///
/// In DeRec, verification allows an Owner to challenge a Helper to prove it still holds
/// the expected share bytes. The Owner sends an encrypted
/// [`derec_proto::VerifyShareRequestMessage`] containing:
///
/// - a `version` identifying the share-distribution version being verified
/// - a `secret_id` binding the request to a specific secret
/// - a fresh `nonce` used to bind the later proof to this specific request
///
/// The request is serialized, encrypted with the already established channel shared key,
/// and wrapped in an outer plain [`derec_proto::DeRecMessage`] envelope.
///
/// The Helper is expected to compute:
///
/// `SHA384(share_content || nonce_be)`
///
/// and return that digest in a [`derec_proto::VerifyShareResponseMessage`].
///
/// # Arguments
///
/// * `channel_id` - Channel identifier for the previously paired helper.
/// * `secret_id` - Identifier of the secret whose share is being verified. Embedded into
///   the request.
/// * `version` - Distribution version to embed in the request. The responder is expected to
///   echo this value in the response.
/// * `shared_key` - Previously established 32-byte symmetric channel key used to encrypt the
///   inner verification request.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an encrypted
///   inner [`derec_proto::VerifyShareRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if outer envelope construction or symmetric encryption fails.
///
/// # Security Notes
///
/// - The nonce is generated using a cryptographically secure RNG and must be unpredictable
///   to prevent replay of previously captured responses.
/// - Only the inner protobuf message is encrypted; the outer envelope is plain.
/// - The outer envelope timestamp equals the inner request timestamp, preserving the
///   invariant `envelope.timestamp == request.timestamp`.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::verification::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let result = request::produce(
///     channel_id,
///     b"secret_id",
///     7,
///     &shared_key,
/// )
/// .expect("failed to build verification request");
///
/// assert!(!result.envelope.is_empty());
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = version))
)]
pub fn produce(
    channel_id: ChannelId,
    secret_id: u64,
    version: u32,
    shared_key: &SharedKey,
) -> Result<ProduceResult, crate::Error> {
    let mut rng = rng();

    let timestamp = current_timestamp();
    let nonce = rng.next_u64();

    let message = VerifyShareRequestMessage {
        secret_id,
        version,
        nonce,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::VerifyShareRequest(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("verification request envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes a [`derec_proto::VerifyShareRequestMessage`] from an outer
/// [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`derec_proto::VerifyShareRequestMessage`] using
///    `shared_key`
/// 3. Validates the invariant `envelope.timestamp == request.timestamp`
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::VerifyShareRequestMessage`], as produced by [`produce`].
/// * `shared_key` - Previously established 32-byte symmetric channel key used to decrypt
///   the inner message.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `request`: the decrypted inner [`derec_proto::VerifyShareRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != request.timestamp`
/// - the inner message is not a [`derec_proto::VerifyShareRequestMessage`]
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(envelope_len = envelope_bytes.len()))
)]
pub fn extract(
    envelope_bytes: &[u8],
    shared_key: &SharedKey,
) -> Result<ExtractResult, crate::Error> {
    let envelope = DeRecMessage::decode(envelope_bytes).map_err(crate::Error::ProtobufDecode)?;

    let request = match extract_inner_message(&envelope.message, shared_key)? {
        MessageBody::VerifyShareRequest(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected VerifyShareRequestMessage");
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: VerifyShareRequestMessage",
            ));
        }
    };

    if envelope.timestamp != request.timestamp {
        #[cfg(feature = "logging")]
        tracing::warn!("timestamp invariant violated");
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match request timestamp",
        ));
    }

    #[cfg(feature = "logging")]
    tracing::info!("verification request extracted and validated");

    Ok(ExtractResult { request })
}
