// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::{ChannelId, SharedKey},
    utils::verify_timestamps,
};
use derec_proto::{DeRecMessage, GetShareRequestMessage, MessageBody};
use prost::Message;

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope with the encrypted request payload.
    pub envelope: Vec<u8>,
}

pub struct ExtractResult {
    pub request: GetShareRequestMessage,
}

/// Produces a recovery request envelope for a specific `(secret_id, version)` share.
///
/// In the DeRec recovery flow, the recovering Owner requests one share from each Helper.
/// The request identifies:
///
/// - `secret_id`: which secret is being recovered
/// - `version`: which version of that secret is being recovered
///
/// The request is serialized, encrypted with the already established channel shared key,
/// and wrapped in a plain outer [`derec_proto::DeRecMessage`] envelope.
///
/// # Arguments
///
/// * `channel_id` - Identifier of the previously paired Helper channel.
/// * `secret_id` - Identifier of the secret being recovered.
/// * `version` - Version number of the secret share to request.
/// * `shared_key` - Previously established 32-byte symmetric channel key used to encrypt
///   the inner request.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an encrypted
///   inner [`derec_proto::GetShareRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if outer envelope construction or symmetric encryption fails.
///
/// # Security Notes
///
/// - This request does not contain secret material; it only identifies which share is requested.
///
/// # Example
///
/// ```
/// use derec_library::primitives::recovery::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let result = request::produce(channel_id, 1, 1, &shared_key, None)
///     .expect("failed to build recovery request");
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
    reply_to: Option<derec_proto::TransportProtocol>,
) -> Result<ProduceResult, crate::Error> {
    let timestamp = current_timestamp();

    let message = GetShareRequestMessage {
        secret_id,
        version,
        timestamp: Some(timestamp),
        reply_to,
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetShareRequest(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("recovery request envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes an incoming [`derec_proto::GetShareRequestMessage`] from an outer
/// [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`derec_proto::GetShareRequestMessage`] using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == request.timestamp`
///
/// Call this on the **Helper** side after receiving a recovery request envelope. The decrypted
/// request can then be passed to [`super::response::produce`] to build a response.
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::GetShareRequestMessage`], as produced by [`produce`].
/// * `shared_key` - Previously established 32-byte symmetric channel key used to decrypt
///   the inner message.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `request`: the decrypted inner [`derec_proto::GetShareRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != request.timestamp`
/// - the inner message is not a [`derec_proto::GetShareRequestMessage`]
///
/// # Security: no freshness or replay protection
///
/// The timestamp check enforced here only binds the envelope to the
/// inner body (`envelope.timestamp == body.timestamp`). It does NOT
/// enforce a freshness window against the receiver's clock and does
/// NOT detect replays of a previously-captured ciphertext. Because
/// the channel key is long-lived, a recorded envelope stays
/// decryptable indefinitely. Callers MUST add a freshness window
/// and per-channel anti-replay (monotonic counter or nonce log) on
/// top before driving any side-effecting state off the parsed body.
///
/// # Example
///
/// ```
/// use derec_library::primitives::recovery::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let request::ProduceResult { envelope } = request::produce(channel_id, 1, 1, &shared_key)
///     .expect("failed to build recovery request");
///
/// let request::ExtractResult { request } = request::extract(&envelope, &shared_key)
///     .expect("failed to extract recovery request");
///
/// assert_eq!(request.secret_id, 1);
/// assert_eq!(request.version, 1);
/// ```
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
        MessageBody::GetShareRequest(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected GetShareRequestMessage");

            return Err(crate::Error::Invariant(
                "Invalid message. Expected: GetShareRequestMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, request.timestamp)?;

    #[cfg(feature = "logging")]
    tracing::info!("recovery request extracted and validated");

    Ok(ExtractResult { request })
}
