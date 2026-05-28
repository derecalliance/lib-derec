// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::{ChannelId, SharedKey},
    utils::verify_timestamps,
};
use derec_proto::{DeRecMessage, GetSecretIdsVersionsRequestMessage, MessageBody};
use prost::Message;

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an encrypted
    /// [`derec_proto::GetSecretIdsVersionsRequestMessage`].
    pub envelope: Vec<u8>,
}

pub struct ExtractResult {
    pub request: GetSecretIdsVersionsRequestMessage,
}

/// Produces a discovery request envelope asking a Helper which secret IDs and
/// versions it holds for this Owner.
///
/// In the DeRec discovery flow, the recovering Owner sends this request to each
/// Helper immediately after re-pairing. Because the Owner may have lost their
/// local state, they cannot know which secrets each Helper stores. This request
/// triggers a [`derec_proto::GetSecretIdsVersionsResponseMessage`] reply that
/// lists all stored `(secret_id, versions)` pairs.
///
/// The request contains only a timestamp — no secret material is included.
/// The [`derec_proto::GetSecretIdsVersionsRequestMessage`] is encrypted with the
/// already-established channel shared key and wrapped in a plain outer
/// [`derec_proto::DeRecMessage`] envelope.
///
/// # Arguments
///
/// * `channel_id` - Identifier of the previously paired Helper channel.
/// * `shared_key` - Previously established 32-byte symmetric channel key used to
///   encrypt the inner request.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::GetSecretIdsVersionsRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if outer envelope construction or symmetric encryption fails.
///
/// # Pre-requisites
///
/// The `channel_id` used for this request is a brand new one Owner and Helper just established.
/// The Owner is usually in recovery-mode when this flow triggers. This means that the Helper
/// must have already linked this new `channel_id` with previous Owner's channel_ids. Otherwise the
/// Helper will not be able to return old secrets and versions for the Owner
///
/// # Security Notes
///
/// This request does not contain secret material; it only signals that the Owner
/// wants the Helper to list the secrets it stores for this channel.
///
/// # Example
///
/// ```
/// use derec_library::primitives::discovery::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let result = request::produce(channel_id, &shared_key)
///     .expect("failed to build discovery request");
///
/// assert!(!result.envelope.is_empty());
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub fn produce(
    channel_id: ChannelId,
    shared_key: &SharedKey,
) -> Result<ProduceResult, crate::Error> {
    let timestamp = current_timestamp();

    let message = GetSecretIdsVersionsRequestMessage {
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetSecretIdsVersionsRequest(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("discovery request envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes an incoming [`derec_proto::GetSecretIdsVersionsRequestMessage`]
/// from an outer [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`derec_proto::GetSecretIdsVersionsRequestMessage`]
///    using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == request.timestamp`
///
/// Call this on the **Helper** side after receiving a discovery request envelope.
/// The Helper should then enumerate all `(secret_id, versions)` it holds for this
/// channel and pass them to [`super::response::produce`].
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::GetSecretIdsVersionsRequestMessage`], as produced
///   by [`produce`].
/// * `shared_key` - Previously established 32-byte symmetric channel key used to decrypt
///   the inner message.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `request`: the decrypted inner [`derec_proto::GetSecretIdsVersionsRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != request.timestamp`
/// - the inner message is not a [`derec_proto::GetSecretIdsVersionsRequestMessage`]
///
/// # Example
///
/// ```
/// use derec_library::primitives::discovery::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let request::ProduceResult { envelope } = request::produce(channel_id, &shared_key)
///     .expect("failed to build discovery request");
///
/// let request::ExtractResult { request } = request::extract(&envelope, &shared_key)
///     .expect("failed to extract discovery request");
///
/// assert!(request.timestamp.is_some());
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
        MessageBody::GetSecretIdsVersionsRequest(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected GetSecretIdsVersionsRequestMessage");

            return Err(crate::Error::Invariant(
                "Invalid message. Expected: GetSecretIdsVersionsRequestMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, request.timestamp)?;

    #[cfg(feature = "logging")]
    tracing::info!("discovery request extracted and validated");

    Ok(ExtractResult { request })
}
