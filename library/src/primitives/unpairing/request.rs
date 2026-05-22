// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::{ChannelId, SharedKey},
};
use derec_proto::{DeRecMessage, MessageBody, UnpairRequestMessage};
use prost::Message;

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an
    /// encrypted inner [`derec_proto::UnpairRequestMessage`]. Ready to send
    /// over transport.
    pub envelope: Vec<u8>,
}

/// Result of [`extract`].
#[derive(Debug)]
pub struct ExtractResult {
    /// Decrypted inner [`derec_proto::UnpairRequestMessage`].
    pub request: UnpairRequestMessage,
}

/// Creates an unpair request envelope.
///
/// Either party — Owner or Helper — calls this to ask the counter-party to
/// drop all state associated with `channel_id`. The envelope is symmetrically
/// encrypted with the channel's `shared_key`; pairing must already be
/// complete (i.e. the symmetric key is established) for this primitive to be
/// meaningful.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier for the paired peer.
/// * `memo` - Optional human-readable reason embedded in the request. Used
///   for logging / display only; the protocol attaches no semantics to it.
///   Pass an empty string when no reason is offered.
/// * `shared_key` - 32-byte symmetric channel key established at pairing time.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes
///   carrying an encrypted inner [`derec_proto::UnpairRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if outer envelope construction or symmetric
/// encryption fails.
///
/// # Security Notes
///
/// - The outer envelope timestamp equals the inner request timestamp,
///   preserving the invariant `envelope.timestamp == request.timestamp`.
/// - The `memo` is sent in the clear inside the encrypted body; do not embed
///   secrets there.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::unpairing::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let result = request::produce(channel_id, "no longer needed", &shared_key)
///     .expect("failed to build unpair request");
///
/// assert!(!result.envelope.is_empty());
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, memo_len = memo.len()))
)]
pub fn produce(
    channel_id: ChannelId,
    memo: &str,
    shared_key: &SharedKey,
) -> Result<ProduceResult, crate::Error> {
    let timestamp = current_timestamp();

    let message = UnpairRequestMessage {
        memo: memo.to_owned(),
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::UnpairRequest(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("unpair request envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes an [`derec_proto::UnpairRequestMessage`] from an
/// outer [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from
///    `envelope_bytes`.
/// 2. Decrypts and decodes the inner [`derec_proto::UnpairRequestMessage`]
///    using `shared_key`.
/// 3. Validates the invariant `envelope.timestamp == request.timestamp`.
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes
///   carrying an encrypted inner [`derec_proto::UnpairRequestMessage`], as
///   produced by [`produce`].
/// * `shared_key` - 32-byte symmetric channel key established at pairing time.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `request`: the decrypted inner [`derec_proto::UnpairRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != request.timestamp`
/// - the inner message is not a [`derec_proto::UnpairRequestMessage`]
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
        MessageBody::UnpairRequest(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected UnpairRequestMessage");
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: UnpairRequestMessage",
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
    tracing::info!("unpair request extracted and validated");

    Ok(ExtractResult { request })
}
