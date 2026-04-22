// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::{ChannelId, SharedKey},
};
use derec_proto::{DeRecMessage, MessageBody, ReplicaChannelsDiscoveryRequestMessage};
use prost::Message;

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an encrypted
    /// [`derec_proto::ReplicaChannelsDiscoveryRequestMessage`].
    pub envelope: Vec<u8>,
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// The decrypted inner [`derec_proto::ReplicaChannelsDiscoveryRequestMessage`].
    pub request: ReplicaChannelsDiscoveryRequestMessage,
}

/// Produces a channels discovery request [`derec_proto::DeRecMessage`] envelope.
///
/// After a Replica has been confirmed, it sends this request to the Owner to
/// learn about all existing Helper channels. Because the number of channels may
/// be large, the response is paginated — the `last_batch_index` parameter tells
/// the Owner which batch to send next.
///
/// # Arguments
///
/// * `channel_id` - Owner↔Replica channel established during Replica pairing.
/// * `shared_key` - 32-byte symmetric key for the Owner↔Replica channel.
/// * `last_batch_index` - Index of the last batch the Replica has successfully
///   received. Use `0` for the initial request.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::ReplicaChannelsDiscoveryRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if envelope construction or symmetric encryption fails.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::channels_discovery::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let request::ProduceResult { envelope } =
///     request::produce(channel_id, &shared_key, 0)
///         .expect("failed to produce channels discovery request");
///
/// assert!(!envelope.is_empty());
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, last_batch_index))
)]
pub fn produce(
    channel_id: ChannelId,
    shared_key: &SharedKey,
    last_batch_index: i32,
) -> Result<ProduceResult, crate::Error> {
    let timestamp = current_timestamp();

    let message = ReplicaChannelsDiscoveryRequestMessage {
        last_batch_index,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::ReplicaChannelsDiscoveryRequest(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("channels discovery request envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes a [`derec_proto::ReplicaChannelsDiscoveryRequestMessage`]
/// from an outer [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner
///    [`derec_proto::ReplicaChannelsDiscoveryRequestMessage`] using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == request.timestamp`
///
/// Call this on the **Owner** side after receiving a channels discovery request
/// from a confirmed Replica. The Owner should then enumerate all active Helper
/// channels and pass them to [`super::response::produce`].
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::ReplicaChannelsDiscoveryRequestMessage`], as
///   produced by [`produce`].
/// * `shared_key` - 32-byte symmetric key for the Owner↔Replica channel.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `request`: the decrypted inner
///   [`derec_proto::ReplicaChannelsDiscoveryRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != request.timestamp`
/// - the inner message is not a
///   [`derec_proto::ReplicaChannelsDiscoveryRequestMessage`]
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::channels_discovery::request;
///
/// let shared_key = [7u8; 32];
/// # let envelope_bytes: Vec<u8> = vec![];
///
/// let request::ExtractResult { request: req } =
///     request::extract(&envelope_bytes, &shared_key)
///         .expect("failed to extract channels discovery request");
///
/// println!("replica asks for batch after index {}", req.last_batch_index);
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
        MessageBody::ReplicaChannelsDiscoveryRequest(m) => m,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!(
                "unexpected message type; expected ReplicaChannelsDiscoveryRequestMessage"
            );
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: ReplicaChannelsDiscoveryRequestMessage",
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
    tracing::info!("channels discovery request extracted and validated");

    Ok(ExtractResult { request })
}
