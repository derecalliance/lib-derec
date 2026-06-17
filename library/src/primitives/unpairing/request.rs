// SPDX-License-Identifier: Apache-2.0

use crate::transport::TransportProtocolExt as _;
use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::{ChannelId, SharedKey},
    utils::verify_timestamps,
};
use derec_proto::{DeRecMessage, MessageBody, UnpairRequestMessage};
use prost::Message;

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an
    /// encrypted inner [`derec_proto::UnpairRequestMessage`].
    pub envelope: Vec<u8>,
}

pub struct ExtractResult {
    pub request: UnpairRequestMessage,
}

/// Produces an unpair request envelope asking the peer to drop all state
/// associated with this channel.
///
/// Either party — **Owner** or **Helper** — may call this to terminate a paired
/// channel. The envelope is symmetrically encrypted with the channel's
/// `shared_key`, so pairing must already be complete (i.e. the symmetric key
/// is established) for this primitive to be meaningful.
///
/// This function:
///
/// 1. Builds an [`derec_proto::UnpairRequestMessage`] carrying the current
///    timestamp and the application-supplied `memo`
/// 2. Serializes the inner message and encrypts it with `shared_key`
/// 3. Wraps the ciphertext into a plain outer [`derec_proto::DeRecMessage`]
///    envelope, copying the same timestamp
/// 4. Returns the serialized envelope bytes ready to send over the transport
///
/// # Arguments
///
/// * `channel_id` - Channel identifier for the paired peer.
/// * `memo` - Optional human-readable reason embedded in the request. Used
///   for logging / display only; the protocol attaches no semantics to it.
///   Pass an empty string when no reason is offered.
/// * `shared_key` - Previously established 32-byte symmetric channel key used
///   to encrypt the inner request.
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
/// ```
/// use derec_library::primitives::unpairing::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let result = request::produce(channel_id, "no longer needed", &shared_key, None)
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
    reply_to: Option<derec_proto::TransportProtocol>,
) -> Result<ProduceResult, crate::Error> {
    let timestamp = current_timestamp();

    let request = UnpairRequestMessage {
        memo: memo.to_owned(),
        timestamp: Some(timestamp),
        reply_to,
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::UnpairRequest(request))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("unpair request envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes an incoming [`derec_proto::UnpairRequestMessage`]
/// from an outer [`derec_proto::DeRecMessage`] envelope.
///
/// Call this on the **receiving** side after an unpair request envelope is
/// received over the transport. Once decrypted, the protocol layer can drop
/// its local state for the channel and reply with an unpair response.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`derec_proto::UnpairRequestMessage`]
///    using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == request.timestamp`
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes
///   carrying an encrypted inner [`derec_proto::UnpairRequestMessage`], as
///   produced by [`produce`].
/// * `shared_key` - Previously established 32-byte symmetric channel key used to
///   decrypt the inner message.
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
/// use derec_library::primitives::unpairing::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let request::ProduceResult { envelope } =
///     request::produce(channel_id, "no longer needed", &shared_key)
///         .expect("failed to build unpair request");
///
/// let request::ExtractResult { request } =
///     request::extract(&envelope, &shared_key).expect("failed to extract");
///
/// assert_eq!(request.memo, "no longer needed");
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
        MessageBody::UnpairRequest(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected UnpairRequestMessage");

            return Err(crate::Error::Invariant(
                "Invalid message. Expected: UnpairRequestMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, request.timestamp)?;

    if let Some(reply_to) = request.reply_to.as_ref() {
        reply_to.validate()?;
    }

    #[cfg(feature = "logging")]
    tracing::info!("unpair request extracted and validated");

    Ok(ExtractResult { request })
}
