// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    primitives::replica_confirmation::ReplicaConfirmationError,
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecMessage, DeRecResult, MessageBody, ReplicaConfirmationResponseMessage, StatusEnum,
};
use prost::Message;

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an encrypted
    /// [`derec_proto::ReplicaConfirmationResponseMessage`].
    pub envelope: Vec<u8>,
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// The decrypted inner [`derec_proto::ReplicaConfirmationResponseMessage`].
    pub response: ReplicaConfirmationResponseMessage,
}

/// Result of [`process`].
pub struct ProcessResult {
    /// The peer's replica identifier.
    pub replica_id: i32,
}

/// Produces a replica confirmation response [`derec_proto::DeRecMessage`] envelope.
///
/// This function is executed by the party that received and verified a
/// [`derec_proto::ReplicaConfirmationRequestMessage`]. It constructs a
/// [`derec_proto::ReplicaConfirmationResponseMessage`] with an OK result and the
/// responder's `replica_id`, encrypts it with the channel shared key, and wraps
/// it in a [`derec_proto::DeRecMessage`] envelope.
///
/// After this exchange both parties know each other's `replica_id` and the
/// Replica channel is considered confirmed, enabling subsequent Channels
/// Discovery and Secret Discovery flows.
///
/// # Arguments
///
/// * `channel_id` - Channel established during Replica pairing.
/// * `shared_key` - 32-byte symmetric key from the Replica pairing.
/// * `replica_id` - Responder's replica identifier within the Owner's device set.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::ReplicaConfirmationResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if envelope construction or symmetric encryption fails.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::replica_confirmation::response;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let response::ProduceResult { envelope } =
///     response::produce(channel_id, &shared_key, 200)
///         .expect("failed to produce replica confirmation response");
///
/// assert!(!envelope.is_empty());
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, replica_id))
)]
pub fn produce(
    channel_id: ChannelId,
    shared_key: &SharedKey,
    replica_id: i32,
) -> Result<ProduceResult, crate::Error> {
    let timestamp = current_timestamp();

    let message = ReplicaConfirmationResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        replica_id,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::ReplicaConfirmationResponse(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("replica confirmation response envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes a [`derec_proto::ReplicaConfirmationResponseMessage`]
/// from an outer [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`derec_proto::ReplicaConfirmationResponseMessage`]
///    using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == response.timestamp`
///
/// Call this on the **initiator** side (the party that sent the confirmation
/// request) after receiving the peer's response. Pass the extracted response to
/// [`process`] to validate the result status and obtain the peer's `replica_id`.
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::ReplicaConfirmationResponseMessage`], as produced
///   by [`produce`].
/// * `shared_key` - 32-byte symmetric channel key established during Replica pairing.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `response`: the decrypted inner [`derec_proto::ReplicaConfirmationResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != response.timestamp`
/// - the inner message is not a [`derec_proto::ReplicaConfirmationResponseMessage`]
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::replica_confirmation::response;
///
/// let shared_key = [7u8; 32];
/// # let envelope_bytes: Vec<u8> = vec![];
///
/// let response::ExtractResult { response: resp } =
///     response::extract(&envelope_bytes, &shared_key)
///         .expect("failed to extract replica confirmation response");
///
/// assert!(resp.timestamp.is_some());
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

    let response = match extract_inner_message(&envelope.message, shared_key)? {
        MessageBody::ReplicaConfirmationResponse(m) => m,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!(
                "unexpected message type; expected ReplicaConfirmationResponseMessage"
            );
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: ReplicaConfirmationResponseMessage",
            ));
        }
    };

    if envelope.timestamp != response.timestamp {
        #[cfg(feature = "logging")]
        tracing::warn!("timestamp invariant violated");
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match response timestamp",
        ));
    }

    #[cfg(feature = "logging")]
    tracing::info!("replica confirmation response extracted and validated");

    Ok(ExtractResult { response })
}

/// Validates a replica confirmation response and extracts the peer's replica ID.
///
/// This function:
///
/// 1. Checks that the response contains a `result` field
/// 2. Validates that `result.status == Ok`
/// 3. Returns the peer's `replica_id`
///
/// Call this on the **initiator** side after [`extract`] succeeds.
///
/// # Arguments
///
/// * `response` - The decrypted inner [`derec_proto::ReplicaConfirmationResponseMessage`]
///   returned by [`extract`].
///
/// # Returns
///
/// On success returns [`ProcessResult`] containing:
///
/// - `replica_id`: the peer's replica identifier within the Owner's device set
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::ReplicaConfirmation(...)`) in
/// the following cases:
///
/// - [`ReplicaConfirmationError::MissingResult`] if the response does not contain
///   a `result` field
/// - [`ReplicaConfirmationError::NonOkStatus`] if `result.status != Ok`
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::replica_confirmation::response;
///
/// let shared_key = [7u8; 32];
/// # let envelope_bytes: Vec<u8> = vec![];
///
/// let response::ExtractResult { response: resp } =
///     response::extract(&envelope_bytes, &shared_key)
///         .expect("failed to extract");
///
/// let response::ProcessResult { replica_id } =
///     response::process(&resp)
///         .expect("peer rejected confirmation");
///
/// println!("peer replica_id: {replica_id}");
/// ```
pub fn process(
    response: &ReplicaConfirmationResponseMessage,
) -> Result<ProcessResult, crate::Error> {
    let result = response
        .result
        .as_ref()
        .ok_or(ReplicaConfirmationError::MissingResult)?;

    if result.status != StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(status = result.status, "peer returned non-OK status");
        return Err(ReplicaConfirmationError::NonOkStatus {
            status: result.status,
        }
        .into());
    }

    #[cfg(feature = "logging")]
    tracing::info!("replica confirmation response processed successfully");

    Ok(ProcessResult {
        replica_id: response.replica_id,
    })
}
