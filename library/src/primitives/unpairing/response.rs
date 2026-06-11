// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    primitives::unpairing::UnpairingError,
    types::{ChannelId, SharedKey},
    utils::verify_timestamps,
};
use derec_proto::{DeRecMessage, DeRecResult, MessageBody, StatusEnum, UnpairResponseMessage};
use prost::Message;

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an
    /// encrypted inner [`derec_proto::UnpairResponseMessage`].
    pub envelope: Vec<u8>,
}

pub struct ExtractResult {
    pub response: UnpairResponseMessage,
}

pub struct ProcessResult {
    pub acknowledged: bool,
}

/// Produces a **successful** unpair acknowledgement envelope on the responder side.
///
/// Called by the party that **received** an [`derec_proto::UnpairRequestMessage`]
/// after it has dropped (or is about to drop) its local state for the
/// channel. The envelope carries `result.status == StatusEnum::Ok` with an
/// empty `memo`.
///
/// Deletion of local state is **not** performed by this primitive — it lives
/// at the [`crate::protocol`] orchestrator layer.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier for the requesting peer.
/// * `shared_key` - 32-byte symmetric channel key.
///
/// # Errors
///
/// Returns [`crate::Error`] if outer envelope construction or encryption fails.
///
/// # Example
///
/// ```
/// use derec_library::primitives::unpairing::response;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let response::ProduceResult { envelope } = response::produce(channel_id, &shared_key)
///     .expect("failed to build unpair response");
///
/// assert!(!envelope.is_empty());
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub fn produce(
    channel_id: ChannelId,
    shared_key: &SharedKey,
) -> Result<ProduceResult, crate::Error> {
    let envelope = build_response(channel_id, StatusEnum::Ok, "", shared_key)?;

    #[cfg(feature = "logging")]
    tracing::info!("unpair response (ok) envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes an [`derec_proto::UnpairResponseMessage`] from an
/// outer [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from
///    `envelope_bytes`.
/// 2. Decrypts and decodes the inner [`derec_proto::UnpairResponseMessage`]
///    using `shared_key`.
/// 3. Validates the invariant `envelope.timestamp == response.timestamp`.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != response.timestamp`
/// - the inner message is not a [`derec_proto::UnpairResponseMessage`]
///
/// # Example
///
/// ```
/// use derec_library::primitives::unpairing::{request, response};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// // Initiator: send an unpair request.
/// let request::ProduceResult { envelope: req_envelope } =
///     request::produce(channel_id, "no longer needed", &shared_key)
///         .expect("produce request failed");
///
/// // Responder: extract and ack with a successful response.
/// let _ = request::extract(&req_envelope, &shared_key).expect("extract request failed");
/// let response::ProduceResult { envelope: resp_envelope } =
///     response::produce(channel_id, &shared_key).expect("produce response failed");
///
/// // Initiator: extract the response.
/// let response::ExtractResult { response: ack } =
///     response::extract(&resp_envelope, &shared_key).expect("extract response failed");
///
/// assert!(ack.result.is_some());
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
        MessageBody::UnpairResponse(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected UnpairResponseMessage");
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: UnpairResponseMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, response.timestamp)?;

    #[cfg(feature = "logging")]
    tracing::info!("unpair response extracted and validated");

    Ok(ExtractResult { response })
}

/// Verifies the result field of a decoded [`derec_proto::UnpairResponseMessage`]
/// and reports whether the responder acknowledged the unpair.
///
/// - `Ok(ProcessResult { acknowledged: true })` — the responder reports
///   success (`result.status == StatusEnum::Ok`).
/// - `Err(UnpairingError::NonOkStatus { … })` — the responder rejected the
///   unpair; carries the peer's status code and memo.
/// - `Err(crate::Error::Invariant(_))` — the response carried no result.
///
/// The initiator's [`crate::protocol`] orchestrator uses the outcome to
/// decide whether to delete its own local state (success) or surface a
/// rejection event to the application.
///
/// # Example
///
/// ```
/// use derec_library::primitives::unpairing::{request, response};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// // Initiator → Responder → Initiator roundtrip.
/// let request::ProduceResult { envelope: req_envelope } =
///     request::produce(channel_id, "no longer needed", &shared_key)
///         .expect("produce request failed");
/// let _ = request::extract(&req_envelope, &shared_key).expect("extract request failed");
/// let response::ProduceResult { envelope: resp_envelope } =
///     response::produce(channel_id, &shared_key).expect("produce response failed");
/// let response::ExtractResult { response: ack } =
///     response::extract(&resp_envelope, &shared_key).expect("extract response failed");
///
/// let response::ProcessResult { acknowledged } =
///     response::process(&ack).expect("process failed");
///
/// assert!(acknowledged);
/// ```
#[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
pub fn process(response: &UnpairResponseMessage) -> Result<ProcessResult, crate::Error> {
    let result = response.result.as_ref().ok_or(crate::Error::Invariant(
        "UnpairResponseMessage is missing result field",
    ))?;

    if result.status != StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(
            status = result.status,
            memo = %result.memo,
            "unpair response status is not Ok"
        );
        return Err(UnpairingError::NonOkStatus {
            status: result.status,
            memo: result.memo.to_owned(),
        }
        .into());
    }

    #[cfg(feature = "logging")]
    tracing::info!("unpair response acknowledged");

    Ok(ProcessResult { acknowledged: true })
}

fn build_response(
    channel_id: ChannelId,
    status: StatusEnum,
    memo: &str,
    shared_key: &SharedKey,
) -> Result<Vec<u8>, crate::Error> {
    let timestamp = current_timestamp();

    let response = UnpairResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::UnpairResponse(response))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    Ok(envelope)
}
