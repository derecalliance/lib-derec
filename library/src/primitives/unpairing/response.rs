// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    primitives::unpairing::error::UnpairingError,
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecMessage, DeRecResult, MessageBody, StatusEnum, UnpairResponseMessage,
};
use prost::Message;

/// Result of [`produce`] and [`reject`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an
    /// encrypted inner [`derec_proto::UnpairResponseMessage`]. Ready to send
    /// over transport.
    pub envelope: Vec<u8>,
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// Decrypted inner [`derec_proto::UnpairResponseMessage`].
    pub response: UnpairResponseMessage,
}

/// Outcome of [`process`].
#[derive(Debug)]
pub struct ProcessResult {
    /// `true` when the responder reported a successful unpair
    /// (`result.status == StatusEnum::Ok`); `false` otherwise.
    pub acknowledged: bool,
}

/// Builds a **successful** unpair acknowledgement envelope (responder side).
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
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub fn produce(
    channel_id: ChannelId,
    shared_key: &SharedKey,
) -> Result<ProduceResult, crate::Error> {
    let timestamp = current_timestamp();

    let response = UnpairResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
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

    #[cfg(feature = "logging")]
    tracing::info!("unpair response (ok) envelope produced");

    Ok(ProduceResult { envelope })
}

/// Builds a **rejection** unpair envelope (responder side).
///
/// Used when the responder cannot or will not honour the unpair request
/// (for example regulatory retention obligations). The envelope echoes
/// the chosen [`StatusEnum`] and the application-supplied memo so the
/// initiator can surface the reason to the user.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier for the requesting peer.
/// * `shared_key` - 32-byte symmetric channel key.
/// * `status` - The [`StatusEnum`] variant to return (e.g. `Fail`,
///   `Rejected`). Must not be `Ok` — callers MUST use [`produce`] for the
///   success path.
/// * `memo` - Human-readable rejection reason.
///
/// # Errors
///
/// Returns [`crate::Error`] if outer envelope construction or encryption fails.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, status = status as i32))
)]
pub fn reject(
    channel_id: ChannelId,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
) -> Result<ProduceResult, crate::Error> {
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

    #[cfg(feature = "logging")]
    tracing::info!("unpair response (reject) envelope produced");

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

    if envelope.timestamp != response.timestamp {
        #[cfg(feature = "logging")]
        tracing::warn!("timestamp invariant violated");
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match response timestamp",
        ));
    }

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
/// - `Err(UnpairingError::MissingResult)` — the response carried no result.
///
/// The initiator's [`crate::protocol`] orchestrator uses the outcome to
/// decide whether to delete its own local state (success) or surface a
/// rejection event to the application.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all)
)]
pub fn process(response: &UnpairResponseMessage) -> Result<ProcessResult, crate::Error> {
    let result = response
        .result
        .as_ref()
        .ok_or(UnpairingError::MissingResult)?;

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
