// SPDX-License-Identifier: Apache-2.0

use crate::transport::TransportProtocolExt as _;
use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::{ChannelId, SharedKey},
    utils::verify_timestamps,
};
use derec_proto::{DeRecMessage, MessageBody, VerifyShareRequestMessage};
use prost::Message;
use rand::{Rng, rng};

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope with the encrypted request payload.
    pub envelope: Vec<u8>,
    /// Fresh `u64` nonce that was embedded into the encrypted
    /// [`derec_proto::VerifyShareRequestMessage`].
    ///
    /// This nonce is the **owner-controlled binding token** for the
    /// challenge: [`super::response::process`] uses it (together with
    /// `secret_id` and `version`) to confirm the helper's response
    /// answers *this specific* outstanding request, preventing replay
    /// of a captured-and-stale response and rejecting responses whose
    /// helper-supplied `nonce` does not match anything the owner has
    /// outstanding.
    ///
    /// # Retention
    ///
    /// Who keeps this value depends on which layer is driving the flow:
    ///
    /// - **Orchestrator users** (`DeRecProtocol::start(VerifyShares)`):
    ///   the orchestrator stores the full request — nonce included —
    ///   in
    ///   [`crate::protocol::PendingVerification`](crate::protocol)
    ///   automatically. Application code never touches it.
    /// - **Primitive-direct callers** (driving `request::produce` and
    ///   `response::process` without the orchestrator, e.g. SDK parity
    ///   tests): MUST retain this `nonce` (typically in a per-
    ///   `channel_id` map) and pass the original
    ///   [`derec_proto::VerifyShareRequestMessage`] back to
    ///   [`super::response::process`] when the matching response arrives.
    ///
    /// In both layers the cryptographic contract is identical; the
    /// retention machinery is what differs.
    pub nonce: u64,
}

pub struct ExtractResult {
    pub request: VerifyShareRequestMessage,
}

/// Produces a verification request envelope to initiate the DeRec *verification* flow.
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
/// * `channel_id` - Channel identifier for the previously paired Helper.
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
/// ```
/// use derec_library::primitives::verification::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let result = request::produce(
///     channel_id,
///     1,
///     7,
///     &shared_key,
///     None,
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
    reply_to: Option<derec_proto::TransportProtocol>,
) -> Result<ProduceResult, crate::Error> {
    let mut rng = rng();

    let timestamp = current_timestamp();
    let nonce = rng.next_u64();

    let message = VerifyShareRequestMessage {
        secret_id,
        version,
        nonce,
        timestamp: Some(timestamp),
        reply_to,
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

    Ok(ProduceResult { envelope, nonce })
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
/// use derec_library::primitives::verification::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let request::ProduceResult { envelope } = request::produce(channel_id, 1, 7, &shared_key)
///     .expect("failed to build verification request");
///
/// let request::ExtractResult { request } = request::extract(&envelope, &shared_key)
///     .expect("failed to extract verification request");
///
/// assert_eq!(request.secret_id, 1);
/// assert_eq!(request.version, 7);
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
        MessageBody::VerifyShareRequest(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected VerifyShareRequestMessage");

            return Err(crate::Error::Invariant(
                "Invalid message. Expected: VerifyShareRequestMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, request.timestamp)?;

    if let Some(reply_to) = request.reply_to.as_ref() {
        reply_to.validate()?;
    }

    #[cfg(feature = "logging")]
    tracing::info!("verification request extracted and validated");

    Ok(ExtractResult { request })
}
