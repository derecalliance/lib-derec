// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    primitives::replica_confirmation::ReplicaConfirmationError,
    types::{ChannelId, SharedKey},
};
use derec_proto::{DeRecMessage, MessageBody, ReplicaConfirmationRequestMessage};
use prost::Message;

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an encrypted
    /// [`derec_proto::ReplicaConfirmationRequestMessage`].
    pub envelope: Vec<u8>,
    /// The 16-digit fingerprint included in the request, so the local application
    /// can display it to the user.
    pub fingerprint: [u8; 16],
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// The decrypted inner [`derec_proto::ReplicaConfirmationRequestMessage`].
    pub request: ReplicaConfirmationRequestMessage,
}

/// Produces a replica confirmation request [`derec_proto::DeRecMessage`] envelope.
///
/// After an Owner and a Replica complete the pairing handshake (with
/// `SenderKind::Replica`), the channel is in an unconfirmed state. This function
/// builds the first message of the confirmation flow: it derives a fingerprint
/// from the shared key, embeds it together with the caller's `replica_id` in a
/// [`derec_proto::ReplicaConfirmationRequestMessage`], encrypts it with the
/// channel shared key, and wraps it in a [`derec_proto::DeRecMessage`] envelope.
///
/// The application should display the returned `fingerprint` to the user so they
/// can visually verify it matches the value shown on the peer device (similar to
/// Bluetooth pairing).
///
/// # Arguments
///
/// * `channel_id` - Channel established during Replica pairing.
/// * `shared_key` - 32-byte symmetric key from the Replica pairing.
/// * `replica_id` - Caller's replica identifier within the Owner's device set.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::ReplicaConfirmationRequestMessage`]
/// - `fingerprint`: 16-digit fingerprint (each byte 0–9) for user display
///
/// # Errors
///
/// Returns [`crate::Error`] if envelope construction or symmetric encryption fails.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::replica_confirmation::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let request::ProduceResult {
///     envelope,
///     fingerprint,
/// } = request::produce(channel_id, &shared_key, 1)
///     .expect("failed to produce replica confirmation request");
///
/// assert_eq!(fingerprint.len(), 16);
/// assert!(fingerprint.iter().all(|&d| d < 10));
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
    let fingerprint = derec_cryptography::replica::fingerprint(shared_key);
    let timestamp = current_timestamp();

    let message = ReplicaConfirmationRequestMessage {
        fingerprint: fingerprint.to_vec(),
        replica_id,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::ReplicaConfirmationRequest(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("replica confirmation request envelope produced");

    Ok(ProduceResult {
        envelope,
        fingerprint,
    })
}

/// Decrypts and decodes a [`derec_proto::ReplicaConfirmationRequestMessage`]
/// from an outer [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`derec_proto::ReplicaConfirmationRequestMessage`]
///    using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == request.timestamp`
///
/// Call this on the **receiving** side after getting a confirmation request. Then
/// pass the extracted request to [`verify_fingerprint`] and display the result to
/// the user for manual comparison.
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::ReplicaConfirmationRequestMessage`], as produced
///   by [`produce`].
/// * `shared_key` - 32-byte symmetric channel key established during Replica pairing.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `request`: the decrypted inner [`derec_proto::ReplicaConfirmationRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != request.timestamp`
/// - the inner message is not a [`derec_proto::ReplicaConfirmationRequestMessage`]
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::replica_confirmation::request;
///
/// let shared_key = [7u8; 32];
/// # let envelope_bytes: Vec<u8> = vec![];
///
/// let request::ExtractResult { request } =
///     request::extract(&envelope_bytes, &shared_key)
///         .expect("failed to extract replica confirmation request");
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
        MessageBody::ReplicaConfirmationRequest(m) => m,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected ReplicaConfirmationRequestMessage");
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: ReplicaConfirmationRequestMessage",
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
    tracing::info!("replica confirmation request extracted and validated");

    Ok(ExtractResult { request })
}

/// Verifies that the fingerprint in the received request matches the locally
/// derived fingerprint.
///
/// Call this after [`extract`] succeeds. If the fingerprints match, the
/// application should display the fingerprint to the user for visual
/// confirmation and then send a [`super::response::produce`] response.
///
/// # Arguments
///
/// * `request` - The decrypted request returned by [`extract`].
/// * `shared_key` - 32-byte symmetric channel key — must be the same key used
///   by the peer to derive the fingerprint.
///
/// # Errors
///
/// Returns [`ReplicaConfirmationError::FingerprintMismatch`] if the received
/// fingerprint bytes differ from the locally computed value.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::replica_confirmation::request;
///
/// let shared_key = [7u8; 32];
/// # let envelope_bytes: Vec<u8> = vec![];
///
/// let request::ExtractResult { request: req } =
///     request::extract(&envelope_bytes, &shared_key)
///         .expect("failed to extract");
///
/// request::verify_fingerprint(&req, &shared_key)
///     .expect("fingerprint mismatch — possible MITM");
/// ```
pub fn verify_fingerprint(
    request: &ReplicaConfirmationRequestMessage,
    shared_key: &SharedKey,
) -> Result<(), crate::Error> {
    let expected = derec_cryptography::replica::fingerprint(shared_key);

    if request.fingerprint.as_slice() != expected.as_slice() {
        #[cfg(feature = "logging")]
        tracing::warn!("fingerprint mismatch in replica confirmation request");
        return Err(ReplicaConfirmationError::FingerprintMismatch.into());
    }

    Ok(())
}
