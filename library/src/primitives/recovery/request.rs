// SPDX-License-Identifier: Apache-2.0

use crate::primitives::recovery::error::RecoveryError;
use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::{ChannelId, SharedKey},
};
use derec_proto::{DeRecMessage, GetShareRequestMessage, MessageBody};
use prost::Message;

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope with the encrypted request payload.
    pub envelope: Vec<u8>,
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// The decrypted inner [`derec_proto::GetShareRequestMessage`].
    pub request: GetShareRequestMessage,
}

/// Produces a recovery request envelope for a specific `(secret_id, version)` share.
///
/// In the DeRec recovery flow, the recovering owner requests one share from each helper.
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
/// * `channel_id` - Identifier of the previously paired helper channel.
/// * `secret_id` - Identifier of the secret being recovered. Must not be empty.
/// * `version` - Version number of the secret share to request. Must be `>= 0`.
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
/// The inner request contains:
///
/// - `secret_id`: the requested secret identifier
/// - `share_version`: the requested version
/// - `timestamp`: the request creation timestamp
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Recovery(...)`) in the following cases:
///
/// - [`RecoveryError::EmptySecretId`] if `secret_id` is empty
/// - [`RecoveryError::InvalidVersion`] if `version < 0`
/// - outer envelope construction or symmetric encryption fails
///
/// # Security Notes
///
/// - This request does not contain secret material; it only identifies which share is requested.
/// - The outer envelope is not encrypted; only the inner protobuf message is encrypted.
/// - The outer envelope timestamp is set equal to the inner request timestamp to preserve
///   the invariant `envelope.timestamp == request.timestamp`.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::recovery::request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let result = request::produce(channel_id, b"my_secret", 1, &shared_key)
///     .expect("failed to build recovery request");
///
/// assert!(!result.envelope.is_empty());
/// ```
pub fn produce(
    channel_id: ChannelId,
    secret_id: &[u8],
    version: i32,
    shared_key: &SharedKey,
) -> Result<ProduceResult, crate::Error> {
    if secret_id.is_empty() {
        return Err(RecoveryError::EmptySecretId.into());
    }

    if version < 0 {
        return Err(RecoveryError::InvalidVersion { version }.into());
    }

    let timestamp = current_timestamp();

    let message = GetShareRequestMessage {
        secret_id: secret_id.to_vec(),
        share_version: version,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetShareRequest(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

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
/// request can then be passed to the response module's `produce` function to build a response.
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
pub fn extract(
    envelope_bytes: &[u8],
    shared_key: &SharedKey,
) -> Result<ExtractResult, crate::Error> {
    let envelope = DeRecMessage::decode(envelope_bytes).map_err(crate::Error::ProtobufDecode)?;

    let request = match extract_inner_message(&envelope.message, shared_key)? {
        MessageBody::GetShareRequest(message) => message,
        _ => {
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: GetShareRequestMessage",
            ));
        }
    };

    if envelope.timestamp != request.timestamp {
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match request timestamp",
        ));
    }

    Ok(ExtractResult { request })
}
