// SPDX-License-Identifier: Apache-2.0

use crate::primitives::sharing::error::SharingError;
use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::*,
};
use derec_cryptography::vss;
use derec_proto::{
    CommittedDeRecShare, DeRecMessage, DeRecResult, DeRecShare, MessageBody, StatusEnum,
    StoreShareRequestMessage, StoreShareResponseMessage,
};
use prost::Message;

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope.
    pub envelope: Vec<u8>,
    /// The [`CommittedDeRecShare`] extracted from the request.
    pub committed_share: CommittedDeRecShare,
    /// Secret identifier extracted from the inner [`derec_proto::DeRecShare`].
    pub secret_id: u64,
    /// Share-distribution version extracted from the request.
    pub version: u32,
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// The decrypted inner [`derec_proto::StoreShareResponseMessage`].
    pub response: StoreShareResponseMessage,
}

/// Processes an incoming [`derec_proto::StoreShareRequestMessage`] on behalf of a Helper,
/// returning an encrypted response envelope and the committed share to persist locally.
///
/// This function is executed by a **Helper** upon receiving a sharing request from an Owner.
/// It:
///
/// 1. Validates the `share` field of the provided `request` is non-empty
/// 2. Decodes the embedded [`derec_proto::CommittedDeRecShare`] from the `share` field
/// 3. Validates that `de_rec_share`, `commitment`, and `merkle_path` are non-empty
/// 4. Decodes `de_rec_share` as a [`derec_proto::DeRecShare`] to extract `(x, y)` coordinates
/// 5. Verifies the Merkle proof: recomputes the root from `(x, y)` and the path,
///    and rejects the share if it does not match `commitment`
/// 6. Constructs a [`derec_proto::StoreShareResponseMessage`] with `status = Ok`
/// 7. Encrypts and wraps the response into a new [`derec_proto::DeRecMessage`] envelope
///
/// The Helper must persist `committed_share` from the returned result for future verification
/// and recovery requests.
///
/// # Arguments
///
/// * `channel_id` - The channel this request arrived on. Used to build the response envelope.
/// * `request` - The decoded [`derec_proto::StoreShareRequestMessage`] received from the Owner,
///   as extracted from the wire envelope.
/// * `shared_key` - 256-bit symmetric key shared with the Owner, established during pairing.
///   Used to encrypt the response.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized response [`derec_proto::DeRecMessage`] to send back to the Owner
/// - `committed_share`: the [`derec_proto::CommittedDeRecShare`] extracted from the request, ready to store
/// - `secret_id`: the secret identifier extracted from the inner [`derec_proto::DeRecShare`]
/// - `version`: the share-distribution version extracted from the request
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - the `share` field of the request is empty
/// - the `share` field cannot be decoded as a valid [`derec_proto::CommittedDeRecShare`]
/// - `CommittedDeRecShare.de_rec_share` is empty
/// - `CommittedDeRecShare.commitment` is empty
/// - `CommittedDeRecShare.merkle_path` is empty
/// - `CommittedDeRecShare.de_rec_share` cannot be decoded as a valid [`derec_proto::DeRecShare`]
/// - the Merkle proof does not verify against `commitment`
/// - response envelope construction or encryption fails
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::sharing::{request, response};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(1);
/// let shared_key = [42u8; 32];
///
/// // First, produce and extract a sharing request to get the StoreShareRequestMessage:
/// // let request::ExtractResult { request, .. } = request::extract(&envelope_bytes, &shared_key)?;
///
/// // Then produce the response:
/// // let response::ProduceResult { envelope, committed_share, .. } =
/// //     response::produce(channel_id, &request, &shared_key)?;
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = request.version))
)]
pub fn produce(
    channel_id: ChannelId,
    request: &StoreShareRequestMessage,
    shared_key: &[u8; 32],
) -> Result<ProduceResult, crate::Error> {
    if request.share.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("share field is empty in StoreShareRequestMessage");
        return Err(crate::Error::Invariant(
            "share field is empty in StoreShareRequestMessage",
        ));
    }

    let committed_share = CommittedDeRecShare::decode(request.share.as_slice())
        .map_err(crate::Error::ProtobufDecode)?;

    if committed_share.de_rec_share.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("CommittedDeRecShare.de_rec_share is empty");
        return Err(crate::Error::Invariant(
            "CommittedDeRecShare.de_rec_share is empty",
        ));
    }

    if committed_share.commitment.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("CommittedDeRecShare.commitment is empty");
        return Err(crate::Error::Invariant(
            "CommittedDeRecShare.commitment is empty",
        ));
    }

    if committed_share.merkle_path.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("CommittedDeRecShare.merkle_path is empty");
        return Err(crate::Error::Invariant(
            "CommittedDeRecShare.merkle_path is empty",
        ));
    }

    let inner_share = DeRecShare::decode(committed_share.de_rec_share.as_slice())
        .map_err(crate::Error::ProtobufDecode)?;

    let secret_id = inner_share.secret_id;
    let version = request.version;

    let vss_share = vss::VSSShare {
        x: inner_share.x,
        y: inner_share.y,
        encrypted_secret: inner_share.encrypted_secret,
        commitment: committed_share.commitment.clone(),
        merkle_path: committed_share
            .merkle_path
            .iter()
            .map(|s| (s.is_left, s.hash.clone()))
            .collect(),
    };

    if !vss::verify(&vss_share) {
        #[cfg(feature = "logging")]
        tracing::warn!("Merkle proof verification failed");
        return Err(crate::Error::Invariant(
            "CommittedDeRecShare Merkle proof verification failed",
        ));
    }

    let timestamp = current_timestamp();

    let response = StoreShareResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        version: request.version,
        timestamp: Some(timestamp),
        secret_id: request.secret_id.clone(),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::StoreShareResponse(response))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("share accepted; response envelope produced");

    Ok(ProduceResult {
        envelope,
        committed_share,
        secret_id,
        version,
    })
}

/// Decrypts and decodes an incoming [`derec_proto::StoreShareResponseMessage`] from an outer
/// [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`derec_proto::StoreShareResponseMessage`] using
///    `shared_key`
/// 3. Validates the invariant `envelope.timestamp == response.timestamp`
///
/// Call this on the **Owner** side after receiving the Helper's response to a sharing
/// request envelope. The decrypted response can then be validated using [`process`].
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] envelope bytes
///   received from the Helper, as produced by [`produce`].
/// * `shared_key` - 256-bit symmetric key shared with this Helper, derived during pairing.
///   Used to decrypt the response envelope.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `response`: the decrypted inner [`derec_proto::StoreShareResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != response.timestamp`
/// - the inner message is not a [`derec_proto::StoreShareResponseMessage`]
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
        MessageBody::StoreShareResponse(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected StoreShareResponseMessage");
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: StoreShareResponseMessage. Received: ???",
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
    tracing::info!("share response extracted and validated");

    Ok(ExtractResult { response })
}

/// Validates a [`derec_proto::StoreShareResponseMessage`] received from a Helper.
///
/// Call this on the **Owner** side after extracting the response with [`extract`].
/// The function:
///
/// 1. Validates that `response.version == version`
/// 2. Validates that the `result` field is present
/// 3. Returns `Ok(())` if the Helper's response status is `Ok`
///
/// Any failure — whether a protocol error or the Helper's explicit rejection — is
/// returned as [`crate::Error`].
///
/// # Arguments
///
/// * `version` - The version number that was sent in the original request. Used to
///   cross-check the version echoed back by the Helper.
/// * `response` - The decrypted [`derec_proto::StoreShareResponseMessage`] previously
///   returned by [`extract`].
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - [`SharingError::NonOkStatus`] if `result.status != Ok`, carrying the
///   Helper's status code and memo string
/// - the `result` field is absent in the response
/// - `response.version != version`
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::sharing::response;
/// use derec_library::types::ChannelId;
///
/// let shared_key = [42u8; 32];
/// let version = 1;
///
/// // After extracting the response envelope:
/// // let response::ExtractResult { response } = response::extract(&envelope_bytes, &shared_key)?;
/// // response::process(version, &response)?;
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(version = version))
)]
pub fn process(version: u32, response: &StoreShareResponseMessage) -> Result<(), crate::Error> {
    // Validate response status before any other checks.
    let result = response.result.as_ref().ok_or(crate::Error::Invariant(
        "StoreShareResponseMessage is missing result field",
    ))?;

    if result.status != StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(status = result.status, memo = %result.memo, "share response status is not Ok");
        return Err(SharingError::NonOkStatus {
            status: result.status,
            memo: result.memo.to_owned(),
        }
        .into());
    }

    if response.version != version {
        #[cfg(feature = "logging")]
        tracing::warn!(expected = version, got = response.version, "version mismatch in share response");
        return Err(crate::Error::Invariant(
            "Response version does not match request version",
        ));
    }

    #[cfg(feature = "logging")]
    tracing::info!("share storage confirmed by helper");

    Ok(())
}
