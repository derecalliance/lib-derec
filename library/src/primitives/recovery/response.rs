// SPDX-License-Identifier: Apache-2.0

use crate::primitives::recovery::error::RecoveryError;
use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::{ChannelId, SharedKey},
};
use derec_cryptography::vss::{self, VSSShare};
use derec_proto::{
    CommittedDeRecShare, DeRecMessage, DeRecResult, DeRecShare, GetShareRequestMessage,
    GetShareResponseMessage, MessageBody, StatusEnum, StoreShareRequestMessage,
};
use prost::Message;

/// Current share algorithm identifier.
const SHARE_ALGORITHM_VSS: i32 = 0;

/// Input required to process a single share response during recovery.
pub struct RecoveryResponseInput<'a> {
    pub share_response: &'a GetShareResponseMessage,
}

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope with the encrypted response payload.
    pub envelope: Vec<u8>,
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// The decrypted inner [`derec_proto::GetShareResponseMessage`].
    pub response: GetShareResponseMessage,
}

/// Result of [`recover`].
pub struct RecoverResult {
    /// Reconstructed secret bytes.
    pub secret_data: Vec<u8>,
}

/// Produces a recovery response envelope containing the requested committed share.
///
/// This function is typically executed by a helper after receiving a recovery request and
/// locating the corresponding stored share from the earlier sharing flow.
///
/// The helper:
///
/// 1. Validates that `stored_share_request` contains non-empty committed share bytes
/// 2. Decodes the embedded [`derec_proto::CommittedDeRecShare`] and inner [`derec_proto::DeRecShare`]
/// 3. Validates that the stored share matches the requested `secret_id` and `share_version`
/// 4. Builds and encrypts a [`derec_proto::GetShareResponseMessage`] carrying the committed share
///
/// # Arguments
///
/// * `channel_id` - Identifier of the previously paired helper channel.
/// * `_secret_id` - Secret identifier of the share being requested. Reserved for future validation.
/// * `request` - The decoded [`derec_proto::GetShareRequestMessage`] previously extracted
///   from the recovery request envelope.
/// * `stored_share_request` - The decoded [`derec_proto::StoreShareRequestMessage`] previously
///   stored by this helper during the sharing flow.
/// * `shared_key` - Previously established 32-byte symmetric channel key used to encrypt
///   the response.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an encrypted
///   inner [`derec_proto::GetShareResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Recovery(...)`) in the following cases:
///
/// - [`RecoveryError::EmptyCommittedDeRecShare`] if the stored share has no committed share bytes
/// - [`RecoveryError::DecodeCommittedDeRecShare`] if the committed share cannot be decoded
/// - [`RecoveryError::DecodeDeRecShare`] if the inner [`derec_proto::DeRecShare`] cannot be decoded
/// - [`RecoveryError::SecretIdMismatch`] if the stored share does not match the requested `secret_id`
/// - [`RecoveryError::VersionMismatch`] if the stored share does not match the requested `share_version`
/// - outer response envelope construction or encryption fails
///
/// # Security Notes
///
/// - The response contains share material and must be treated as sensitive.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::recovery::{request, response};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// // After extracting the recovery request and looking up the stored share:
/// // let request::ExtractResult { request } = request::extract(&envelope_bytes, &shared_key)?;
/// // let response::ProduceResult { envelope } =
/// //     response::produce(channel_id, b"secret_id", &request, &stored_share_request, &shared_key)?;
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = request.share_version))
)]
pub fn produce(
    channel_id: ChannelId,
    _secret_id: &[u8],
    request: &GetShareRequestMessage,
    stored_share_request: &StoreShareRequestMessage,
    shared_key: &SharedKey,
) -> Result<ProduceResult, crate::Error> {
    if stored_share_request.share.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("stored share is empty");
        return Err(RecoveryError::EmptyCommittedDeRecShare.into());
    }

    let committed_derec_share = CommittedDeRecShare::decode(stored_share_request.share.as_slice())
        .map_err(|source| RecoveryError::DecodeCommittedDeRecShare { source })?;

    let derec_share = DeRecShare::decode(committed_derec_share.de_rec_share.as_slice())
        .map_err(|source| RecoveryError::DecodeDeRecShare { source })?;

    if derec_share.secret_id != request.secret_id {
        #[cfg(feature = "logging")]
        tracing::warn!("secret_id mismatch between request and stored share");
        return Err(RecoveryError::SecretIdMismatch.into());
    }

    if derec_share.version != request.share_version {
        #[cfg(feature = "logging")]
        tracing::warn!(expected = request.share_version, got = derec_share.version, "version mismatch between request and stored share");
        return Err(RecoveryError::VersionMismatch {
            expected: request.share_version,
            got: derec_share.version,
        }
        .into());
    }

    let timestamp = current_timestamp();

    let message = GetShareResponseMessage {
        share_algorithm: SHARE_ALGORITHM_VSS,
        committed_de_rec_share: stored_share_request.share.clone(),
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetShareResponse(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("recovery response envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes an incoming [`derec_proto::GetShareResponseMessage`] from an outer
/// [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`derec_proto::GetShareResponseMessage`] using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == response.timestamp`
///
/// Call this on the **Owner** side after receiving a recovery response from a helper.
/// The decrypted response can then be passed to [`recover`] as part of the `responses` slice.
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::GetShareResponseMessage`], as produced by [`produce`].
/// * `shared_key` - Previously established 32-byte symmetric channel key used to decrypt
///   the inner message.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `response`: the decrypted inner [`derec_proto::GetShareResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != response.timestamp`
/// - the inner message is not a [`derec_proto::GetShareResponseMessage`]
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
        MessageBody::GetShareResponse(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected GetShareResponseMessage");
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: GetShareResponseMessage",
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
    tracing::info!("recovery response extracted and validated");

    Ok(ExtractResult { response })
}

/// Reconstructs the original secret from helper recovery responses.
///
/// This function performs the recovery pipeline:
///
/// 1. Validates inputs (`responses`, `secret_id`, `version`)
/// 2. Validates that each response reports `result.status == Ok`
/// 3. Decodes each embedded [`derec_proto::CommittedDeRecShare`]
/// 4. Decodes each embedded [`derec_proto::DeRecShare`]
/// 5. Validates that each share matches the requested `secret_id` and `version`
/// 6. Maps validated shares into [`derec_cryptography::vss::VSSShare`] values
/// 7. Reconstructs the original secret using the VSS recovery algorithm
///
/// # Arguments
///
/// * `secret_id` - The secret identifier being recovered. Must not be empty.
/// * `version` - The version of the secret being recovered. Must be `>= 0`.
/// * `responses` - Collection of helper responses. Each entry must contain:
///   - `share_response`: decrypted [`derec_proto::GetShareResponseMessage`] previously
///     returned by [`extract`]
///
/// # Returns
///
/// On success returns [`RecoverResult`] containing:
///
/// - `secret_data`: the reconstructed secret bytes
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Recovery(...)`) in the following cases:
///
/// - [`RecoveryError::EmptyResponses`] if `responses` is empty
/// - [`RecoveryError::EmptySecretId`] if `secret_id` is empty
/// - [`RecoveryError::InvalidVersion`] if `version < 0`
/// - [`RecoveryError::MissingResult`] if any response is missing the `result` field
/// - [`RecoveryError::NonOkStatus`] if any response indicates a non-OK status
/// - [`RecoveryError::EmptyCommittedDeRecShare`] if any response contains empty committed share bytes
/// - [`RecoveryError::DecodeCommittedDeRecShare`] if committed share decoding fails
/// - [`RecoveryError::DecodeDeRecShare`] if inner share decoding fails
/// - [`RecoveryError::SecretIdMismatch`] if any decoded share does not match `secret_id`
/// - [`RecoveryError::VersionMismatch`] if any decoded share does not match `version`
/// - [`RecoveryError::ReconstructionFailed`] if VSS reconstruction fails
///
/// # Security Notes
///
/// - The reconstructed secret is highly sensitive. Callers should minimize exposure in memory,
///   avoid logging, and store it securely if persistence is required.
/// - Responses are treated as untrusted input; this function validates protocol status,
///   secret identity, and version binding before attempting reconstruction.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::recovery::response::{self, RecoveryResponseInput};
/// use derec_proto::GetShareResponseMessage;
///
/// let shared_key = [7u8; 32];
/// let response = GetShareResponseMessage::default();
///
/// let responses = vec![
///     RecoveryResponseInput {
///         share_response: &response,
///     }
/// ];
///
/// let result = response::recover(b"secret_id", 1, &responses);
/// assert!(result.is_err()); // empty committed share expected to fail
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(version = version, responses_count = responses.len()))
)]
pub fn recover(
    secret_id: &[u8],
    version: i32,
    responses: &[RecoveryResponseInput<'_>],
) -> Result<RecoverResult, crate::Error> {
    if responses.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("responses list is empty");
        return Err(RecoveryError::EmptyResponses.into());
    }

    if secret_id.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("secret_id is empty");
        return Err(RecoveryError::EmptySecretId.into());
    }

    if version < 0 {
        #[cfg(feature = "logging")]
        tracing::warn!(version = version, "version is negative");
        return Err(RecoveryError::InvalidVersion { version }.into());
    }

    let mut shares = Vec::with_capacity(responses.len());

    for input in responses {
        shares.push(extract_share_from_response(
            input.share_response,
            secret_id,
            version,
        )?);
    }

    let secret_data =
        vss::recover(&shares).map_err(|source| RecoveryError::ReconstructionFailed { source })?;

    #[cfg(feature = "logging")]
    tracing::info!("secret reconstructed from shares");

    Ok(RecoverResult { secret_data })
}

fn extract_share_from_response(
    response: &GetShareResponseMessage,
    secret_id: &[u8],
    version: i32,
) -> Result<VSSShare, crate::Error> {
    let result = response
        .result
        .as_ref()
        .ok_or(RecoveryError::MissingResult)?;

    if result.status != StatusEnum::Ok as i32 {
        return Err(RecoveryError::NonOkStatus {
            status: result.status,
        }
        .into());
    }

    if response.committed_de_rec_share.is_empty() {
        return Err(RecoveryError::EmptyCommittedDeRecShare.into());
    }

    let committed_derec_share =
        CommittedDeRecShare::decode(response.committed_de_rec_share.as_slice())
            .map_err(|source| RecoveryError::DecodeCommittedDeRecShare { source })?;

    let derec_share = DeRecShare::decode(committed_derec_share.de_rec_share.as_slice())
        .map_err(|source| RecoveryError::DecodeDeRecShare { source })?;

    if derec_share.secret_id != secret_id {
        return Err(RecoveryError::SecretIdMismatch.into());
    }

    if derec_share.version != version {
        return Err(RecoveryError::VersionMismatch {
            expected: version,
            got: derec_share.version,
        }
        .into());
    }

    Ok(VSSShare {
        x: derec_share.x,
        y: derec_share.y,
        encrypted_secret: derec_share.encrypted_secret,
        commitment: committed_derec_share.commitment,
        merkle_path: committed_derec_share
            .merkle_path
            .into_iter()
            .map(|h| (h.is_left, h.hash))
            .collect(),
    })
}
