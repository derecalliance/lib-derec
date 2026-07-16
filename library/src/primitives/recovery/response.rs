// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::primitives::recovery::RecoveryError;
use crate::utils::verify_timestamps;
use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::{ChannelId, SharedKey},
};
use derec_cryptography::vss;
use derec_proto::{
    CommittedDeRecShare, DeRecMessage, DeRecResult, DeRecShare, GetShareRequestMessage,
    GetShareResponseMessage, MessageBody, StatusEnum, StoreShareRequestMessage,
};
use prost::Message;

const SHARE_ALGORITHM_VSS: i32 = 0;

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope with the encrypted response payload.
    pub envelope: Vec<u8>,
}

pub struct ExtractResult {
    pub response: GetShareResponseMessage,
}

pub struct RecoverResult {
    pub secret_data: Vec<u8>,
}

/// Produces a recovery response envelope containing the requested committed share.
///
/// This function is typically executed by a Helper after receiving a recovery request and
/// locating the corresponding stored share from the earlier sharing flow.
///
/// The Helper:
///
/// 1. Validates that `stored_share_request` contains non-empty committed share bytes
/// 2. Decodes the embedded [`derec_proto::CommittedDeRecShare`] and inner [`derec_proto::DeRecShare`]
/// 3. Validates that the stored share matches the requested `secret_id` and `version`
/// 4. Builds and encrypts a [`derec_proto::GetShareResponseMessage`] carrying the committed share
///
/// # Arguments
///
/// * `channel_id` - Identifier of the previously paired Helper channel.
/// * `request` - The decoded [`derec_proto::GetShareRequestMessage`] previously extracted
///   from the recovery request envelope.
/// * `stored_share_request` - The decoded [`derec_proto::StoreShareRequestMessage`] previously
///   stored by this Helper during the sharing flow.
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
/// - [`RecoveryError::VersionMismatch`] if the stored share does not match the requested `version`
/// - outer response envelope construction or encryption fails
///
/// # Security Notes
///
/// - The response contains share material and must be treated as sensitive.
///
/// # Example
///
/// ```
/// use derec_library::primitives::{recovery, sharing};
/// use derec_library::types::ChannelId;
///
/// let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
/// let shared_key = [42u8; 32];
/// let channel_id = ChannelId(1);
///
/// // Sharing flow: produce a stored share that the Helper retains for recovery.
/// let sharing::request::SplitResult { shares } =
///     sharing::request::split(&channels, 1, 1, b"super_secret_value", 2)
///         .expect("split failed");
/// let committed_share = shares.get(&channel_id).expect("missing share");
/// let sharing::request::ProduceResult { envelope: share_envelope } =
///     sharing::request::produce(channel_id, 1, 1, committed_share, &[], "", &shared_key, None, None)
///         .expect("share produce failed");
/// let sharing::request::ExtractResult { request: stored_share_request } =
///     sharing::request::extract(&share_envelope, &shared_key).expect("share extract failed");
///
/// // Recovery flow: Owner asks for the share back, Helper answers.
/// let recovery::request::ProduceResult { envelope: req_envelope } =
///     recovery::request::produce(channel_id, 1, 1, &shared_key, None).expect("recovery request failed");
/// let recovery::request::ExtractResult { request: get_share_request } =
///     recovery::request::extract(&req_envelope, &shared_key)
///         .expect("recovery request extract failed");
///
/// let recovery::response::ProduceResult { envelope } =
///     recovery::response::produce(channel_id, &get_share_request, &stored_share_request, &shared_key)
///         .expect("recovery response failed");
///
/// assert!(!envelope.is_empty());
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = request.version))
)]
pub fn produce(
    channel_id: ChannelId,
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

    if derec_share.version != request.version {
        #[cfg(feature = "logging")]
        tracing::warn!(
            expected = request.version,
            got = derec_share.version,
            "version mismatch between request and stored share"
        );

        return Err(RecoveryError::VersionMismatch {
            expected: request.version,
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
        secret_id: request.secret_id,
        version: request.version,
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
/// Call this on the **Owner** side after receiving a recovery response from a Helper.
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
///
/// # Security Notes
///
/// - The decrypted response carries the Helper's committed share material and must be
///   treated as sensitive.
/// - **No freshness or replay protection.** The timestamp check
///   enforced here only binds the envelope to the inner body
///   (`envelope.timestamp == body.timestamp`). It does NOT enforce
///   a freshness window against the receiver's clock and does NOT
///   detect replays of a previously-captured ciphertext. Because
///   the channel key is long-lived, a recorded envelope stays
///   decryptable indefinitely. Callers MUST add a freshness window
///   and per-channel anti-replay (monotonic counter or nonce log)
///   on top before driving any side-effecting state off the parsed
///   body.
///
/// # Example
///
/// ```
/// use derec_library::primitives::{recovery, sharing};
/// use derec_library::types::ChannelId;
///
/// let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
/// let shared_key = [42u8; 32];
/// let channel_id = ChannelId(1);
///
/// // Sharing flow: produce a stored share that the Helper retains for recovery.
/// let sharing::request::SplitResult { shares } =
///     sharing::request::split(&channels, 1, 1, b"super_secret_value", 2)
///         .expect("split failed");
/// let committed_share = shares.get(&channel_id).expect("missing share");
/// let sharing::request::ProduceResult { envelope: share_envelope } =
///     sharing::request::produce(channel_id, 1, 1, committed_share, &[], "", &shared_key, None, None)
///         .expect("share produce failed");
/// let sharing::request::ExtractResult { request: stored_share_request } =
///     sharing::request::extract(&share_envelope, &shared_key).expect("share extract failed");
///
/// // Recovery flow: Owner asks for the share back, Helper answers, Owner extracts.
/// let recovery::request::ProduceResult { envelope: req_envelope } =
///     recovery::request::produce(channel_id, 1, 1, &shared_key, None).expect("recovery request failed");
/// let recovery::request::ExtractResult { request: get_share_request } =
///     recovery::request::extract(&req_envelope, &shared_key)
///         .expect("recovery request extract failed");
/// let recovery::response::ProduceResult { envelope: resp_envelope } =
///     recovery::response::produce(channel_id, &get_share_request, &stored_share_request, &shared_key)
///         .expect("recovery response failed");
///
/// let recovery::response::ExtractResult { response } =
///     recovery::response::extract(&resp_envelope, &shared_key)
///         .expect("recovery response extract failed");
///
/// assert!(response.result.is_some());
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
        MessageBody::GetShareResponse(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected GetShareResponseMessage");
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: GetShareResponseMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, response.timestamp)?;

    #[cfg(feature = "logging")]
    tracing::info!("recovery response extracted and validated");

    Ok(ExtractResult { response })
}

/// Reconstructs the original secret from Helper recovery responses.
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
/// * `secret_id` - The secret identifier being recovered.
/// * `version` - The version of the secret being recovered.
/// * `responses` - Collection of Helper responses. Each entry must contain:
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
/// - any response is missing the `result` field (returned as `crate::Error::Invariant`)
/// - [`RecoveryError::NonOkStatus`] if any response indicates a non-OK status, carrying the
///   Helper's status code and memo string
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
/// ```
/// use derec_library::primitives::{recovery, sharing};
/// use derec_library::primitives::recovery::response::RecoverResult;
/// use derec_library::types::ChannelId;
///
/// let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
/// let shared_key = [42u8; 32];
/// let secret_data = b"super_secret_value";
///
/// // Sharing flow: store one share per Helper for later recovery.
/// let sharing::request::SplitResult { shares } =
///     sharing::request::split(&channels, 1, 1, secret_data, 2).expect("split failed");
///
/// let mut stored_shares = Vec::new();
/// for &channel_id in &channels[..2] {
///     let committed_share = shares.get(&channel_id).expect("missing share");
///     let sharing::request::ProduceResult { envelope } =
///         sharing::request::produce(channel_id, 1, 1, committed_share, &[], "", &shared_key, None, None)
///             .expect("share produce failed");
///     let sharing::request::ExtractResult { request } =
///         sharing::request::extract(&envelope, &shared_key).expect("share extract failed");
///     stored_shares.push((channel_id, request));
/// }
///
/// // Recovery flow: collect threshold-many recovered shares.
/// let mut responses = Vec::new();
/// for (channel_id, stored_share_request) in &stored_shares {
///     let recovery::request::ProduceResult { envelope: req_env } =
///         recovery::request::produce(*channel_id, 1, 1, &shared_key, None)
///             .expect("recovery request failed");
///     let recovery::request::ExtractResult { request: get_share_req } =
///         recovery::request::extract(&req_env, &shared_key)
///             .expect("recovery request extract failed");
///     let recovery::response::ProduceResult { envelope: resp_env } =
///         recovery::response::produce(*channel_id, &get_share_req, stored_share_request, &shared_key)
///             .expect("recovery response failed");
///     let recovery::response::ExtractResult { response } =
///         recovery::response::extract(&resp_env, &shared_key)
///             .expect("recovery response extract failed");
///     responses.push(response);
/// }
///
/// let inputs: Vec<&_> = responses.iter().collect();
///
/// let RecoverResult { secret_data: recovered } =
///     recovery::response::recover(1, 1, &inputs).expect("recover failed");
///
/// assert_eq!(recovered, secret_data);
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(version = version, responses_count = responses.len()))
)]
pub fn recover(
    secret_id: u64,
    version: u32,
    responses: &[&GetShareResponseMessage],
) -> Result<RecoverResult, crate::Error> {
    if responses.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("responses list is empty");
        return Err(RecoveryError::EmptyResponses.into());
    }

    let mut shares = Vec::with_capacity(responses.len());

    for response in responses {
        shares.push(extract_share_from_response(response, secret_id, version)?);
    }

    let secret_data =
        vss::recover(&shares).map_err(|source| RecoveryError::ReconstructionFailed { source })?;

    #[cfg(feature = "logging")]
    tracing::info!("secret reconstructed from shares");

    Ok(RecoverResult { secret_data })
}

fn extract_share_from_response(
    response: &GetShareResponseMessage,
    secret_id: u64,
    version: u32,
) -> Result<vss::VSSShare, crate::Error> {
    let result = response.result.as_ref().ok_or(crate::Error::Invariant(
        "GetShareResponseMessage is missing result field",
    ))?;

    if result.status != StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(status = result.status, memo = %result.memo, "recovery share response status is not Ok");
        return Err(RecoveryError::NonOkStatus {
            status: result.status,
            memo: result.memo.to_owned(),
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

    Ok(vss::VSSShare {
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
