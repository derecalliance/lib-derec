// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{self, DeRecMessageBuilder, current_timestamp},
    recovery::{
        GenerateShareRequestResult, GenerateShareResponseResult, RecoverFromResponsesResult,
        RecoveryError, RecoveryResponseInput,
    },
    types::ChannelId,
};
use derec_cryptography::vss::*;
use derec_proto::{
    CommittedDeRecShare, DeRecResult, DeRecShare, GetShareRequestMessage, GetShareResponseMessage,
    StatusEnum, StoreShareRequestMessage,
};
use prost::Message;

/// Current share algorithm identifier embedded into [`GetShareResponseMessage`].
const SHARE_ALGORITHM_VSS: i32 = 0;

/// Produces a recovery request envelope for a specific `(secret_id, version)` share.
///
/// In the DeRec recovery flow, the recovering owner requests one share from each helper.
/// The request identifies:
///
/// - `secret_id`: which secret is being recovered
/// - `share_version`: which version of that secret is being recovered
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
/// On success returns [`GenerateShareRequestResult`] containing:
///
/// - `wire_bytes`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an encrypted
///   inner [`GetShareRequestMessage`]
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
/// ```rust
/// use derec_library::recovery::generate_share_request;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let result = generate_share_request(channel_id, b"my_secret", 1, &shared_key)
///     .expect("failed to build recovery request");
///
/// assert!(!result.wire_bytes.is_empty());
/// ```
pub fn generate_share_request(
    channel_id: ChannelId,
    secret_id: &[u8],
    version: i32,
    shared_key: &[u8; 32],
) -> Result<GenerateShareRequestResult, crate::Error> {
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

    let wire_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(&message)
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    Ok(GenerateShareRequestResult { wire_bytes })
}

/// Produces a recovery response envelope containing the requested committed share.
///
/// This function is typically executed by a helper after receiving a recovery request and
/// locating the corresponding stored share from the earlier sharing flow.
///
/// The helper:
///
/// 1. decrypts and decodes the incoming [`GetShareRequestMessage`]
/// 2. validates the invariant `envelope.timestamp == request.timestamp`
/// 3. decrypts and decodes the stored sharing envelope to recover the inner
///    [`StoreShareRequestMessage`]
/// 4. validates the invariant `stored_envelope.timestamp == stored_share.timestamp`
/// 5. decodes the embedded committed share and inner [`DeRecShare`]
/// 6. verifies that the stored share matches the requested `secret_id` and `share_version`
/// 7. builds and encrypts a [`GetShareResponseMessage`] carrying the committed share
///
/// # Arguments
///
/// * `channel_id` - Identifier of the previously paired helper channel.
/// * `_secret_id` - Secret identifier (currently unused by this helper). Included for API
///   consistency and future extensibility.
/// * `request_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying the
///   encrypted inner [`GetShareRequestMessage`].
/// * `stored_share_request_wire_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes
///   previously produced by the sharing flow for this helper. This envelope must contain an
///   encrypted inner [`StoreShareRequestMessage`].
/// * `shared_key` - Previously established 32-byte symmetric channel key used to decrypt the
///   request and stored share envelope, and to encrypt the response.
///
/// # Returns
///
/// On success returns [`GenerateShareResponseResult`] containing:
///
/// - `wire_bytes`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an encrypted
///   inner [`GetShareResponseMessage`]
///
/// The inner response contains:
///
/// - `result.status = Ok`
/// - `committed_de_rec_share`: the committed share bytes from the stored share request
/// - `share_algorithm = 0`
/// - `timestamp`: the response creation timestamp
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - request decryption or decoding fails
/// - `envelope.timestamp != request.timestamp`
/// - stored share envelope decryption or decoding fails
/// - `stored_envelope.timestamp != stored_share.timestamp`
/// - the stored share does not contain committed share bytes
/// - the stored committed share cannot be decoded
/// - the inner [`DeRecShare`] cannot be decoded
/// - the stored share does not match the requested `secret_id`
/// - the stored share does not match the requested `share_version`
/// - outer response envelope construction or encryption fails
///
/// # Security Notes
///
/// - The response contains share material and must be treated as sensitive.
/// - The outer envelope is not encrypted; only the inner protobuf message is encrypted.
/// - The outer response timestamp is set equal to the inner response timestamp to preserve
///   the invariant `envelope.timestamp == response.timestamp`.
///
/// # Example
///
/// ```rust
/// use derec_library::recovery::{generate_share_request, generate_share_response};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let request = generate_share_request(channel_id, b"secret_id", 1, &shared_key)
///     .expect("failed to build request");
///
/// // In a real helper, this would be the serialized sharing envelope that was
/// // previously received and stored for this helper.
/// let stored_share_request_wire_bytes: Vec<u8> = vec![];
///
/// let _ = generate_share_response(
///     channel_id,
///     b"secret_id",
///     &request.wire_bytes,
///     &stored_share_request_wire_bytes,
///     &shared_key,
/// );
/// ```
pub fn generate_share_response(
    channel_id: ChannelId,
    _secret_id: &[u8],
    request_bytes: &[u8],
    stored_share_request_wire_bytes: &[u8],
    shared_key: &[u8; 32],
) -> Result<GenerateShareResponseResult, crate::Error> {
    let (envelope, request) =
        derec_message::extract_inner_message::<GetShareRequestMessage>(request_bytes, shared_key)?;

    if envelope.timestamp != request.timestamp {
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match request timestamp",
        ));
    }

    let (stored_envelope, stored_share_request) = derec_message::extract_inner_message::<
        StoreShareRequestMessage,
    >(
        stored_share_request_wire_bytes, shared_key
    )?;

    if stored_envelope.timestamp != stored_share_request.timestamp {
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match stored share request timestamp",
        ));
    }

    if stored_share_request.share.is_empty() {
        return Err(RecoveryError::EmptyCommittedDeRecShare.into());
    }

    let committed_derec_share = CommittedDeRecShare::decode(stored_share_request.share.as_slice())
        .map_err(|source| RecoveryError::DecodeCommittedDeRecShare { source })?;

    let derec_share = DeRecShare::decode(committed_derec_share.de_rec_share.as_slice())
        .map_err(|source| RecoveryError::DecodeDeRecShare { source })?;

    if derec_share.secret_id != request.secret_id {
        return Err(RecoveryError::SecretIdMismatch.into());
    }

    if derec_share.version != request.share_version {
        return Err(RecoveryError::VersionMismatch {
            expected: request.share_version,
            got: derec_share.version,
        }
        .into());
    }

    let timestamp = current_timestamp();

    let message = GetShareResponseMessage {
        share_algorithm: SHARE_ALGORITHM_VSS,
        committed_de_rec_share: stored_share_request.share,
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        timestamp: Some(timestamp),
    };

    let wire_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(&message)
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    Ok(GenerateShareResponseResult { wire_bytes })
}

/// Reconstructs the original secret from helper recovery responses.
///
/// This function performs the recovery pipeline:
///
/// 1. validate inputs (`responses`, `secret_id`, `version`)
/// 2. decrypt and decode each inner [`GetShareResponseMessage`]
/// 3. validate `envelope.timestamp == response.timestamp` for each response
/// 4. validate that each response reports `result.status == Ok`
/// 5. decode each embedded [`CommittedDeRecShare`]
/// 6. decode each embedded [`DeRecShare`]
/// 7. validate that each share matches the requested `secret_id` and `version`
/// 8. map validated shares into [`VSSShare`] values
/// 9. reconstruct the original secret using the VSS recovery algorithm
///
/// # Arguments
///
/// * `secret_id` - The secret identifier being recovered. Must not be empty.
/// * `version` - The version of the secret being recovered. Must be `>= 0`.
/// * `responses` - Collection of helper responses paired with their corresponding
///   per-channel shared keys. Each entry must contain:
///   - `response_bytes`: serialized outer [`derec_proto::DeRecMessage`] bytes
///     containing an encrypted [`GetShareResponseMessage`]
///   - `shared_key`: the 32-byte symmetric key associated with that helper,
///     used to decrypt the response
///
/// # Returns
///
/// On success returns [`RecoverFromResponsesResult`] containing:
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
/// - [`Error::Invariant`] if `envelope.timestamp != response.timestamp` for any response
/// - [`Error::Decryption`] if any response cannot be decrypted with its provided `shared_key`
///
/// # Security Notes
///
/// - The reconstructed secret is highly sensitive. Callers should minimize exposure in memory,
///   avoid logging, and store it securely if persistence is required.
/// - Responses are treated as untrusted input; this function validates protocol status,
///   timestamp invariants, secret identity, and version binding before attempting reconstruction.
/// - Each response is decrypted independently using its associated shared key; incorrect key
///   pairing will result in decryption failure.
///
/// # Example
///
/// ```rust
/// use derec_library::recovery::{recover_from_share_responses, RecoveryResponseInput};
///
/// let shared_key = [7u8; 32];
///
/// let responses = vec![
///     RecoveryResponseInput {
///         bytes: &[],
///         shared_key: &shared_key,
///     }
/// ];
///
/// let result = recover_from_share_responses(b"secret_id", 1, &responses);
/// assert!(result.is_err());
/// ```
pub fn recover_from_share_responses(
    secret_id: &[u8],
    version: i32,
    responses: &[RecoveryResponseInput<'_>],
) -> Result<RecoverFromResponsesResult, crate::Error> {
    if responses.is_empty() {
        return Err(RecoveryError::EmptyResponses.into());
    }

    if secret_id.is_empty() {
        return Err(RecoveryError::EmptySecretId.into());
    }

    if version < 0 {
        return Err(RecoveryError::InvalidVersion { version }.into());
    }

    let decoded_responses = responses
        .iter()
        .map(|input| {
            let (envelope, response) = derec_message::extract_inner_message::<
                GetShareResponseMessage,
            >(input.bytes, input.shared_key)?;

            if envelope.timestamp != response.timestamp {
                return Err(crate::Error::Invariant(
                    "Envelope timestamp does not match response timestamp",
                ));
            }

            Ok(response)
        })
        .collect::<Result<Vec<_>, crate::Error>>()?;

    let mut shares = Vec::with_capacity(decoded_responses.len());

    for response in &decoded_responses {
        shares.push(extract_share_from_response(response, secret_id, version)?);
    }

    let secret_data =
        recover(&shares).map_err(|source| RecoveryError::ReconstructionFailed { source })?;

    Ok(RecoverFromResponsesResult { secret_data })
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
