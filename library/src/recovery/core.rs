// SPDX-License-Identifier: Apache-2.0

use crate::{recovery::RecoveryError, types::ChannelId};
use derec_cryptography::vss::*;
use derec_proto::{
    CommittedDeRecShare, DeRecShare, GetShareRequestMessage, GetShareResponseMessage,
    Result as DerecResult, StatusEnum, StoreShareRequestMessage,
};
use prost::Message;

/// Produces a [`GetShareRequestMessage`] to request a specific `(secret_id, version)` share
/// from a helper during the DeRec *recovery* flow.
///
/// In DeRec recovery, the recovering owner requests one share from each helper.
/// Each request identifies:
///
/// - `secret_id`: which secret is being recovered
/// - `share_version`: which version of that secret is being recovered
///
/// The returned message is a **protocol payload only**. It is not signed or encrypted by
/// this function; callers must apply the DeRec wire rules before transport.
///
/// # Arguments
///
/// * `_channel_id` - Identifier of the channel (currently unused; reserved for future channel-specific behavior).
/// * `secret_id` - Identifier of the secret being recovered. Must not be empty.
/// * `version` - Version number of the secret share to request. Must be `>= 0`.
///
/// # Returns
///
/// On success returns [`GetShareRequestMessage`] containing:
///
/// - `secret_id`: the requested secret identifier
/// - `share_version`: the requested version
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Recovery(...)`) in the following cases:
///
/// - `RecoveryError::EmptySecretId` if `secret_id` is empty.
/// - `RecoveryError::InvalidVersion { .. }` if `version < 0`.
///
/// # Security Notes
///
/// - This function does not embed secrets; it only identifies which share is requested.
/// - The returned message should be signed and encrypted according to DeRec wire rules
///   before being sent over any transport.
///
/// # Example
///
/// ```rust
/// use derec_library::recovery::*;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let secret_id = b"my_secret";
/// let version = 1;
///
/// let req = generate_share_request(channel_id, secret_id, version)
///     .expect("failed to build request");
///
/// assert_eq!(req.secret_id, secret_id);
/// assert_eq!(req.share_version, 1);
/// ```
pub fn generate_share_request(
    _channel_id: ChannelId,
    secret_id: impl AsRef<[u8]>,
    version: i32,
) -> Result<GetShareRequestMessage, crate::Error> {
    let secret_id = secret_id.as_ref();
    if secret_id.is_empty() {
        return Err(RecoveryError::EmptySecretId.into());
    }

    if version < 0 {
        return Err(RecoveryError::InvalidVersion { version }.into());
    }

    Ok(GetShareRequestMessage {
        secret_id: secret_id.as_ref().to_vec(),
        share_version: version,
    })
}

/// Produces a [`GetShareResponseMessage`] containing a committed share, in response to a
/// previously received [`GetShareRequestMessage`].
///
/// This function is typically executed by a **helper** after locating the requested share
/// in its local store. The helper wraps the committed share bytes into a response message
/// and marks the result status as `Ok`.
///
/// This function is a **message constructor**. It does not:
///
/// - verify that `share_content` matches the incoming request,
/// - decrypt or validate any cryptographic contents,
/// - sign/encrypt the returned message.
///
/// Callers must apply DeRec wire rules before transport.
///
/// # Arguments
///
/// * `_channel_id` - Identifier of the channel (currently unused; reserved for future channel-specific behavior).
/// * `_secret_id` - Secret identifier (currently unused; reserved for future binding/validation).
/// * `_request` - The original request message (currently unused; reserved for future binding/validation).
/// * `share_content` - The share payload to return, typically retrieved from storage. Must not be empty.
///   This is expected to contain the bytes of a `CommittedDeRecShare` (as produced by the sharing flow).
///
/// # Returns
///
/// On success returns [`GetShareResponseMessage`] containing:
///
/// - `result`: set to [`StatusEnum::Ok`]
/// - `committed_de_rec_share`: the committed share bytes (opaque to this function)
/// - `share_algorithm`: currently set to `0` (placeholder until algorithm IDs are standardized)
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Recovery(...)`) in the following cases:
///
/// - `RecoveryError::EmptyCommittedDeRecShare` if `share_content.share` is empty.
///
/// # Security Notes
///
/// - The returned message contains share material and must be treated as sensitive.
/// - Callers must ensure the message is signed and encrypted according to DeRec wire rules
///   before transport.
/// - This function does not prove that the share corresponds to the request; if binding is
///   required at this layer, decode and validate the share before constructing the response.
///
/// # Example
///
/// ```rust
/// use derec_library::recovery::*;
/// use derec_library::types::ChannelId;
/// use derec_proto::StoreShareRequestMessage;
///
/// let channel_id = ChannelId(42);
/// let secret_id = b"secret_id";
/// let version = 1;
/// let request = generate_share_request(channel_id, secret_id, version).unwrap();
///
/// // In a real helper, this comes from secure storage.
/// let stored = StoreShareRequestMessage { share: vec![1, 2, 3], ..Default::default() };
///
/// let resp = generate_share_response(channel_id, secret_id, &request, &stored)
///     .expect("failed to build response");
///
/// assert!(resp.result.is_some());
/// assert!(!resp.committed_de_rec_share.is_empty());
/// ```
pub fn generate_share_response(
    _channel_id: ChannelId,
    _secret_id: impl AsRef<[u8]>,
    _request: &GetShareRequestMessage,
    share_content: &StoreShareRequestMessage,
) -> Result<GetShareResponseMessage, crate::Error> {
    if share_content.share.is_empty() {
        return Err(RecoveryError::EmptyCommittedDeRecShare.into());
    }
    // share_content is of type StoreShareRequestMessage
    Ok(GetShareResponseMessage {
        share_algorithm: 0,
        committed_de_rec_share: share_content.share.to_vec(),
        result: Some(DerecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
    })
}

/// Reconstructs the original secret from a set of [`GetShareResponseMessage`] values
/// collected from helpers during the DeRec *recovery* flow.
///
/// This function performs the recovery pipeline:
///
/// 1. Validate inputs (`responses`, `secret_id`, `version`)
/// 2. For each response:
///    - ensure `result.status == Ok`
///    - decode `CommittedDeRecShare`
///    - decode `DeRecShare`
///    - validate `secret_id` and `version` match the requested values
///    - map the payload into a [`VSSShare`]
/// 3. Attempt reconstruction using the VSS recovery algorithm.
///
/// # Arguments
///
/// * `responses` - Share responses collected from helpers. Must not be empty.
/// * `secret_id` - The secret identifier being recovered. Must not be empty.
/// * `version` - The version of the secret being recovered. Must be `>= 0`.
///
/// # Returns
///
/// On success returns `Vec<u8>` containing the reconstructed secret bytes.
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Recovery(...)`) in the following cases:
///
/// - `RecoveryError::EmptyResponses` if `responses` is empty.
/// - `RecoveryError::EmptySecretId` if `secret_id` is empty.
/// - `RecoveryError::InvalidVersion { .. }` if `version < 0`.
/// - `RecoveryError::MissingResult` if any response is missing the `result` field.
/// - `RecoveryError::NonOkStatus { .. }` if any response indicates a non-OK status.
/// - `RecoveryError::EmptyCommittedDeRecShare` if any response contains empty committed share bytes.
/// - `RecoveryError::DecodeCommittedDeRecShare { .. }` if committed share decoding fails.
/// - `RecoveryError::DecodeDeRecShare { .. }` if inner share decoding fails.
/// - `RecoveryError::SecretIdMismatch` if any decoded share does not match `secret_id`.
/// - `RecoveryError::VersionMismatch { .. }` if any decoded share does not match `version`.
/// - `RecoveryError::ReconstructionFailed { .. }` if the VSS reconstruction fails.
///
/// # Security Notes
///
/// - The reconstructed secret is sensitive. Callers should minimize exposure in memory,
///   avoid logging, and store it securely if persistence is required.
/// - Shares are treated as untrusted input; this function validates identity (`secret_id`)
///   and version binding before attempting reconstruction.
///
/// # Example
///
/// ```rust
/// use derec_library::recovery::*;
/// use derec_proto::GetShareResponseMessage;
///
/// let secret_id = b"secret_id";
/// let version = 1;
///
/// // In practice these come from helpers.
/// let responses: Vec<GetShareResponseMessage> = vec![];
///
/// // This will fail because responses is empty.
/// let _ = recover_from_share_responses(&responses, secret_id, version).unwrap_err();
/// ```
pub fn recover_from_share_responses(
    responses: &[GetShareResponseMessage],
    secret_id: impl AsRef<[u8]>,
    version: i32,
) -> Result<Vec<u8>, crate::Error> {
    if responses.is_empty() {
        return Err(RecoveryError::EmptyResponses.into());
    }

    let secret_id = secret_id.as_ref();
    if secret_id.is_empty() {
        return Err(RecoveryError::EmptySecretId.into());
    }

    if version < 0 {
        return Err(RecoveryError::InvalidVersion { version }.into());
    }

    let mut shares = Vec::with_capacity(responses.len());
    for res in responses {
        shares.push(extract_share_from_response(res, secret_id, version)?);
    }

    recover(&shares).map_err(|e| RecoveryError::ReconstructionFailed { source: e }.into())
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
            .map_err(|e| RecoveryError::DecodeCommittedDeRecShare { source: e })?;

    let derec_share = DeRecShare::decode(committed_derec_share.de_rec_share.as_slice())
        .map_err(|e| RecoveryError::DecodeDeRecShare { source: e })?;

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
            .iter()
            .map(|h| (h.is_left, h.hash.to_owned()))
            .collect(),
    })
}
