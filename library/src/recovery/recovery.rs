use prost::Message;
use derec_cryptography::vss::*;
use crate::{protos::derec_proto::{
    CommittedDeRecShare,
    DeRecShare,
    StoreShareRequestMessage,
    GetShareRequestMessage,
    GetShareResponseMessage,
    Result as DerecResult,
    StatusEnum
}, types::ChannelId};
use crate::{Error, Result};

/// Generates a `GetShareRequestMessage` for requesting a secret share.
///
/// # Arguments
///
/// * `_channel_id` - The identifier of the channel (currently unused).
/// * `secret_id` - The identifier of the secret for which the share is requested.
/// * `version` - The version of the secret share to request.
///
/// # Returns
///
/// Returns `Ok(GetShareRequestMessage)` containing the constructed request message,
/// or an error string if the request could not be generated.
pub fn generate_share_request(
    _channel_id: &ChannelId,
    secret_id: impl AsRef<[u8]>,
    version: i32,
) -> GetShareRequestMessage {
    GetShareRequestMessage {
        secret_id: secret_id.as_ref().to_vec(),
        share_version: version,
    }
}

/// Generates a `GetShareResponseMessage` containing a secret share in response to a share request.
///
/// # Arguments
///
/// * `_channel_id` - The identifier of the channel (currently unused).
/// * `_request` - The original `GetShareRequestMessage` for which this response is generated (currently unused).
/// * `share_content` - The content of the share to be included in the response. This should be a byte slice or any type that can be referenced as a byte slice.
///
/// # Returns
///
/// Returns `Ok(GetShareResponseMessage)` containing the constructed response message with the share and a success status,
/// or an error string if the response could not be generated.
pub fn generate_share_response(
    _channel_id: &ChannelId,
    _secret_id: impl AsRef<[u8]>,
    _request: &GetShareRequestMessage,
    share_content: &StoreShareRequestMessage,
) -> GetShareResponseMessage {
    // share_content is of type StoreShareRequestMessage
    GetShareResponseMessage {
        share_algorithm: 0,
        committed_de_rec_share: share_content.share.to_vec(),
        result: Some(DerecResult { status: StatusEnum::Ok as i32, memo: String::new() }),
    }
}

/// Attempts to reconstruct the original secret from a collection of `GetShareResponseMessage` responses.
///
/// This function processes each response, extracting the contained share and verifying that it matches
/// the requested `secret_id` and `version`. If all shares are valid, it attempts to reconstruct the secret
/// using the underlying verifiable secret sharing (VSS) recovery mechanism.
///
/// # Arguments
///
/// * `response` - A slice of `GetShareResponseMessage` objects, each containing a share to be used in reconstruction.
/// * `secret_id` - The identifier of the secret being recovered. Used to validate that each share corresponds to the correct secret.
/// * `version` - The version of the secret to recover. Used to validate that each share is for the correct version.
///
/// # Returns
///
/// Returns `Ok(Vec<u8>)` containing the reconstructed secret if successful, or an error string if recovery fails
/// (e.g., due to invalid shares, mismatched secret IDs or versions, or insufficient shares).
///
/// # Errors
///
/// Returns an error if:
/// - Any response does not contain a valid result or indicates an error status.
/// - Any share cannot be decoded or does not match the requested secret ID or version.
/// - The secret cannot be reconstructed from the provided shares.
pub fn recover_from_share_responses(
    responses: &[GetShareResponseMessage],
    secret_id: impl AsRef<[u8]>,
    version: i32,
) -> Result<Vec<u8>> {
    let mut shares = Vec::new();
    for res in responses {
        let share = extract_share_from_response(res, &secret_id.as_ref().to_vec(), version)?;
        shares.push(share);
    }

    // Assuming we have a function to reconstruct the secret from shares
    let reconstructed_secret = recover(&shares)
        .map_err(|err| Error::Recovery(format!("Failed to reconstruct secret from shares: {err}")))?;

    Ok(reconstructed_secret)
}

fn extract_share_from_response(
    response: &GetShareResponseMessage,
    secret_id: impl AsRef<[u8]>,
    version: i32
) -> Result<VSSShare> {
    let result = response
        .result
        .as_ref()
        .ok_or(Error::MissingField("result"))?;

    if result.status != StatusEnum::Ok as i32 {
        return Err(Error::Recovery("Share response indicates an error".to_string()));
    }

    let committed_derec_share = CommittedDeRecShare::decode(response.committed_de_rec_share.as_slice())
        .map_err(|err| Error::Decode(format!("Failed to decode CommittedDeRecShare: {err}")))?;

    let derec_share = DeRecShare::decode(committed_derec_share.de_rec_share.as_slice())
        .map_err(|err| Error::Decode(format!("Failed to decode DeRecShare: {err}")))?;

    if derec_share.secret_id != secret_id.as_ref() {
        return Err(Error::Recovery("Secret ID in response does not match the requested secret ID".to_string()));
    }

    if derec_share.version != version {
        return Err(Error::Recovery("Share version in response does not match the requested version".to_string()));
    }

    let share = VSSShare {
        x: derec_share.x,
        y: derec_share.y,
        encrypted_secret: derec_share.encrypted_secret,
        commitment: committed_derec_share.commitment,
        merkle_path: committed_derec_share.merkle_path.iter().map(|h| (h.is_left, h.hash.to_owned())).collect(),
    };

    Ok(share)
}

#[cfg(test)]
mod tests {
    use crate::sharing::*;

    #[test]
    fn test_generate_share_request() {
        // This test assumes that sharing::protect_secret exists and works as expected.
        // It should generate shares for each channel, which can be verified using the verification API.

        let secret_id = b"real_secret_id";
        let secret = b"real_secret_value";
        let channels = vec![21, 22, 23];
        let threshold = 2;
        let version: i32 = 2;

        // Use the actual protect_secret API from sharing module
        let shares = sharing::protect_secret(secret_id, secret, &channels, threshold, version, None, None)
            .expect("protect_secret should succeed");

        // Simulate generating share requests and responses for each share
        let mut responses = Vec::new();
        for (i, share) in shares.iter().enumerate() {
            // Generate a share response
            let response = super::generate_share_response(
            &share.0,
            &secret_id,
            &super::generate_share_request(&channels[i], &secret_id.to_vec(), version),
            share.1,
            );

            responses.push(response);
        }

        // Attempt to recover the secret from the responses
        let recovered = super::recover_from_share_responses(&responses, &secret_id.to_vec(), version)
            .expect("recovery should succeed");

        assert_eq!(recovered, secret);
    }
}
