// SPDX-License-Identifier: Apache-2.0

use crate::protos::derec_proto::{
    Result as DerecResult, StatusEnum, VerifyShareRequestMessage, VerifyShareResponseMessage,
};
use crate::types::*;
use rand::RngCore;
use sha2::*;

/// Generates a verification request for each provided channel.
///
/// This function creates a map of `ChannelId` to `VerifyShareRequestMessage`, where each request
/// contains a securely generated random nonce and the specified version. The nonce is used to
/// ensure freshness and prevent replay attacks during the verification process.
///
/// # Arguments
///
/// * `_secret_id` - An identifier for the secret (not used in this function, but may be useful for context).
/// * `channels` - A slice of channel identifiers for which to generate verification requests.
/// * `version` - The version number to include in each verification request.
///
/// # Returns
///
/// Returns a `Result` containing a `HashMap` mapping each `ChannelId` to its corresponding
/// `VerifyShareRequestMessage` on success, or an error string on failure.
///
/// # Example
///
/// ```rust
/// use crate::derec_library::verification::*;
/// let requests = generate_verification_request("secret_id", 1);
/// ```
pub fn generate_verification_request(
    _secret_id: impl AsRef<[u8]>,
    version: i32,
) -> VerifyShareRequestMessage {
    // Generate a nonce using a secure random number generator
    let mut rng = rand::rngs::OsRng;
    let mut nonce: Vec<u8> = vec![0; 32];
    rng.fill_bytes(&mut nonce);
    VerifyShareRequestMessage { version, nonce }
}

/// Generates a verification response for a given share and verification request.
///
/// This function computes a SHA-384 hash over the provided share content and the nonce from the
/// verification request. It then constructs a `VerifyShareResponseMessage` containing the hash,
/// the original nonce, the version, and a result indicating success.
///
/// # Arguments
///
/// * `_secret_id` - An identifier for the secret (not used in this function, but may be useful for context).
/// * `_channel_id` - A slice of channel identifiers (not used in this function, but may be useful for context).
/// * `share_content` - The content of the share to be verified.
/// * `request` - The original `VerifyShareRequestMessage` containing the nonce and version.
///
/// # Returns
///
/// Returns a `Result` containing the constructed `VerifyShareResponseMessage` on success,
/// or an error string on failure.
///
/// # Example
///
/// ```rust
/// use crate::derec_library::verification::*;
/// let share_content = b"example_share";
/// let channel = 2;
/// let request = generate_verification_request("secret", 101);
/// let response = generate_verification_response("secret", &channel, share_content, &request);
/// ```
pub fn generate_verification_response(
    _secret_id: impl AsRef<[u8]>,
    _channel_id: &ChannelId,
    share_content: impl AsRef<[u8]>,
    request: &VerifyShareRequestMessage,
) -> VerifyShareResponseMessage {
    // compute the Sha384 hash of the share content
    let mut hasher = Sha384::new();
    hasher.update(share_content);
    hasher.update(request.nonce.as_slice());
    let hash = hasher.finalize().to_vec();

    VerifyShareResponseMessage {
        result: Some(DerecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        version: request.version,
        nonce: request.nonce.clone(),
        hash,
    }
}

/// Verifies a share response by recomputing the hash and comparing it to the provided response.
///
/// This function takes the share content and the corresponding `VerifyShareResponseMessage`,
/// recomputes the SHA-384 hash using the share content and the nonce from the response,
/// and checks if it matches the hash included in the response. This ensures the integrity
/// and authenticity of the share content as verified by the original request's nonce.
///
/// # Arguments
///
/// * `_secret_id` - An identifier for the secret (not used in this function, but may be useful for context).
/// * `_channel_id` - A slice of channel identifiers (not used in this function, but may be useful for context).
/// * `share_content` - The content of the share to be verified.
/// * `response` - The `VerifyShareResponseMessage` containing the nonce and hash to verify against.
///
/// # Returns
///
/// Returns `Ok(true)` if the verification succeeds (hashes match), or an `Err` with an error message
/// if the verification fails (hash mismatch).
///
/// # Example
///
/// ```rust
/// use crate::derec_library::verification::*;
/// let share_content = b"example_share";
/// let channel = 2;
/// let request = generate_verification_request("secret", 100);
/// let response = generate_verification_response("secret", &channel, share_content, &request);
/// let verify = verify_share_response("secret", &channel, share_content, &response);
/// assert!(verify);
/// ```
pub fn verify_share_response(
    _secret_id: impl AsRef<[u8]>,
    _channel_id: &ChannelId,
    share_content: impl AsRef<[u8]>,
    response: &VerifyShareResponseMessage,
) -> bool {
    // compute the Sha384 hash of the share content
    let mut hasher = Sha384::new();
    hasher.update(share_content);
    hasher.update(response.nonce.as_slice());
    let hash = hasher.finalize().to_vec();

    hash == response.hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_verification_response_and_verify_success() {
        let target_channel = 2;
        let version = 4;

        let share_content = b"test_share_content";
        let request = generate_verification_request("secret", version);
        let response =
            generate_verification_response("secret", &target_channel, share_content, &request);

        assert_eq!(response.version, version);
        assert_eq!(response.nonce, request.nonce);
        assert_eq!(
            response.result.as_ref().unwrap().status,
            StatusEnum::Ok as i32
        );

        // Should verify successfully
        assert!(verify_share_response(
            "secret",
            &target_channel,
            share_content,
            &response
        ));
    }

    #[test]
    fn test_generate_verification_response_and_verify_failure() {
        let target_channel = 2;
        let version = 3;

        let share_content = b"test_share_content";
        let wrong_share_content = b"wrong_content";
        let request = generate_verification_request("secret", version);

        let response =
            generate_verification_response("secret", &target_channel, share_content, &request);

        // Should fail verification with wrong share content
        assert!(!verify_share_response(
            "secret",
            &target_channel,
            wrong_share_content,
            &response
        ));
    }

    #[test]
    fn test_generate_verification_response_nonce_and_hash() {
        let channel = 5;
        let share_content = b"abc123";
        let request = generate_verification_request("secret", 4);

        let response = generate_verification_response("secret", &channel, share_content, &request);

        // Manually compute expected hash
        let mut hasher = Sha384::new();
        hasher.update(share_content);
        hasher.update(request.nonce.as_slice());
        let expected_hash = hasher.finalize().to_vec();

        assert_eq!(response.hash, expected_hash);
    }

    #[test]
    fn test_verification_fails_with_modified_nonce() {
        let share_content = b"nonce_test_content";
        let request = generate_verification_request("secret", 4);

        let mut response = generate_verification_response("secret", &41, share_content, &request);

        // Tamper with the nonce
        response.nonce[0] ^= 0xAA;

        assert!(!verify_share_response(
            "secret",
            &41,
            share_content,
            &response
        ));
    }
}
