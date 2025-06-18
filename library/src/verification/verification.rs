use std::collections::HashMap;
use rand::RngCore;
use crate::protos::derec_proto::{
    VerifyShareRequestMessage,
    VerifyShareResponseMessage,
    Result as DerecResult,
    StatusEnum
};
use crate::types::*;
use sha2::*;

pub fn generate_verification_request(
    _secret_id: impl AsRef<[u8]>,
    channels: &[impl AsRef<[u8]>],
    version: i32,
) -> Result<HashMap<ChannelId, VerifyShareRequestMessage>, &'static str> {
    // Generate a nonce using a secure random number generator
    let mut rng = rand::rngs::OsRng;

    let mut request_map: HashMap<ChannelId, VerifyShareRequestMessage> = HashMap::new();
    for channel in channels {
        let mut nonce: Vec<u8> = vec![0; 32];
        rng.fill_bytes(&mut nonce);
        let request = VerifyShareRequestMessage { version, nonce };
        request_map.insert(channel.as_ref().to_vec(), request);
    }

    Ok(request_map)
}

pub fn generate_verification_response(
    _secret_id: impl AsRef<[u8]>,
    _channel_id: &[impl AsRef<[u8]>],
    share_content: impl AsRef<[u8]>,
    request: &VerifyShareRequestMessage,
) -> Result<VerifyShareResponseMessage, &'static str> {
    // compute the Sha384 hash of the share content
    let mut hasher = Sha384::new();
    hasher.update(share_content);
    hasher.update(request.nonce.as_slice());
    let hash = hasher.finalize().to_vec();

    let response = VerifyShareResponseMessage {
        result: Some(DerecResult { status: StatusEnum::Ok as i32, memo: String::new() }),
        version: request.version,
        nonce: request.nonce.clone(),
        hash
    };

    Ok(response)
}

pub fn verify_share_response(
    _secret_id: impl AsRef<[u8]>,
    _channel_id: &[impl AsRef<[u8]>],
    share_content: impl AsRef<[u8]>,
    response: &VerifyShareResponseMessage,
) -> Result<bool, &'static str> {
    // compute the Sha384 hash of the share content
    let mut hasher = Sha384::new();
    hasher.update(share_content);
    hasher.update(response.nonce.as_slice());
    let hash = hasher.finalize().to_vec();

    if hash == response.hash {
        Ok(true)
    } else {
        Err("Verification failed: Hash mismatch")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharing;
    use prost::Message;

    fn dummy_channel_id(n: u8) -> Vec<u8> {
        vec![n; 8]
    }

    #[test]
    fn test_generate_verification_response_and_verify_success() {
        let channel = dummy_channel_id(3);
        let share_content = b"test_share_content";
        let requests = generate_verification_request("secret", &[channel.clone()], 2).unwrap();
        let request = requests.get(&channel).unwrap();

        let response = generate_verification_response("secret", &[channel.clone()], share_content, request).unwrap();
        assert_eq!(response.version, 2);
        assert_eq!(response.nonce, request.nonce);
        assert_eq!(response.result.as_ref().unwrap().status, StatusEnum::Ok as i32);

        // Should verify successfully
        let verify = verify_share_response("secret", &[channel.clone()], share_content, &response).unwrap();
        assert!(verify);
    }

    #[test]
    fn test_generate_verification_response_and_verify_failure() {
        let channel = dummy_channel_id(4);
        let share_content = b"test_share_content";
        let wrong_share_content = b"wrong_content";
        let requests = generate_verification_request("secret", &[channel.clone()], 3).unwrap();
        let request = requests.get(&channel).unwrap();

        let response = generate_verification_response("secret", &[channel.clone()], share_content, request).unwrap();

        // Should fail verification with wrong share content
        let verify = verify_share_response("secret", &[channel.clone()], wrong_share_content, &response);
        assert!(verify.is_err());
        assert_eq!(verify.unwrap_err(), "Verification failed: Hash mismatch");
    }

    #[test]
    fn test_generate_verification_response_nonce_and_hash() {
        let channel = dummy_channel_id(5);
        let share_content = b"abc123";
        let requests = generate_verification_request("secret", &[channel.clone()], 4).unwrap();
        let request = requests.get(&channel).unwrap();

        let response = generate_verification_response("secret", &[channel.clone()], share_content, request).unwrap();

        // Manually compute expected hash
        let mut hasher = Sha384::new();
        hasher.update(share_content);
        hasher.update(request.nonce.as_slice());
        let expected_hash = hasher.finalize().to_vec();

        assert_eq!(response.hash, expected_hash);
    }

    #[test]
    fn test_verification_with_real_protect_secret_shares() {
        // This test assumes that sharing::protect_secret exists and works as expected.
        // It should generate shares for each channel, which can be verified using the verification API.

        let secret_id = b"real_secret_id";
        let secret = b"real_secret_value";
        let channels = vec![dummy_channel_id(21), dummy_channel_id(22), dummy_channel_id(23)];
        let threshold = 2;
        let version: i32 = 2;

        // Use the actual protect_secret API from sharing module
        let shares = sharing::protect_secret(secret_id, secret, &channels, threshold, version, None, None)
            .expect("protect_secret should succeed");

        // Generate verification requests for each channel
        let requests = generate_verification_request(secret_id, &channels, version).unwrap();

        for channel in &channels {
            let share = shares.get(channel).expect("Share should exist for channel");
            let share_encoded = share.encode_to_vec();
            let request = requests.get(channel).expect("Request should exist for channel");

            // Generate response
            let response = generate_verification_response(secret_id, &[channel.clone()], &share_encoded, request)
                .expect("Should generate verification response");

            // Verify response
            let verify = verify_share_response(secret_id, &[channel.clone()], &share_encoded, &response)
                .expect("Verification should succeed");
            assert!(verify, "Verification failed for channel {:?}", channel);
        }
    }

    #[test]
    fn test_verification_fails_with_modified_nonce() {
        let channel = dummy_channel_id(41);
        let share_content = b"nonce_test_content";
        let requests = generate_verification_request("secret", &[channel.clone()], 4).unwrap();
        let request = requests.get(&channel).unwrap();

        let mut response = generate_verification_response("secret", &[channel.clone()], share_content, request).unwrap();

        // Tamper with the nonce
        response.nonce[0] ^= 0xAA;

        let verify = verify_share_response("secret", &[channel.clone()], share_content, &response);
        assert!(verify.is_err());
        assert_eq!(verify.unwrap_err(), "Verification failed: Hash mismatch");
    }
}
