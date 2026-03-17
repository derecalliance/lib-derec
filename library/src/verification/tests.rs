use crate::{
    types::ChannelId,
    verification::{
        generate_verification_request, generate_verification_response, verify_share_response,
    },
};
use derec_proto::StatusEnum;
use sha2::{Digest, Sha384};

#[test]
fn test_generate_verification_response_and_verify_success() {
    let secret_id = "secret_id";
    let target_channel = ChannelId(2);
    let version = 4;

    let share_content = b"test_share_content";
    let request = generate_verification_request(secret_id, version)
        .expect("Failed to generate verification request");
    let response =
        generate_verification_response(secret_id, target_channel, share_content, &request)
            .expect("Failed to generate verification response");

    assert_eq!(response.version, version);
    assert_eq!(response.nonce, request.nonce);
    assert_eq!(
        response.result.as_ref().unwrap().status,
        StatusEnum::Ok as i32
    );

    assert!(
        matches!(verify_share_response(secret_id, target_channel, share_content, &response), Ok(valid) if valid)
    );
}

#[test]
fn test_generate_verification_response_and_verify_failure() {
    let secret_id = "secret_id";
    let target_channel = ChannelId(2);
    let version = 4;

    let share_content = b"test_share_content";
    let wrong_share_content = b"wrong_content";
    let request = generate_verification_request(secret_id, version)
        .expect("Failed to generate verification request");

    let response =
        generate_verification_response(secret_id, target_channel, share_content, &request)
            .expect("Failed to generate verification response");

    assert!(
        matches!(verify_share_response(secret_id, target_channel, wrong_share_content, &response), Ok(valid) if !valid)
    );
}

#[test]
fn test_generate_verification_response_nonce_and_hash() {
    let secret_id = "secret_id";
    let version = 4;
    let channel_id = ChannelId(1);
    let share_content = b"abc123";
    let request = generate_verification_request(secret_id, version)
        .expect("Failed to generate verification request");

    let response = generate_verification_response(secret_id, channel_id, share_content, &request)
        .expect("Failed to generate verification response");

    // Manually compute expected hash
    let mut hasher = Sha384::new();
    hasher.update(share_content);
    hasher.update(request.nonce.to_be_bytes());
    let expected_hash = hasher.finalize().to_vec();

    assert_eq!(response.hash, expected_hash);
}

#[test]
fn test_verification_fails_with_modified_nonce() {
    let secret_id = "secret_id";
    let version = 4;
    let channel_id = ChannelId(1);

    let share_content = b"nonce_test_content";
    let request = generate_verification_request(secret_id, version)
        .expect("Failed to generate verification request");

    let mut response =
        generate_verification_response(secret_id, channel_id, share_content, &request)
            .expect("Failed to generate verification response");

    // Tamper with the nonce
    response.nonce = 123;

    assert!(
        matches!(verify_share_response(secret_id, channel_id, share_content, &response), Ok(valid) if !valid)
    );
}
