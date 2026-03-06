#[cfg(test)]
mod tests {
    use crate::{
        Error,
        protos::derec_proto::{StatusEnum, VerifyShareRequestMessage},
        verification::{
            VerificationError, generate_verification_request, generate_verification_response,
            verify_share_response,
        },
    };
    use sha2::{Digest, Sha384};

    #[test]
    fn test_generate_verification_response_invalid_nonce_len() {
        let secret_id = "secret_id";
        let channel_id = 1;
        let share_content = b"example_share";

        let request = VerifyShareRequestMessage {
            version: 7,
            nonce: vec![0u8; 31],
        };

        let result =
            generate_verification_response(secret_id, &channel_id.into(), share_content, &request);

        assert!(matches!(
            result,
            Err(Error::Verification(VerificationError::Invariant(msg)))
                if msg == "request nonce must be 32 bytes"
        ));
    }

    #[test]
    fn test_generate_verification_response_and_verify_success() {
        let secret_id = "secret_id";
        let target_channel = 2;
        let version = 4;

        let share_content = b"test_share_content";
        let request = generate_verification_request(secret_id, version)
            .expect("Failed to generate verification request");
        let response = generate_verification_response(
            secret_id,
            &target_channel.into(),
            share_content,
            &request,
        )
        .expect("Failed to generate verification response");

        assert_eq!(response.version, version);
        assert_eq!(response.nonce, request.nonce);
        assert_eq!(
            response.result.as_ref().unwrap().status,
            StatusEnum::Ok as i32
        );

        assert!(
            matches!(verify_share_response(secret_id, &target_channel.into(), share_content, &response), Ok(valid) if valid)
        );
    }

    #[test]
    fn test_generate_verification_response_and_verify_failure() {
        let secret_id = "secret_id";
        let target_channel = 2;
        let version = 4;

        let share_content = b"test_share_content";
        let wrong_share_content = b"wrong_content";
        let request = generate_verification_request(secret_id, version)
            .expect("Failed to generate verification request");

        let response = generate_verification_response(
            secret_id,
            &target_channel.into(),
            share_content,
            &request,
        )
        .expect("Failed to generate verification response");

        assert!(
            matches!(verify_share_response(secret_id, &target_channel.into(), wrong_share_content, &response), Ok(valid) if !valid)
        );
    }

    #[test]
    fn test_generate_verification_response_nonce_and_hash() {
        let secret_id = "secret_id";
        let version = 4;
        let channel = 5;
        let share_content = b"abc123";
        let request = generate_verification_request(secret_id, version)
            .expect("Failed to generate verification request");

        let response =
            generate_verification_response(secret_id, &channel.into(), share_content, &request)
                .expect("Failed to generate verification response");

        // Manually compute expected hash
        let mut hasher = Sha384::new();
        hasher.update(share_content);
        hasher.update(request.nonce.as_slice());
        let expected_hash = hasher.finalize().to_vec();

        assert_eq!(response.hash, expected_hash);
    }

    #[test]
    fn test_verification_fails_with_modified_nonce() {
        let secret_id = "secret_id";
        let version = 4;
        let channel = 41;
        let share_content = b"nonce_test_content";
        let request = generate_verification_request(secret_id, version)
            .expect("Failed to generate verification request");

        let mut response =
            generate_verification_response(secret_id, &channel.into(), share_content, &request)
                .expect("Failed to generate verification response");

        // Tamper with the nonce
        response.nonce[0] ^= 0xAA;

        assert!(
            matches!(verify_share_response(secret_id, &channel.into(), share_content, &response), Ok(valid) if !valid)
        );
    }
}
