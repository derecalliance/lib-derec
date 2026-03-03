#[cfg(test)]
mod tests {
    use crate::{
        Error,
        protos::derec_proto::{
            CommittedDeRecShare, DeRecShare, GetShareRequestMessage, GetShareResponseMessage,
            Result as DerecResult, StatusEnum, StoreShareRequestMessage,
        },
        recovery::{
            RecoveryError, generate_share_request, generate_share_response,
            recover_from_share_responses,
        },
        sharing::{self, ProtectSecretResult},
    };
    use prost::Message;

    fn create_ok_response_with_committed_bytes(
        committed_bytes: Vec<u8>,
    ) -> GetShareResponseMessage {
        GetShareResponseMessage {
            share_algorithm: 0,
            committed_de_rec_share: committed_bytes,
            result: Some(DerecResult {
                status: StatusEnum::Ok as i32,
                memo: String::new(),
            }),
        }
    }

    fn create_response_with_status(
        status: i32,
        committed_bytes: Vec<u8>,
    ) -> GetShareResponseMessage {
        GetShareResponseMessage {
            share_algorithm: 0,
            committed_de_rec_share: committed_bytes,
            result: Some(DerecResult {
                status,
                memo: String::new(),
            }),
        }
    }

    fn create_committed_share_bytes(secret_id: &[u8], version: i32) -> Vec<u8> {
        let derec_share = DeRecShare {
            secret_id: secret_id.to_vec(),
            version,
            x: vec![1, 2, 3],
            y: vec![4, 5, 6],
            encrypted_secret: vec![7, 8, 9],
        };

        let committed = CommittedDeRecShare {
            de_rec_share: derec_share.encode_to_vec(),
            commitment: vec![10, 11, 12],
            merkle_path: vec![],
        };

        committed.encode_to_vec()
    }

    #[test]
    fn test_generate_share_request_empty_secret_id() {
        let channel_id = 1;
        let empty_secret_id = b"";
        let version = 0;

        let result = generate_share_request(&channel_id, empty_secret_id, version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::EmptySecretId))
        ));
    }

    #[test]
    fn test_generate_share_request_invalid_version() {
        let channel_id = 1;
        let secret_id = b"secret_id";
        let invalid_version = -1;

        let result = generate_share_request(&channel_id, secret_id, invalid_version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::InvalidVersion {
                version: -1
            }))
        ));
    }

    #[test]
    fn test_generate_share_response_empty_committed_share() {
        let channel_id = 1;
        let secret_id = b"secret_id";
        let request = GetShareRequestMessage {
            secret_id: secret_id.to_vec(),
            share_version: 0,
        };
        let share_content = StoreShareRequestMessage {
            share: vec![],
            ..Default::default()
        };

        let result = generate_share_response(&channel_id, secret_id, &request, &share_content);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::EmptyCommittedDeRecShare))
        ));
    }

    #[test]
    fn test_recover_from_share_responses_empty_responses() {
        let secret_id = b"secret_id";
        let version = 0;

        let result = recover_from_share_responses(&[], secret_id, version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::EmptyResponses))
        ));
    }

    #[test]
    fn test_recover_from_share_responses_empty_secret_id() {
        let responses: Vec<GetShareResponseMessage> =
            vec![create_ok_response_with_committed_bytes(vec![1])];
        let empty_secret_id = b"";
        let version = 0;

        let result = recover_from_share_responses(&responses, empty_secret_id, version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::EmptySecretId))
        ));
    }

    #[test]
    fn test_recover_from_share_responses_invalid_version() {
        let responses: Vec<GetShareResponseMessage> =
            vec![create_ok_response_with_committed_bytes(vec![1])];
        let secret_id = b"secret_id";
        let invalid_version = -1;

        let result = recover_from_share_responses(&responses, secret_id, invalid_version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::InvalidVersion {
                version: -1
            }))
        ));
    }

    #[test]
    fn test_recover_from_share_responses_missing_result() {
        let secret_id = b"secret_id";
        let version = 0;

        let responses = vec![GetShareResponseMessage {
            share_algorithm: 0,
            committed_de_rec_share: create_committed_share_bytes(secret_id, version),
            result: None,
        }];

        let result = recover_from_share_responses(&responses, secret_id, version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::MissingResult))
        ));
    }

    #[test]
    fn test_recover_from_share_responses_non_ok_status() {
        let secret_id = b"secret_id";
        let version = 0;

        let committed = create_committed_share_bytes(secret_id, version);
        let responses = vec![create_response_with_status(
            StatusEnum::Fail as i32,
            committed,
        )];

        let result = recover_from_share_responses(&responses, secret_id, version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::NonOkStatus { status })) if status == StatusEnum::Fail as i32
        ));
    }

    #[test]
    fn test_recover_from_share_responses_empty_committed_de_rec_share() {
        let secret_id = b"secret_id";
        let version = 0;

        let responses = vec![create_ok_response_with_committed_bytes(vec![])];

        let result = recover_from_share_responses(&responses, secret_id, version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::EmptyCommittedDeRecShare))
        ));
    }

    #[test]
    fn test_recover_from_share_responses_decode_committed_derec_share_error() {
        let secret_id = b"secret_id";
        let version = 0;
        let invalid_byes = vec![0xFF, 0xFF, 0xFF];

        let responses = vec![create_ok_response_with_committed_bytes(invalid_byes)];

        let result = recover_from_share_responses(&responses, secret_id, version);

        assert!(matches!(
            result,
            Err(Error::Recovery(
                RecoveryError::DecodeCommittedDeRecShare { .. }
            ))
        ));
    }

    #[test]
    fn test_recover_from_share_responses_decode_derec_share_error() {
        let secret_id = b"secret_id";
        let version = 0;
        let invalid_byes = vec![0xFF, 0xFF, 0xFF];

        let committed = CommittedDeRecShare {
            de_rec_share: invalid_byes,
            commitment: vec![1, 2, 3],
            merkle_path: vec![],
        }
        .encode_to_vec();

        let responses = vec![create_ok_response_with_committed_bytes(committed)];

        let result = recover_from_share_responses(&responses, secret_id, version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::DecodeDeRecShare { .. }))
        ));
    }

    #[test]
    fn test_recover_from_share_responses_secret_id_mismatch() {
        let requested_secret_id = b"secret_id";
        let wrong_secret_id = b"other_secret";
        let version = 0;

        let committed = create_committed_share_bytes(wrong_secret_id, version);
        let responses = vec![create_ok_response_with_committed_bytes(committed)];

        let result = recover_from_share_responses(&responses, requested_secret_id, version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::SecretIdMismatch))
        ));
    }

    #[test]
    fn test_recover_from_share_responses_version_mismatch() {
        let secret_id = b"secret_id";
        let requested_version = 7;
        let wrong_version = 8;

        let committed = create_committed_share_bytes(secret_id, wrong_version);
        let responses = vec![create_ok_response_with_committed_bytes(committed)];

        let result = recover_from_share_responses(&responses, secret_id, requested_version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::VersionMismatch { expected, got }))
                if expected == requested_version && got == wrong_version
        ));
    }

    #[test]
    fn test_recover_from_share_responses_reconstruction_failed() {
        let secret_id = b"secret_id";
        let version = 0;

        // A single valid-looking share should typically be insufficient for reconstruction,
        // causing derec_cryptography::vss::recover(...) to fail.
        let committed = create_committed_share_bytes(secret_id, version);
        let responses = vec![create_ok_response_with_committed_bytes(committed)];

        let result = recover_from_share_responses(&responses, secret_id, version);

        assert!(matches!(
            result,
            Err(Error::Recovery(RecoveryError::ReconstructionFailed { .. }))
        ));
    }

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
        let ProtectSecretResult { shares } =
            sharing::protect_secret(secret_id, secret, &channels, threshold, version, None, None)
                .expect("protect_secret should succeed");

        // Simulate generating share requests and responses for each share
        let mut responses = Vec::new();
        for (i, (channel_id, share_content)) in shares.iter().enumerate() {
            let request = generate_share_request(&channels[i], secret_id, version)
                .unwrap_or_else(|_| panic!("Failed to generate request {i}"));
            // Generate a share response
            let response = generate_share_response(channel_id, secret_id, &request, share_content)
                .unwrap_or_else(|_| panic!("Failed to generate response {i}"));

            responses.push(response);
        }

        // Attempt to recover the secret from the responses
        let recovered = recover_from_share_responses(&responses, secret_id, version)
            .expect("recovery should succeed");

        assert_eq!(recovered, secret);
    }
}
