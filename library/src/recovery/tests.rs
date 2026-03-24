use crate::{
    Error,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    recovery::{
        GenerateShareRequestResult, GenerateShareResponseResult, RecoverFromResponsesResult,
        RecoveryError, generate_share_request, generate_share_response,
        recover_from_share_responses,
    },
    sharing::{self, ProtectSecretResult},
    types::ChannelId,
};
use derec_proto::{
    CommittedDeRecShare, DeRecResult, DeRecShare, GetShareResponseMessage, StatusEnum,
    StoreShareRequestMessage,
};
use prost::Message;
use std::collections::HashMap;

fn make_shared_key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn make_channels(ids: &[u64], shared_key: [u8; 32]) -> HashMap<ChannelId, [u8; 32]> {
    ids.iter()
        .copied()
        .map(|id| (ChannelId(id), shared_key))
        .collect()
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

fn create_response_wire_bytes(
    channel_id: ChannelId,
    shared_key: &[u8; 32],
    status: Option<i32>,
    committed_bytes: Vec<u8>,
) -> Vec<u8> {
    let timestamp = current_timestamp();

    let message = GetShareResponseMessage {
        share_algorithm: 0,
        committed_de_rec_share: committed_bytes,
        result: status.map(|status| DeRecResult {
            status,
            memo: String::new(),
        }),
        timestamp: Some(timestamp),
    };

    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(&message)
        .encrypt(shared_key)
        .expect("failed to encrypt response")
        .build()
        .expect("failed to build response envelope")
        .encode_to_vec()
}

fn create_response_wire_bytes_with_mismatched_timestamp(
    channel_id: ChannelId,
    shared_key: &[u8; 32],
    committed_bytes: Vec<u8>,
) -> Vec<u8> {
    let message_timestamp = current_timestamp();
    let mut envelope_timestamp = message_timestamp;
    envelope_timestamp.seconds += 1;

    let message = GetShareResponseMessage {
        share_algorithm: 0,
        committed_de_rec_share: committed_bytes,
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        timestamp: Some(message_timestamp),
    };

    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message(&message)
        .encrypt(shared_key)
        .expect("failed to encrypt response")
        .build()
        .expect("failed to build response envelope")
        .encode_to_vec()
}

fn create_store_share_request_wire_bytes(
    channel_id: ChannelId,
    shared_key: &[u8; 32],
    share_bytes: Vec<u8>,
) -> Vec<u8> {
    let timestamp = current_timestamp();

    let message = StoreShareRequestMessage {
        share: share_bytes,
        share_algorithm: 0,
        version: 0,
        keep_list: vec![],
        version_description: String::new(),
        timestamp: Some(timestamp),
    };

    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(&message)
        .encrypt(shared_key)
        .expect("failed to encrypt stored share")
        .build()
        .expect("failed to build stored share envelope")
        .encode_to_vec()
}

#[test]
fn test_generate_share_request_empty_secret_id() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let empty_secret_id = b"";
    let version = 0;

    let result = generate_share_request(channel_id, empty_secret_id, version, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::EmptySecretId))
    ));
}

#[test]
fn test_generate_share_request_invalid_version() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let secret_id = b"secret_id";
    let invalid_version = -1;

    let result = generate_share_request(channel_id, secret_id, invalid_version, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::InvalidVersion {
            version: -1
        }))
    ));
}

#[test]
fn test_generate_share_response_empty_committed_share() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let secret_id = b"secret_id";
    let version = 0;

    let GenerateShareRequestResult {
        wire_bytes: request,
    } = generate_share_request(channel_id, secret_id, version, &shared_key)
        .expect("request generation should succeed");

    let stored_share_wire_bytes =
        create_store_share_request_wire_bytes(channel_id, &shared_key, vec![]);

    let result = generate_share_response(
        channel_id,
        secret_id,
        &request,
        &stored_share_wire_bytes,
        &shared_key,
    );

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::EmptyCommittedDeRecShare))
    ));
}

#[test]
fn test_recover_from_share_responses_empty_responses() {
    let secret_id = b"secret_id";
    let version = 0;
    let shared_key = make_shared_key(1);

    let empty: Vec<Vec<u8>> = vec![];
    let result = recover_from_share_responses(&empty, secret_id, version, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::EmptyResponses))
    ));
}

#[test]
fn test_recover_from_share_responses_empty_secret_id() {
    let shared_key = make_shared_key(1);
    let responses = vec![create_response_wire_bytes(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        vec![1],
    )];
    let empty_secret_id = b"";
    let version = 0;

    let result = recover_from_share_responses(&responses, empty_secret_id, version, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::EmptySecretId))
    ));
}

#[test]
fn test_recover_from_share_responses_invalid_version() {
    let shared_key = make_shared_key(1);
    let responses = vec![create_response_wire_bytes(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        vec![1],
    )];
    let secret_id = b"secret_id";
    let invalid_version = -1;

    let result = recover_from_share_responses(&responses, secret_id, invalid_version, &shared_key);

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
    let shared_key = make_shared_key(1);

    let responses = vec![create_response_wire_bytes(
        ChannelId(1),
        &shared_key,
        None,
        create_committed_share_bytes(secret_id, version),
    )];

    let result = recover_from_share_responses(&responses, secret_id, version, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::MissingResult))
    ));
}

#[test]
fn test_recover_from_share_responses_non_ok_status() {
    let secret_id = b"secret_id";
    let version = 0;
    let shared_key = make_shared_key(1);

    let responses = vec![create_response_wire_bytes(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Fail as i32),
        create_committed_share_bytes(secret_id, version),
    )];

    let result = recover_from_share_responses(&responses, secret_id, version, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::NonOkStatus { status }))
            if status == StatusEnum::Fail as i32
    ));
}

#[test]
fn test_recover_from_share_responses_empty_committed_de_rec_share() {
    let secret_id = b"secret_id";
    let version = 0;
    let shared_key = make_shared_key(1);

    let responses = vec![create_response_wire_bytes(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        vec![],
    )];

    let result = recover_from_share_responses(&responses, secret_id, version, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::EmptyCommittedDeRecShare))
    ));
}

#[test]
fn test_recover_from_share_responses_decode_committed_derec_share_error() {
    let secret_id = b"secret_id";
    let version = 0;
    let shared_key = make_shared_key(1);
    let invalid_bytes = vec![0xFF, 0xFF, 0xFF];

    let responses = vec![create_response_wire_bytes(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        invalid_bytes,
    )];

    let result = recover_from_share_responses(&responses, secret_id, version, &shared_key);

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
    let shared_key = make_shared_key(1);
    let invalid_bytes = vec![0xFF, 0xFF, 0xFF];

    let committed = CommittedDeRecShare {
        de_rec_share: invalid_bytes,
        commitment: vec![1, 2, 3],
        merkle_path: vec![],
    }
    .encode_to_vec();

    let responses = vec![create_response_wire_bytes(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        committed,
    )];

    let result = recover_from_share_responses(&responses, secret_id, version, &shared_key);

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
    let shared_key = make_shared_key(1);

    let responses = vec![create_response_wire_bytes(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        create_committed_share_bytes(wrong_secret_id, version),
    )];

    let result =
        recover_from_share_responses(&responses, requested_secret_id, version, &shared_key);

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
    let shared_key = make_shared_key(1);

    let responses = vec![create_response_wire_bytes(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        create_committed_share_bytes(secret_id, wrong_version),
    )];

    let result =
        recover_from_share_responses(&responses, secret_id, requested_version, &shared_key);

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
    let shared_key = make_shared_key(1);

    let responses = vec![create_response_wire_bytes(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        create_committed_share_bytes(secret_id, version),
    )];

    let result = recover_from_share_responses(&responses, secret_id, version, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::ReconstructionFailed { .. }))
    ));
}

#[test]
fn test_recover_from_share_responses_response_timestamp_mismatch() {
    let secret_id = b"secret_id";
    let version = 0;
    let shared_key = make_shared_key(1);

    let responses = vec![create_response_wire_bytes_with_mismatched_timestamp(
        ChannelId(1),
        &shared_key,
        create_committed_share_bytes(secret_id, version),
    )];

    let result = recover_from_share_responses(&responses, secret_id, version, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Invariant(
            "Envelope timestamp does not match response timestamp"
        ))
    ));
}

#[test]
fn test_generate_share_response_request_timestamp_mismatch() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let secret_id = b"secret_id";
    let version = 0;

    let message_timestamp = current_timestamp();
    let mut envelope_timestamp = message_timestamp;
    envelope_timestamp.seconds += 1;

    let tampered_request_message = derec_proto::GetShareRequestMessage {
        secret_id: secret_id.to_vec(),
        share_version: version,
        timestamp: Some(message_timestamp),
    };

    let tampered_request_wire_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message(&tampered_request_message)
        .encrypt(&shared_key)
        .expect("failed to encrypt tampered request")
        .build()
        .expect("failed to build tampered request")
        .encode_to_vec();

    let stored_share_wire_bytes = create_store_share_request_wire_bytes(
        channel_id,
        &shared_key,
        create_committed_share_bytes(secret_id, version),
    );

    let result = generate_share_response(
        channel_id,
        secret_id,
        &tampered_request_wire_bytes,
        &stored_share_wire_bytes,
        &shared_key,
    );

    assert!(matches!(
        result,
        Err(Error::Invariant(
            "Envelope timestamp does not match request timestamp"
        ))
    ));
}

#[test]
fn test_generate_share_response_stored_share_timestamp_mismatch() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let secret_id = b"secret_id";
    let version = 0;

    let GenerateShareRequestResult {
        wire_bytes: request,
    } = generate_share_request(channel_id, secret_id, version, &shared_key)
        .expect("request generation should succeed");

    let message_timestamp = current_timestamp();
    let mut envelope_timestamp = message_timestamp;
    envelope_timestamp.seconds += 1;

    let stored_share_message = StoreShareRequestMessage {
        share: create_committed_share_bytes(secret_id, version),
        share_algorithm: 0,
        version,
        keep_list: vec![],
        version_description: String::new(),
        timestamp: Some(message_timestamp),
    };

    let tampered_stored_share_wire_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message(&stored_share_message)
        .encrypt(&shared_key)
        .expect("failed to encrypt tampered stored share")
        .build()
        .expect("failed to build tampered stored share")
        .encode_to_vec();

    let result = generate_share_response(
        channel_id,
        secret_id,
        &request,
        &tampered_stored_share_wire_bytes,
        &shared_key,
    );

    assert!(matches!(
        result,
        Err(Error::Invariant(
            "Envelope timestamp does not match stored share request timestamp"
        ))
    ));
}

#[test]
fn test_generate_share_response_secret_id_mismatch() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let requested_secret_id = b"secret_id";
    let stored_secret_id = b"other_secret";
    let version = 0;

    let GenerateShareRequestResult {
        wire_bytes: request,
    } = generate_share_request(channel_id, requested_secret_id, version, &shared_key)
        .expect("request generation should succeed");

    let stored_share_wire_bytes = create_store_share_request_wire_bytes(
        channel_id,
        &shared_key,
        create_committed_share_bytes(stored_secret_id, version),
    );

    let result = generate_share_response(
        channel_id,
        requested_secret_id,
        &request,
        &stored_share_wire_bytes,
        &shared_key,
    );

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::SecretIdMismatch))
    ));
}

#[test]
fn test_generate_share_response_version_mismatch() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let secret_id = b"secret_id";
    let requested_version = 7;
    let stored_version = 8;

    let GenerateShareRequestResult {
        wire_bytes: request,
    } = generate_share_request(channel_id, secret_id, requested_version, &shared_key)
        .expect("request generation should succeed");

    let stored_share_wire_bytes = create_store_share_request_wire_bytes(
        channel_id,
        &shared_key,
        create_committed_share_bytes(secret_id, stored_version),
    );

    let result = generate_share_response(
        channel_id,
        secret_id,
        &request,
        &stored_share_wire_bytes,
        &shared_key,
    );

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::VersionMismatch { expected, got }))
            if expected == requested_version && got == stored_version
    ));
}

#[test]
fn test_recovery_end_to_end() {
    let secret_id = b"real_secret_id";
    let secret = b"real_secret_value";
    let shared_key = make_shared_key(42);
    let channels = make_channels(&[21, 22, 23], shared_key);
    let threshold = 2;
    let version = 2;

    let ProtectSecretResult { shares } = sharing::protect_secret(
        secret_id,
        secret,
        channels.clone(),
        threshold,
        version,
        None,
        None,
    )
    .expect("protect_secret should succeed");

    let mut responses = Vec::new();

    for channel_id in channels.keys() {
        let GenerateShareRequestResult {
            wire_bytes: request,
        } = generate_share_request(*channel_id, secret_id, version, &shared_key)
            .expect("generate_share_request should succeed");

        let stored_share_wire_bytes = shares
            .get(channel_id)
            .expect("missing stored share envelope for channel");

        let GenerateShareResponseResult {
            wire_bytes: response,
        } = generate_share_response(
            *channel_id,
            secret_id,
            &request,
            stored_share_wire_bytes,
            &shared_key,
        )
        .expect("generate_share_response should succeed");

        responses.push(response);
    }

    let RecoverFromResponsesResult { secret_data } =
        recover_from_share_responses(&responses, secret_id, version, &shared_key)
            .expect("recovery should succeed");

    assert_eq!(secret_data, secret);
}
