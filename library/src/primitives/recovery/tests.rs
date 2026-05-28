use crate::{
    Error,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    primitives::make_shared_key,
    primitives::{
        recovery::{
            RecoveryError,
            request::{
                ExtractResult as ExtractGetShareRequestResult,
                ProduceResult as ProduceGetShareRequestMessageResult,
                extract as extract_get_share_request, produce as produce_get_share_request_message,
            },
            response::{
                ExtractResult as ExtractGetShareResponseResult,
                ProduceResult as ProduceGetShareResponseMessageResult,
                RecoverResult as RecoverFromResponsesResult,
                extract as extract_get_share_response,
                produce as produce_get_share_response_message,
                recover as recover_from_share_responses,
            },
        },
        sharing::request::{
            SplitResult, extract as extract_store_share_request, split as sharing_split,
        },
    },
    types::ChannelId,
};
use derec_proto::{
    CommittedDeRecShare, DeRecResult, DeRecShare, GetShareResponseMessage, MessageBody, StatusEnum,
    StoreShareRequestMessage,
};
use prost::Message;

fn make_channel_ids(ids: &[u64]) -> Vec<ChannelId> {
    ids.iter().copied().map(ChannelId).collect()
}

fn create_committed_share_bytes(secret_id: u64, version: u32) -> Vec<u8> {
    let derec_share = DeRecShare {
        secret_id,
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

fn create_response_envelope(
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
        secret_id: 0,
        version: 0,
    };

    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetShareResponse(message))
        .encrypt(shared_key)
        .expect("failed to encrypt response")
        .build()
        .expect("failed to build response envelope")
        .encode_to_vec()
}

fn create_response_envelope_with_mismatched_timestamp(
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
        secret_id: 0,
        version: 0,
    };

    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message_body(MessageBody::GetShareResponse(message))
        .encrypt(shared_key)
        .expect("failed to encrypt response")
        .build()
        .expect("failed to build response envelope")
        .encode_to_vec()
}

fn create_store_share_request_envelope(
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
        secret_id: 1,
    };

    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::StoreShareRequest(message))
        .encrypt(shared_key)
        .expect("failed to encrypt stored share")
        .build()
        .expect("failed to build stored share envelope")
        .encode_to_vec()
}

#[test]
fn test_produce_get_share_response_message_empty_committed_share() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let secret_id = 123;
    let version = 1;

    let ProduceGetShareRequestMessageResult {
        envelope: request_envelope,
    } = produce_get_share_request_message(channel_id, secret_id, version, &shared_key)
        .expect("request generation should succeed");

    let ExtractGetShareRequestResult { request } =
        extract_get_share_request(&request_envelope, &shared_key)
            .expect("extract_get_share_request should succeed");

    let stored_share_envelope =
        create_store_share_request_envelope(channel_id, &shared_key, vec![]);
    let crate::primitives::sharing::request::ExtractResult {
        request: stored_share_request,
    } = extract_store_share_request(&stored_share_envelope, &shared_key)
        .expect("extract_store_share_request should succeed");

    let result = produce_get_share_response_message(
        channel_id,
        &request,
        &stored_share_request,
        &shared_key,
    );

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::EmptyCommittedDeRecShare))
    ));
}

#[test]
fn test_recover_from_share_responses_empty_responses() {
    let secret_id = 1;
    let version = 0;

    let empty: Vec<&derec_proto::GetShareResponseMessage> = vec![];
    let result = recover_from_share_responses(secret_id, version, &empty);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::EmptyResponses))
    ));
}

#[test]
fn test_recover_from_share_responses_missing_result() {
    let secret_id = 123;
    let version = 0;
    let shared_key = make_shared_key(1);

    let response_envelope = create_response_envelope(
        ChannelId(1),
        &shared_key,
        None,
        create_committed_share_bytes(secret_id, version),
    );
    let ExtractGetShareResponseResult { response } =
        extract_get_share_response(&response_envelope, &shared_key)
            .expect("extract should succeed");
    let responses = vec![&response];

    let result = recover_from_share_responses(secret_id, version, &responses);

    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_recover_from_share_responses_non_ok_status() {
    let secret_id = 123;
    let version = 0;
    let shared_key = make_shared_key(1);

    let response_envelope = create_response_envelope(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Fail as i32),
        create_committed_share_bytes(secret_id, version),
    );
    let ExtractGetShareResponseResult { response } =
        extract_get_share_response(&response_envelope, &shared_key)
            .expect("extract should succeed");
    let responses = vec![&response];

    let result = recover_from_share_responses(secret_id, version, &responses);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::NonOkStatus { status, .. }))
            if status == StatusEnum::Fail as i32
    ));
}

#[test]
fn test_recover_from_share_responses_empty_committed_de_rec_share() {
    let secret_id = 123;
    let version = 0;
    let shared_key = make_shared_key(1);

    let response_envelope = create_response_envelope(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        vec![],
    );
    let ExtractGetShareResponseResult { response } =
        extract_get_share_response(&response_envelope, &shared_key)
            .expect("extract should succeed");
    let responses = vec![&response];

    let result = recover_from_share_responses(secret_id, version, &responses);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::EmptyCommittedDeRecShare))
    ));
}

#[test]
fn test_recover_from_share_responses_decode_committed_derec_share_error() {
    let secret_id = 123;
    let version = 0;
    let shared_key = make_shared_key(1);
    let invalid_bytes = vec![0xFF, 0xFF, 0xFF];

    let response_envelope = create_response_envelope(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        invalid_bytes,
    );
    let ExtractGetShareResponseResult { response } =
        extract_get_share_response(&response_envelope, &shared_key)
            .expect("extract should succeed");
    let responses = vec![&response];

    let result = recover_from_share_responses(secret_id, version, &responses);

    assert!(matches!(
        result,
        Err(Error::Recovery(
            RecoveryError::DecodeCommittedDeRecShare { .. }
        ))
    ));
}

#[test]
fn test_recover_from_share_responses_decode_derec_share_error() {
    let secret_id = 123;
    let version = 0;
    let shared_key = make_shared_key(1);
    let invalid_bytes = vec![0xFF, 0xFF, 0xFF];

    let committed = CommittedDeRecShare {
        de_rec_share: invalid_bytes,
        commitment: vec![1, 2, 3],
        merkle_path: vec![],
    }
    .encode_to_vec();

    let response_envelope = create_response_envelope(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        committed,
    );
    let ExtractGetShareResponseResult { response } =
        extract_get_share_response(&response_envelope, &shared_key)
            .expect("extract should succeed");
    let responses = vec![&response];

    let result = recover_from_share_responses(secret_id, version, &responses);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::DecodeDeRecShare { .. }))
    ));
}

#[test]
fn test_recover_from_share_responses_secret_id_mismatch() {
    let requested_secret_id = 123;
    let wrong_secret_id = 456;
    let version = 0;
    let shared_key = make_shared_key(1);

    let response_envelope = create_response_envelope(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        create_committed_share_bytes(wrong_secret_id, version),
    );
    let ExtractGetShareResponseResult { response } =
        extract_get_share_response(&response_envelope, &shared_key)
            .expect("extract should succeed");
    let responses = vec![&response];

    let result = recover_from_share_responses(requested_secret_id, version, &responses);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::SecretIdMismatch))
    ));
}

#[test]
fn test_recover_from_share_responses_version_mismatch() {
    let secret_id = 123;
    let requested_version = 7;
    let wrong_version = 8;
    let shared_key = make_shared_key(1);

    let response_envelope = create_response_envelope(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        create_committed_share_bytes(secret_id, wrong_version),
    );
    let ExtractGetShareResponseResult { response } =
        extract_get_share_response(&response_envelope, &shared_key)
            .expect("extract should succeed");
    let responses = vec![&response];

    let result = recover_from_share_responses(secret_id, requested_version, &responses);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::VersionMismatch { expected, got }))
            if expected == requested_version && got == wrong_version
    ));
}

#[test]
fn test_recover_from_share_responses_reconstruction_failed() {
    let secret_id = 123;
    let version = 0;
    let shared_key = make_shared_key(1);

    let response_envelope = create_response_envelope(
        ChannelId(1),
        &shared_key,
        Some(StatusEnum::Ok as i32),
        create_committed_share_bytes(secret_id, version),
    );
    let ExtractGetShareResponseResult { response } =
        extract_get_share_response(&response_envelope, &shared_key)
            .expect("extract should succeed");
    let responses = vec![&response];

    let result = recover_from_share_responses(secret_id, version, &responses);

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::ReconstructionFailed { .. }))
    ));
}

#[test]
fn test_extract_get_share_response_timestamp_mismatch() {
    let secret_id = 123;
    let version = 0;
    let shared_key = make_shared_key(1);

    let response_envelope = create_response_envelope_with_mismatched_timestamp(
        ChannelId(1),
        &shared_key,
        create_committed_share_bytes(secret_id, version),
    );

    let result = extract_get_share_response(&response_envelope, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Invariant(
            "Envelope timestamp does not match response timestamp"
        ))
    ));
}

#[test]
fn test_produce_get_share_response_message_request_timestamp_mismatch() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let secret_id = 123;
    let version = 0;

    let message_timestamp = current_timestamp();
    let mut envelope_timestamp = message_timestamp;
    envelope_timestamp.seconds += 1;

    let tampered_request_message = derec_proto::GetShareRequestMessage {
        secret_id,
        version,
        timestamp: Some(message_timestamp),
    };

    let tampered_request_envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message_body(MessageBody::GetShareRequest(tampered_request_message))
        .encrypt(&shared_key)
        .expect("failed to encrypt tampered request")
        .build()
        .expect("failed to build tampered request")
        .encode_to_vec();

    let result = extract_get_share_request(&tampered_request_envelope, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Invariant(
            "Envelope timestamp does not match request timestamp"
        ))
    ));
}

#[test]
fn test_produce_get_share_response_message_stored_share_timestamp_mismatch() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let secret_id = 123;
    let version = 0;

    let ProduceGetShareRequestMessageResult {
        envelope: request_envelope,
    } = produce_get_share_request_message(channel_id, secret_id, version, &shared_key)
        .expect("request generation should succeed");

    let ExtractGetShareRequestResult { request } =
        extract_get_share_request(&request_envelope, &shared_key)
            .expect("extract_get_share_request should succeed");

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
        secret_id,
    };

    let tampered_stored_share_envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message_body(MessageBody::StoreShareRequest(stored_share_message))
        .encrypt(&shared_key)
        .expect("failed to encrypt tampered stored share")
        .build()
        .expect("failed to build tampered stored share")
        .encode_to_vec();

    let result = extract_store_share_request(&tampered_stored_share_envelope, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Invariant(
            "Envelope timestamp does not match request timestamp"
        ))
    ));

    // Also verify produce_get_share_response_message works with correct stored share
    let stored_share_envelope = create_store_share_request_envelope(
        channel_id,
        &shared_key,
        create_committed_share_bytes(secret_id, version),
    );
    let crate::primitives::sharing::request::ExtractResult {
        request: stored_share_request,
    } = extract_store_share_request(&stored_share_envelope, &shared_key)
        .expect("extract should succeed");

    let _ = produce_get_share_response_message(
        channel_id,
        &request,
        &stored_share_request,
        &shared_key,
    )
    .expect("produce_get_share_response_message should succeed with correct data");
}

#[test]
fn test_produce_get_share_response_message_secret_id_mismatch() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let requested_secret_id = 123;
    let stored_secret_id = 567;
    let version = 0;

    let ProduceGetShareRequestMessageResult {
        envelope: request_envelope,
    } = produce_get_share_request_message(channel_id, requested_secret_id, version, &shared_key)
        .expect("request generation should succeed");

    let ExtractGetShareRequestResult { request } =
        extract_get_share_request(&request_envelope, &shared_key)
            .expect("extract_get_share_request should succeed");

    let stored_share_envelope = create_store_share_request_envelope(
        channel_id,
        &shared_key,
        create_committed_share_bytes(stored_secret_id, version),
    );
    let crate::primitives::sharing::request::ExtractResult {
        request: stored_share_request,
    } = extract_store_share_request(&stored_share_envelope, &shared_key)
        .expect("extract_store_share_request should succeed");

    let result = produce_get_share_response_message(
        channel_id,
        &request,
        &stored_share_request,
        &shared_key,
    );

    assert!(matches!(
        result,
        Err(Error::Recovery(RecoveryError::SecretIdMismatch))
    ));
}

#[test]
fn test_produce_get_share_response_message_version_mismatch() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let secret_id = 123;
    let requested_version = 7;
    let stored_version = 8;

    let ProduceGetShareRequestMessageResult {
        envelope: request_envelope,
    } = produce_get_share_request_message(channel_id, secret_id, requested_version, &shared_key)
        .expect("request generation should succeed");

    let ExtractGetShareRequestResult { request } =
        extract_get_share_request(&request_envelope, &shared_key)
            .expect("extract_get_share_request should succeed");

    let stored_share_envelope = create_store_share_request_envelope(
        channel_id,
        &shared_key,
        create_committed_share_bytes(secret_id, stored_version),
    );
    let crate::primitives::sharing::request::ExtractResult {
        request: stored_share_request,
    } = extract_store_share_request(&stored_share_envelope, &shared_key)
        .expect("extract_store_share_request should succeed");

    let result = produce_get_share_response_message(
        channel_id,
        &request,
        &stored_share_request,
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
    let secret_id = 123;
    let secret = b"real_secret_value";
    let shared_key = make_shared_key(42);
    let channel_ids = make_channel_ids(&[21, 22, 23]);
    let threshold = 2;
    let version = 2;

    let SplitResult { shares } = sharing_split(&channel_ids, secret_id, version, secret, threshold)
        .expect("split should succeed");

    let mut response_messages: Vec<GetShareResponseMessage> = Vec::new();

    for channel_id in &channel_ids {
        let ProduceGetShareRequestMessageResult {
            envelope: request_envelope,
        } = produce_get_share_request_message(*channel_id, secret_id, version, &shared_key)
            .expect("produce_get_share_request_message should succeed");

        let ExtractGetShareRequestResult { request } =
            extract_get_share_request(&request_envelope, &shared_key)
                .expect("extract_get_share_request should succeed");

        // Wrap the CommittedDeRecShare into an encrypted StoreShareRequestMessage envelope.
        let committed_share = shares
            .get(channel_id)
            .expect("missing committed share for channel");

        let timestamp = current_timestamp();
        let store_msg = StoreShareRequestMessage {
            share: committed_share.encode_to_vec(),
            share_algorithm: 0,
            version,
            keep_list: vec![],
            version_description: String::new(),
            timestamp: Some(timestamp),
            secret_id,
        };
        let stored_share_envelope = DeRecMessageBuilder::channel()
            .channel_id(*channel_id)
            .timestamp(timestamp)
            .message_body(MessageBody::StoreShareRequest(store_msg))
            .encrypt(&shared_key)
            .expect("encryption should succeed")
            .build()
            .expect("build should succeed")
            .encode_to_vec();

        let crate::primitives::sharing::request::ExtractResult {
            request: stored_share_request,
        } = extract_store_share_request(&stored_share_envelope, &shared_key)
            .expect("extract_store_share_request should succeed");

        let ProduceGetShareResponseMessageResult {
            envelope: response_envelope,
        } = produce_get_share_response_message(
            *channel_id,
            &request,
            &stored_share_request,
            &shared_key,
        )
        .expect("produce_get_share_response_message should succeed");

        let ExtractGetShareResponseResult { response } =
            extract_get_share_response(&response_envelope, &shared_key)
                .expect("extract_get_share_response should succeed");

        response_messages.push(response);
    }

    let responses: Vec<&_> = response_messages.iter().collect();

    let RecoverFromResponsesResult { secret_data } =
        recover_from_share_responses(secret_id, version, &responses)
            .expect("recovery should succeed");

    assert_eq!(secret_data, secret);
}
