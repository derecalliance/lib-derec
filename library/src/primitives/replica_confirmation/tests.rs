// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    primitives::replica_confirmation::{
        ReplicaConfirmationError,
        request::{
            ExtractResult as ExtractRequestResult,
            ProduceResult as ProduceRequestResult,
            extract as extract_request,
            produce as produce_request,
            verify_fingerprint,
        },
        response::{
            ExtractResult as ExtractResponseResult,
            ProcessResult,
            ProduceResult as ProduceResponseResult,
            extract as extract_response,
            process as process_response,
            produce as produce_response,
        },
    },
    types::ChannelId,
};
use derec_proto::{
    DeRecResult, MessageBody, ReplicaConfirmationResponseMessage, StatusEnum,
};
use prost::Message;

fn make_shared_key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

// ─── request::produce ───────────────────────────────────────────────────────

#[test]
fn test_produce_request_returns_non_empty_envelope_and_fingerprint() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceRequestResult {
        envelope,
        fingerprint,
    } = produce_request(channel_id, &shared_key, 100)
        .expect("produce should succeed");

    assert!(!envelope.is_empty());
    assert_eq!(fingerprint.len(), 16);
    assert!(fingerprint.iter().all(|&d| d < 10));
}

#[test]
fn test_produce_request_fingerprint_matches_crypto() {
    let shared_key = make_shared_key(42);
    let expected = derec_cryptography::replica::fingerprint(&shared_key);

    let ProduceRequestResult { fingerprint, .. } =
        produce_request(ChannelId(1), &shared_key, 1).expect("produce should succeed");

    assert_eq!(fingerprint, expected);
}

// ─── request::extract ───────────────────────────────────────────────────────

#[test]
fn test_produce_extract_request_roundtrip() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceRequestResult { envelope, .. } =
        produce_request(channel_id, &shared_key, 42).expect("produce should succeed");

    let ExtractRequestResult { request } =
        extract_request(&envelope, &shared_key).expect("extract should succeed");

    assert_eq!(request.replica_id, 42);
    assert!(request.timestamp.is_some());
}

#[test]
fn test_extract_request_wrong_key_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let wrong_key = make_shared_key(2);

    let ProduceRequestResult { envelope, .. } =
        produce_request(channel_id, &shared_key, 1).expect("produce should succeed");

    assert!(extract_request(&envelope, &wrong_key).is_err());
}

#[test]
fn test_extract_request_invalid_bytes_fails() {
    let shared_key = make_shared_key(1);
    assert!(extract_request(b"not a valid protobuf", &shared_key).is_err());
}

#[test]
fn test_extract_request_mismatched_timestamp_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let fingerprint = derec_cryptography::replica::fingerprint(&shared_key);
    let message_timestamp = current_timestamp();
    let mut envelope_timestamp = message_timestamp;
    envelope_timestamp.seconds += 1;

    let message = derec_proto::ReplicaConfirmationRequestMessage {
        fingerprint: fingerprint.to_vec(),
        replica_id: 1,
        timestamp: Some(message_timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message_body(MessageBody::ReplicaConfirmationRequest(message))
        .encrypt(&shared_key)
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec();

    assert!(matches!(
        extract_request(&envelope, &shared_key),
        Err(Error::Invariant(_))
    ));
}

#[test]
fn test_extract_request_wrong_message_type_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let timestamp = current_timestamp();

    let message = derec_proto::GetSecretIdsVersionsRequestMessage {
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetSecretIdsVersionsRequest(message))
        .encrypt(&shared_key)
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec();

    assert!(matches!(
        extract_request(&envelope, &shared_key),
        Err(Error::Invariant(_))
    ));
}

// ─── request::verify_fingerprint ────────────────────────────────────────────

#[test]
fn test_verify_fingerprint_matching_succeeds() {
    let shared_key = make_shared_key(1);

    let ProduceRequestResult { envelope, .. } =
        produce_request(ChannelId(1), &shared_key, 1).expect("produce should succeed");

    let ExtractRequestResult { request } =
        extract_request(&envelope, &shared_key).expect("extract should succeed");

    verify_fingerprint(&request, &shared_key).expect("fingerprint should match");
}

#[test]
fn test_verify_fingerprint_mismatch_fails() {
    let shared_key = make_shared_key(1);
    let wrong_key = make_shared_key(2);

    let ProduceRequestResult { envelope, .. } =
        produce_request(ChannelId(1), &shared_key, 1).expect("produce should succeed");

    let ExtractRequestResult { request } =
        extract_request(&envelope, &shared_key).expect("extract should succeed");

    assert!(matches!(
        verify_fingerprint(&request, &wrong_key),
        Err(Error::ReplicaConfirmation(
            ReplicaConfirmationError::FingerprintMismatch
        ))
    ));
}

// ─── response::produce ──────────────────────────────────────────────────────

#[test]
fn test_produce_response_returns_non_empty_envelope() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceResponseResult { envelope } =
        produce_response(channel_id, &shared_key, 200).expect("produce should succeed");

    assert!(!envelope.is_empty());
}

// ─── response::extract ──────────────────────────────────────────────────────

#[test]
fn test_produce_extract_response_roundtrip() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceResponseResult { envelope } =
        produce_response(channel_id, &shared_key, 77).expect("produce should succeed");

    let ExtractResponseResult { response } =
        extract_response(&envelope, &shared_key).expect("extract should succeed");

    assert_eq!(response.replica_id, 77);
    assert!(response.timestamp.is_some());
}

#[test]
fn test_extract_response_wrong_key_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let wrong_key = make_shared_key(2);

    let ProduceResponseResult { envelope } =
        produce_response(channel_id, &shared_key, 1).expect("produce should succeed");

    assert!(extract_response(&envelope, &wrong_key).is_err());
}

#[test]
fn test_extract_response_mismatched_timestamp_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let message_timestamp = current_timestamp();
    let mut envelope_timestamp = message_timestamp;
    envelope_timestamp.seconds += 1;

    let message = ReplicaConfirmationResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        replica_id: 1,
        timestamp: Some(message_timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message_body(MessageBody::ReplicaConfirmationResponse(message))
        .encrypt(&shared_key)
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec();

    assert!(matches!(
        extract_response(&envelope, &shared_key),
        Err(Error::Invariant(_))
    ));
}

// ─── response::process ──────────────────────────────────────────────────────

#[test]
fn test_process_response_ok_returns_replica_id() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceResponseResult { envelope } =
        produce_response(channel_id, &shared_key, 99).expect("produce should succeed");

    let ExtractResponseResult { response } =
        extract_response(&envelope, &shared_key).expect("extract should succeed");

    let ProcessResult { replica_id } =
        process_response(&response).expect("process should succeed");

    assert_eq!(replica_id, 99);
}

#[test]
fn test_process_response_missing_result_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let timestamp = current_timestamp();

    let message = ReplicaConfirmationResponseMessage {
        result: None,
        replica_id: 1,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::ReplicaConfirmationResponse(message))
        .encrypt(&shared_key)
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec();

    let ExtractResponseResult { response } =
        extract_response(&envelope, &shared_key).expect("extract should succeed");

    assert!(matches!(
        process_response(&response),
        Err(Error::ReplicaConfirmation(
            ReplicaConfirmationError::MissingResult
        ))
    ));
}

#[test]
fn test_process_response_non_ok_status_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let timestamp = current_timestamp();

    let message = ReplicaConfirmationResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Fail as i32,
            memo: "rejected".to_owned(),
        }),
        replica_id: 1,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::ReplicaConfirmationResponse(message))
        .encrypt(&shared_key)
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec();

    let ExtractResponseResult { response } =
        extract_response(&envelope, &shared_key).expect("extract should succeed");

    assert!(matches!(
        process_response(&response),
        Err(Error::ReplicaConfirmation(
            ReplicaConfirmationError::NonOkStatus { .. }
        ))
    ));
}

// ─── Full roundtrip ─────────────────────────────────────────────────────────

#[test]
fn test_full_replica_confirmation_roundtrip() {
    let channel_id = ChannelId(42);
    let shared_key = make_shared_key(7);
    let initiator_replica_id = 100;
    let responder_replica_id = 200;

    // Initiator → Responder: produce confirmation request
    let ProduceRequestResult {
        envelope: request_envelope,
        fingerprint: initiator_fingerprint,
    } = produce_request(channel_id, &shared_key, initiator_replica_id)
        .expect("produce request should succeed");

    // Responder: extract + verify fingerprint
    let ExtractRequestResult { request } =
        extract_request(&request_envelope, &shared_key)
            .expect("extract request should succeed");

    assert_eq!(request.replica_id, initiator_replica_id);
    verify_fingerprint(&request, &shared_key).expect("fingerprint should match");

    // Verify both sides derive the same fingerprint
    let responder_fingerprint = derec_cryptography::replica::fingerprint(&shared_key);
    assert_eq!(initiator_fingerprint, responder_fingerprint);

    // Responder → Initiator: produce confirmation response
    let ProduceResponseResult {
        envelope: response_envelope,
    } = produce_response(channel_id, &shared_key, responder_replica_id)
        .expect("produce response should succeed");

    // Initiator: extract + process
    let ExtractResponseResult { response } =
        extract_response(&response_envelope, &shared_key)
            .expect("extract response should succeed");

    let ProcessResult { replica_id } =
        process_response(&response).expect("process response should succeed");

    assert_eq!(replica_id, responder_replica_id);
}
