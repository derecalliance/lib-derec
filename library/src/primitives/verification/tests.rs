// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error,
    derec_message::extract_inner_message,
    primitives::verification::{
        request::{
            extract as extract_verify_share_request,
            produce as produce_verify_share_request_message,
        },
        response::{
            extract as extract_verify_share_response,
            process as process_verify_share_response_message,
            produce as produce_verify_share_response_message,
        },
    },
    types::ChannelId,
};
use derec_proto::{DeRecMessage, MessageBody, StatusEnum};
use prost::Message;
use sha2::{Digest, Sha384};

fn parse_request(
    envelope_bytes: &[u8],
    shared_key: &[u8; 32],
) -> crate::primitives::verification::request::ExtractResult {
    extract_verify_share_request(envelope_bytes, shared_key)
        .expect("extract_verify_share_request failed")
}

#[test]
fn test_produce_verify_share_request_message_produces_non_empty_envelope() {
    let channel_id = ChannelId(7);
    let shared_key = [23u8; 32];

    let result = produce_verify_share_request_message(channel_id, b"my_secret", 5, &shared_key)
        .expect("failed to produce verification request");

    assert!(!result.envelope.is_empty());
    let decoded = DeRecMessage::decode(result.envelope.as_slice()).unwrap();
    assert_eq!(decoded.channel_id, u64::from(channel_id));
}

#[test]
fn test_extract_verify_share_request_extracts_all_fields() {
    let channel_id = ChannelId(5);
    let shared_key = [29u8; 32];
    let secret_id = b"my_secret_id";
    let version = 9;

    let produced =
        produce_verify_share_request_message(channel_id, secret_id, version, &shared_key)
            .expect("failed to produce verification request");

    let result = extract_verify_share_request(&produced.envelope, &shared_key)
        .expect("failed to extract verification request");

    assert_eq!(result.request.secret_id, secret_id.as_slice());
    assert_eq!(result.request.version, version);
    assert_ne!(
        result.request.nonce, 0,
        "nonce must be a non-zero random value"
    );
}

#[test]
fn test_extract_verify_share_request_nonce_matches_inner_message() {
    let channel_id = ChannelId(2);
    let shared_key = [31u8; 32];

    let produced = produce_verify_share_request_message(channel_id, b"nonce_check", 3, &shared_key)
        .expect("failed to produce verification request");

    let result = extract_verify_share_request(&produced.envelope, &shared_key)
        .expect("failed to extract verification request");

    // Cross-check by independently decoding the inner message.
    let outer = DeRecMessage::decode(produced.envelope.as_slice()).unwrap();
    let raw_request = match extract_inner_message(&outer.message, &shared_key)
        .expect("failed to decode inner request")
    {
        MessageBody::VerifyShareRequest(m) => m,
        _ => panic!("unexpected message body"),
    };

    assert_eq!(result.request.nonce, raw_request.nonce);
    assert_eq!(result.request.secret_id, raw_request.secret_id);
    assert_eq!(result.request.version, raw_request.version);
}

#[test]
fn test_extract_verify_share_request_rejects_tampered_timestamp() {
    let channel_id = ChannelId(4);
    let shared_key = [37u8; 32];

    let produced = produce_verify_share_request_message(channel_id, b"secret", 1, &shared_key)
        .expect("failed to produce verification request");

    let outer = DeRecMessage::decode(produced.envelope.as_slice()).unwrap();
    let message = match extract_inner_message(&outer.message, &shared_key)
        .expect("failed to decode request")
    {
        MessageBody::VerifyShareRequest(m) => m,
        _ => panic!("unexpected message body"),
    };

    let original_timestamp = outer.timestamp.expect("timestamp must be present");
    let mut tampered_timestamp = original_timestamp;
    tampered_timestamp.seconds += 1;

    // Build a tampered envelope with a mismatched outer timestamp.
    let tampered_envelope = crate::derec_message::DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(tampered_timestamp)
        .message_body(MessageBody::VerifyShareRequest(message))
        .encrypt(&shared_key)
        .expect("failed to encrypt tampered request")
        .build()
        .expect("failed to build tampered envelope")
        .encode_to_vec();

    let result = extract_verify_share_request(&tampered_envelope, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Invariant(
            "Envelope timestamp does not match request timestamp"
        ))
    ));
}

#[test]
fn test_produce_verify_share_response_message_produces_non_empty_envelope() {
    let channel_id = ChannelId(1);
    let shared_key = [7u8; 32];

    let produced = produce_verify_share_request_message(channel_id, b"secret_id", 4, &shared_key)
        .expect("failed to produce verification request");

    let req = parse_request(&produced.envelope, &shared_key);

    let response = produce_verify_share_response_message(
        channel_id,
        &req.request,
        &shared_key,
        b"share_content",
    )
    .expect("failed to produce verification response");

    assert!(!response.envelope.is_empty());
}

#[test]
fn test_produce_verify_share_response_message_echo_fields() {
    let channel_id = ChannelId(2);
    let shared_key = [9u8; 32];
    let secret_id = b"secret_id";
    let version = 4;

    let produced =
        produce_verify_share_request_message(channel_id, secret_id, version, &shared_key)
            .expect("failed to produce verification request");

    let req = parse_request(&produced.envelope, &shared_key);

    let response = produce_verify_share_response_message(
        channel_id,
        &req.request,
        &shared_key,
        b"share_content",
    )
    .expect("failed to produce verification response");

    let response_outer = DeRecMessage::decode(response.envelope.as_slice()).unwrap();
    let response_message = match extract_inner_message(&response_outer.message, &shared_key)
        .expect("failed to decrypt verification response")
    {
        MessageBody::VerifyShareResponse(m) => m,
        _ => panic!("unexpected message body"),
    };

    assert_eq!(response_message.secret_id, secret_id.as_slice());
    assert_eq!(response_message.version, version);
    assert_eq!(response_message.nonce, req.request.nonce);
    assert_eq!(
        response_message
            .result
            .as_ref()
            .expect("response result must be present")
            .status,
        StatusEnum::Ok as i32
    );
    assert!(response_outer.timestamp.is_some());
    assert_eq!(response_outer.timestamp, response_message.timestamp);
}

#[test]
fn test_full_verification_flow_success() {
    let channel_id = ChannelId(2);
    let shared_key = [7u8; 32];
    let secret_id = b"secret_id";
    let version = 4;
    let share_content = b"test_share_content";

    let produced =
        produce_verify_share_request_message(channel_id, secret_id, version, &shared_key)
            .expect("failed to produce verification request");

    // Helper side.
    let req = parse_request(&produced.envelope, &shared_key);

    assert_eq!(req.request.secret_id, secret_id.as_slice());
    assert_eq!(req.request.version, version);

    let response =
        produce_verify_share_response_message(channel_id, &req.request, &shared_key, share_content)
            .expect("failed to produce verification response");

    // Owner side.
    let resp_result = extract_verify_share_response(&response.envelope, &shared_key)
        .expect("failed to extract verification response");

    assert!(matches!(
        process_verify_share_response_message(&resp_result.response, share_content),
        Ok(valid) if valid
    ));
}

#[test]
fn test_full_verification_flow_wrong_share_returns_false() {
    let channel_id = ChannelId(2);
    let shared_key = [9u8; 32];
    let secret_id = b"secret_id";
    let version = 4;
    let share_content = b"test_share_content";
    let wrong_share_content = b"wrong_content";

    let produced =
        produce_verify_share_request_message(channel_id, secret_id, version, &shared_key)
            .expect("failed to produce verification request");

    let req = parse_request(&produced.envelope, &shared_key);

    let response =
        produce_verify_share_response_message(channel_id, &req.request, &shared_key, share_content)
            .expect("failed to produce verification response");

    let resp_result = extract_verify_share_response(&response.envelope, &shared_key)
        .expect("failed to extract verification response");

    assert!(matches!(
        process_verify_share_response_message(&resp_result.response, wrong_share_content),
        Ok(valid) if !valid
    ));
}

#[test]
fn test_verification_hash_is_correct_sha384() {
    let channel_id = ChannelId(1);
    let shared_key = [3u8; 32];
    let share_content = b"abc123";

    let produced = produce_verify_share_request_message(channel_id, b"secret", 4, &shared_key)
        .expect("failed to produce verification request");

    let req = parse_request(&produced.envelope, &shared_key);

    let response =
        produce_verify_share_response_message(channel_id, &req.request, &shared_key, share_content)
            .expect("failed to produce verification response");

    let response_outer = DeRecMessage::decode(response.envelope.as_slice()).unwrap();
    let response_message = match extract_inner_message(&response_outer.message, &shared_key)
        .expect("failed to decrypt verification response")
    {
        MessageBody::VerifyShareResponse(m) => m,
        _ => panic!("unexpected message body"),
    };

    let mut hasher = Sha384::new();
    hasher.update(share_content);
    hasher.update(req.request.nonce.to_be_bytes());
    let expected_hash = hasher.finalize().to_vec();

    assert_eq!(response_message.hash, expected_hash);
}

#[test]
fn test_verification_fails_with_modified_response_nonce() {
    let channel_id = ChannelId(1);
    let shared_key = [5u8; 32];
    let share_content = b"nonce_test_content";

    let produced = produce_verify_share_request_message(channel_id, b"secret", 4, &shared_key)
        .expect("failed to produce verification request");

    let req = parse_request(&produced.envelope, &shared_key);

    let response =
        produce_verify_share_response_message(channel_id, &req.request, &shared_key, share_content)
            .expect("failed to produce verification response");

    let response_outer = DeRecMessage::decode(response.envelope.as_slice()).unwrap();
    let mut response_message = match extract_inner_message(&response_outer.message, &shared_key)
        .expect("failed to decrypt verification response")
    {
        MessageBody::VerifyShareResponse(m) => m,
        _ => panic!("unexpected message body"),
    };

    response_message.nonce = 123;

    let tampered_envelope = crate::derec_message::DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(
            response_outer
                .timestamp
                .expect("response envelope timestamp must be present"),
        )
        .message_body(MessageBody::VerifyShareResponse(response_message))
        .encrypt(&shared_key)
        .expect("failed to encrypt tampered response")
        .build()
        .expect("failed to build tampered response envelope")
        .encode_to_vec();

    let resp_result = extract_verify_share_response(&tampered_envelope, &shared_key)
        .expect("failed to extract tampered response");

    assert!(matches!(
        process_verify_share_response_message(&resp_result.response, share_content),
        Ok(valid) if !valid
    ));
}

#[test]
fn test_process_verify_share_response_message_rejects_tampered_envelope_timestamp() {
    let channel_id = ChannelId(1);
    let shared_key = [13u8; 32];
    let share_content = b"response_timestamp_test_content";

    let produced = produce_verify_share_request_message(channel_id, b"secret", 4, &shared_key)
        .expect("failed to produce verification request");

    let req = parse_request(&produced.envelope, &shared_key);

    let response =
        produce_verify_share_response_message(channel_id, &req.request, &shared_key, share_content)
            .expect("failed to produce verification response");

    let response_outer = DeRecMessage::decode(response.envelope.as_slice()).unwrap();
    let response_message = match extract_inner_message(&response_outer.message, &shared_key)
        .expect("failed to decrypt verification response")
    {
        MessageBody::VerifyShareResponse(m) => m,
        _ => panic!("unexpected message body"),
    };

    let original_timestamp = response_outer
        .timestamp
        .expect("response envelope timestamp must be present");

    let mut tampered_timestamp = original_timestamp;
    tampered_timestamp.seconds += 1;

    let tampered_envelope = crate::derec_message::DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(tampered_timestamp)
        .message_body(MessageBody::VerifyShareResponse(response_message))
        .encrypt(&shared_key)
        .expect("failed to encrypt tampered response")
        .build()
        .expect("failed to build tampered response")
        .encode_to_vec();

    assert!(matches!(
        extract_verify_share_response(&tampered_envelope, &shared_key),
        Err(Error::Invariant(
            "Envelope timestamp does not match response timestamp"
        ))
    ));
}

#[test]
fn test_extract_verify_share_response_returns_correct_channel_id() {
    let channel_id = ChannelId(7);
    let shared_key = [23u8; 32];

    let produced = produce_verify_share_request_message(channel_id, b"secret", 1, &shared_key)
        .expect("failed to produce verification request");
    let req = parse_request(&produced.envelope, &shared_key);
    let response =
        produce_verify_share_response_message(channel_id, &req.request, &shared_key, b"share")
            .expect("failed to produce verification response");

    // The outer envelope channel_id must match the original.
    let decoded = DeRecMessage::decode(response.envelope.as_slice()).unwrap();
    assert_eq!(decoded.channel_id, u64::from(channel_id));
}

#[test]
fn test_extract_verify_share_response_returns_encrypted_bytes() {
    let channel_id = ChannelId(3);
    let shared_key = [11u8; 32];

    let produced = produce_verify_share_request_message(channel_id, b"secret", 2, &shared_key)
        .expect("failed to produce verification request");
    let req = parse_request(&produced.envelope, &shared_key);
    let response = produce_verify_share_response_message(
        channel_id,
        &req.request,
        &shared_key,
        b"share_bytes",
    )
    .expect("failed to produce verification response");

    // Encrypted payload in the envelope must be non-empty.
    assert!(!response.envelope.is_empty());
}

#[test]
fn test_extract_verify_share_response_timestamp_matches_inner() {
    let channel_id = ChannelId(2);
    let shared_key = [31u8; 32];

    let produced = produce_verify_share_request_message(channel_id, b"secret", 4, &shared_key)
        .expect("failed to produce verification request");
    let req = parse_request(&produced.envelope, &shared_key);
    let response =
        produce_verify_share_response_message(channel_id, &req.request, &shared_key, b"some_share")
            .expect("failed to produce verification response");

    let resp_result = extract_verify_share_response(&response.envelope, &shared_key)
        .expect("failed to extract verification response");

    // Cross-check: the inner response timestamp must match the envelope timestamp.
    let response_outer = DeRecMessage::decode(response.envelope.as_slice()).unwrap();
    let inner = match extract_inner_message(&response_outer.message, &shared_key)
        .expect("failed to decrypt response")
    {
        MessageBody::VerifyShareResponse(m) => m,
        _ => panic!("unexpected message body"),
    };

    assert_eq!(resp_result.response.timestamp, inner.timestamp);
}
