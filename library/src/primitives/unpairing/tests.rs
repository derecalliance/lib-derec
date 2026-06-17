// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error,
    derec_message::extract_inner_message,
    primitives::{
        make_shared_key,
        unpairing::{
            request::{extract as extract_unpair_request, produce as produce_unpair_request_message},
            response::{
                extract as extract_unpair_response, process as process_unpair_response_message,
                produce as produce_unpair_response_message,
            },
        },
    },
    types::ChannelId,
};
use derec_proto::{DeRecMessage, MessageBody, StatusEnum};
use prost::Message;

#[test]
fn test_produce_unpair_request_produces_non_empty_envelope() {
    let channel_id = ChannelId(7);
    let shared_key = make_shared_key(11);

    let result = produce_unpair_request_message(channel_id, "no longer needed", &shared_key, None)
        .expect("failed to produce unpair request");

    assert!(!result.envelope.is_empty());
    let decoded = DeRecMessage::decode(result.envelope.as_slice()).unwrap();
    assert_eq!(decoded.channel_id, u64::from(channel_id));
}

#[test]
fn test_produce_unpair_request_accepts_empty_memo() {
    let channel_id = ChannelId(7);
    let shared_key = make_shared_key(11);

    let result = produce_unpair_request_message(channel_id, "", &shared_key, None)
        .expect("failed to produce unpair request with empty memo");

    let extracted = extract_unpair_request(&result.envelope, &shared_key)
        .expect("failed to extract unpair request");
    assert_eq!(extracted.request.memo, "");
}

#[test]
fn test_extract_unpair_request_returns_original_memo() {
    let channel_id = ChannelId(5);
    let shared_key = make_shared_key(29);
    let memo = "explicit user choice";

    let produced = produce_unpair_request_message(channel_id, memo, &shared_key, None)
        .expect("failed to produce unpair request");

    let result = extract_unpair_request(&produced.envelope, &shared_key)
        .expect("failed to extract unpair request");

    assert_eq!(result.request.memo, memo);
    assert!(result.request.timestamp.is_some());
}

#[test]
fn test_extract_unpair_request_rejects_wrong_make_shared_key() {
    let channel_id = ChannelId(5);
    let producing_key = make_shared_key(1);
    let other_key = make_shared_key(2);

    let produced = produce_unpair_request_message(channel_id, "x", &producing_key, None)
        .expect("failed to produce unpair request");

    let result = extract_unpair_request(&produced.envelope, &other_key);
    assert!(result.is_err());
}

#[test]
fn test_extract_unpair_request_rejects_tampered_timestamp() {
    let channel_id = ChannelId(5);
    let shared_key = make_shared_key(7);

    let produced = produce_unpair_request_message(channel_id, "m", &shared_key, None)
        .expect("failed to produce unpair request");

    // Mutate the outer envelope timestamp so the invariant
    // `envelope.timestamp == request.timestamp` is broken.
    let mut envelope = DeRecMessage::decode(produced.envelope.as_slice()).unwrap();
    let mut ts = envelope.timestamp.unwrap();
    ts.seconds += 1;
    envelope.timestamp = Some(ts);
    let tampered = envelope.encode_to_vec();

    let result = extract_unpair_request(&tampered, &shared_key);
    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_produce_unpair_response_carries_ok_status() {
    let channel_id = ChannelId(9);
    let shared_key = make_shared_key(31);

    let response = produce_unpair_response_message(channel_id, &shared_key)
        .expect("failed to produce unpair response");

    let extracted = extract_unpair_response(&response.envelope, &shared_key)
        .expect("failed to extract unpair response");

    let result = extracted.response.result.expect("missing result");
    assert_eq!(result.status, StatusEnum::Ok as i32);
    assert!(result.memo.is_empty());
}

#[test]
fn test_process_unpair_response_accepts_ok() {
    let channel_id = ChannelId(11);
    let shared_key = make_shared_key(7);

    let response = produce_unpair_response_message(channel_id, &shared_key)
        .expect("failed to produce unpair response");
    let extracted = extract_unpair_response(&response.envelope, &shared_key)
        .expect("failed to extract unpair response");

    let outcome = process_unpair_response_message(&extracted.response)
        .expect("processing Ok response should succeed");
    assert!(outcome.acknowledged);
}

#[test]
fn test_process_unpair_response_surfaces_missing_result() {
    let response = derec_proto::UnpairResponseMessage {
        result: None,
        timestamp: None,
    };

    let result = process_unpair_response_message(&response);
    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_full_unpair_round_trip_ok() {
    // Initiator → request envelope.
    let channel_id = ChannelId(42);
    let shared_key = make_shared_key(99);
    let memo = "device decommissioned";

    let request = produce_unpair_request_message(channel_id, memo, &shared_key, None)
        .expect("failed to produce unpair request");

    // Responder extracts the request, validates memo round-trip, sends Ok.
    let extracted_req = extract_unpair_request(&request.envelope, &shared_key)
        .expect("failed to extract unpair request");
    assert_eq!(extracted_req.request.memo, memo);

    let response = produce_unpair_response_message(channel_id, &shared_key)
        .expect("failed to produce unpair response");

    // Initiator extracts response and processes outcome.
    let extracted_resp = extract_unpair_response(&response.envelope, &shared_key)
        .expect("failed to extract unpair response");
    let outcome = process_unpair_response_message(&extracted_resp.response)
        .expect("processing Ok response should succeed");
    assert!(outcome.acknowledged);
}

#[test]
fn test_inner_request_decodable_via_extract_inner_message() {
    let channel_id = ChannelId(8);
    let shared_key = make_shared_key(5);

    let produced = produce_unpair_request_message(channel_id, "x", &shared_key, None).unwrap();
    let envelope = DeRecMessage::decode(produced.envelope.as_slice()).unwrap();
    let inner = extract_inner_message(&envelope.message, &shared_key).unwrap();
    assert!(matches!(inner, MessageBody::UnpairRequest(_)));
}

/// A peer-supplied `reply_to` that declares `Protocol::Https` but ships a
/// plaintext URI is rejected at extract — the scheme-vs-protocol gate is
/// what stops a malicious request sender from redirecting our response
/// onto an HTTP transport.
#[test]
fn test_extract_unpair_request_rejects_scheme_mismatched_reply_to() {
    let channel_id = ChannelId(9);
    let shared_key = make_shared_key(17);

    let malicious_reply_to = derec_proto::TransportProtocol {
        uri: "http://attacker.example/inbox".to_owned(),
        protocol: derec_proto::Protocol::Https as i32,
    };

    let produced = produce_unpair_request_message(
        channel_id,
        "bye",
        &shared_key,
        Some(malicious_reply_to),
    )
    .expect("failed to produce unpair request");

    let result = extract_unpair_request(&produced.envelope, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Transport(
            crate::transport::TransportValidationError::SchemeMismatch { .. }
        ))
    ));
}
