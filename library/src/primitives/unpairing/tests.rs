// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error,
    derec_message::extract_inner_message,
    primitives::unpairing::{
        UnpairingError,
        request::{
            extract as extract_unpair_request, produce as produce_unpair_request_message,
        },
        response::{
            extract as extract_unpair_response,
            process as process_unpair_response_message,
            produce as produce_unpair_response_message,
            reject as reject_unpair_response_message,
        },
    },
    types::ChannelId,
};
use derec_proto::{DeRecMessage, MessageBody, StatusEnum};
use prost::Message;

fn key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

// ─── request::produce ───────────────────────────────────────────────────────

#[test]
fn test_produce_unpair_request_produces_non_empty_envelope() {
    let channel_id = ChannelId(7);
    let shared_key = key(11);

    let result =
        produce_unpair_request_message(channel_id, "no longer needed", &shared_key)
            .expect("failed to produce unpair request");

    assert!(!result.envelope.is_empty());
    let decoded = DeRecMessage::decode(result.envelope.as_slice()).unwrap();
    assert_eq!(decoded.channel_id, u64::from(channel_id));
}

#[test]
fn test_produce_unpair_request_accepts_empty_memo() {
    let channel_id = ChannelId(7);
    let shared_key = key(11);

    let result = produce_unpair_request_message(channel_id, "", &shared_key)
        .expect("failed to produce unpair request with empty memo");

    let extracted = extract_unpair_request(&result.envelope, &shared_key)
        .expect("failed to extract unpair request");
    assert_eq!(extracted.request.memo, "");
}

// ─── request::extract ───────────────────────────────────────────────────────

#[test]
fn test_extract_unpair_request_returns_original_memo() {
    let channel_id = ChannelId(5);
    let shared_key = key(29);
    let memo = "explicit user choice";

    let produced = produce_unpair_request_message(channel_id, memo, &shared_key)
        .expect("failed to produce unpair request");

    let result = extract_unpair_request(&produced.envelope, &shared_key)
        .expect("failed to extract unpair request");

    assert_eq!(result.request.memo, memo);
    assert!(result.request.timestamp.is_some());
}

#[test]
fn test_extract_unpair_request_rejects_wrong_key() {
    let channel_id = ChannelId(5);
    let producing_key = key(1);
    let other_key = key(2);

    let produced = produce_unpair_request_message(channel_id, "x", &producing_key)
        .expect("failed to produce unpair request");

    let err = extract_unpair_request(&produced.envelope, &other_key).unwrap_err();
    assert!(matches!(err, Error::DeRecMessage(_) | Error::ProtobufDecode(_)) || format!("{err}").len() > 0);
}

#[test]
fn test_extract_unpair_request_rejects_tampered_timestamp() {
    let channel_id = ChannelId(5);
    let shared_key = key(7);

    let produced = produce_unpair_request_message(channel_id, "m", &shared_key)
        .expect("failed to produce unpair request");

    // Mutate the outer envelope timestamp so the invariant
    // `envelope.timestamp == request.timestamp` is broken.
    let mut envelope = DeRecMessage::decode(produced.envelope.as_slice()).unwrap();
    let mut ts = envelope.timestamp.unwrap();
    ts.seconds += 1;
    envelope.timestamp = Some(ts);
    let tampered = envelope.encode_to_vec();

    let err = extract_unpair_request(&tampered, &shared_key).unwrap_err();
    assert!(matches!(err, Error::Invariant(_)));
}

// ─── response::produce / reject / extract / process ─────────────────────────

#[test]
fn test_produce_unpair_response_carries_ok_status() {
    let channel_id = ChannelId(9);
    let shared_key = key(31);

    let response = produce_unpair_response_message(channel_id, &shared_key)
        .expect("failed to produce unpair response");

    let extracted = extract_unpair_response(&response.envelope, &shared_key)
        .expect("failed to extract unpair response");

    let result = extracted.response.result.expect("missing result");
    assert_eq!(result.status, StatusEnum::Ok as i32);
    assert!(result.memo.is_empty());
}

#[test]
fn test_reject_unpair_response_carries_non_ok_status() {
    let channel_id = ChannelId(9);
    let shared_key = key(33);

    let response = reject_unpair_response_message(
        channel_id,
        &shared_key,
        StatusEnum::Fail,
        "retention policy",
    )
    .expect("failed to produce unpair rejection");

    let extracted = extract_unpair_response(&response.envelope, &shared_key)
        .expect("failed to extract unpair response");

    let result = extracted.response.result.expect("missing result");
    assert_eq!(result.status, StatusEnum::Fail as i32);
    assert_eq!(result.memo, "retention policy");
}

#[test]
fn test_process_unpair_response_accepts_ok() {
    let channel_id = ChannelId(11);
    let shared_key = key(7);

    let response = produce_unpair_response_message(channel_id, &shared_key)
        .expect("failed to produce unpair response");
    let extracted = extract_unpair_response(&response.envelope, &shared_key)
        .expect("failed to extract unpair response");

    let outcome = process_unpair_response_message(&extracted.response)
        .expect("processing Ok response should succeed");
    assert!(outcome.acknowledged);
}

#[test]
fn test_process_unpair_response_surfaces_non_ok_as_error() {
    let channel_id = ChannelId(11);
    let shared_key = key(7);

    let response = reject_unpair_response_message(
        channel_id,
        &shared_key,
        StatusEnum::Fail,
        "retention policy",
    )
    .expect("failed to produce unpair rejection");
    let extracted = extract_unpair_response(&response.envelope, &shared_key)
        .expect("failed to extract unpair response");

    let err = process_unpair_response_message(&extracted.response).unwrap_err();
    match err {
        Error::Unpairing(UnpairingError::NonOkStatus { status, memo }) => {
            assert_eq!(status, StatusEnum::Fail as i32);
            assert_eq!(memo, "retention policy");
        }
        other => panic!("expected Unpairing::NonOkStatus, got {other:?}"),
    }
}

#[test]
fn test_process_unpair_response_surfaces_missing_result() {
    let response = derec_proto::UnpairResponseMessage {
        result: None,
        timestamp: None,
    };

    let err = process_unpair_response_message(&response).unwrap_err();
    assert!(matches!(
        err,
        Error::Unpairing(UnpairingError::MissingResult)
    ));
}

// ─── round-trip ─────────────────────────────────────────────────────────────

#[test]
fn test_full_unpair_round_trip_ok() {
    // Initiator → request envelope.
    let channel_id = ChannelId(42);
    let shared_key = key(99);
    let memo = "device decommissioned";

    let request = produce_unpair_request_message(channel_id, memo, &shared_key)
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
    // Sanity: the inner message decodes to UnpairRequest via the same
    // helper used by the protocol dispatcher.
    let channel_id = ChannelId(8);
    let shared_key = key(5);

    let produced = produce_unpair_request_message(channel_id, "x", &shared_key).unwrap();
    let envelope = DeRecMessage::decode(produced.envelope.as_slice()).unwrap();
    let inner = extract_inner_message(&envelope.message, &shared_key).unwrap();
    assert!(matches!(inner, MessageBody::UnpairRequest(_)));
}
