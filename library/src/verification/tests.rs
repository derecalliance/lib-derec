use crate::{
    Error,
    derec_message::extract_inner_message,
    types::ChannelId,
    verification::{
        generate_verification_request, generate_verification_response, verify_share_response,
    },
};
use derec_proto::{StatusEnum, VerifyShareRequestMessage, VerifyShareResponseMessage};
use prost::Message;
use sha2::{Digest, Sha384};

#[test]
fn test_generate_verification_response_and_verify_success() {
    let secret_id = "secret_id";
    let channel_id = ChannelId(2);
    let shared_key = [7u8; 32];
    let version = 4;
    let share_content = b"test_share_content";

    let request = generate_verification_request(secret_id, channel_id, version, &shared_key)
        .expect("failed to generate verification request");

    let (request_envelope, request_message) =
        extract_inner_message::<VerifyShareRequestMessage>(&request.wire_bytes, &shared_key)
            .expect("failed to decrypt verification request");

    assert_eq!(request_message.version, version);
    assert!(
        request_envelope.timestamp.is_some(),
        "request envelope timestamp must be present"
    );
    assert!(
        request_message.timestamp.is_some(),
        "request message timestamp must be present"
    );
    assert_eq!(
        request_envelope.timestamp, request_message.timestamp,
        "request envelope timestamp must match request message timestamp"
    );

    let response = generate_verification_response(
        secret_id,
        channel_id,
        &shared_key,
        share_content,
        &request.wire_bytes,
    )
    .expect("failed to generate verification response");

    let (response_envelope, response_message) =
        extract_inner_message::<VerifyShareResponseMessage>(&response.wire_bytes, &shared_key)
            .expect("failed to decrypt verification response");

    assert_eq!(response_message.version, version);
    assert_eq!(response_message.nonce, request_message.nonce);
    assert_eq!(
        response_message
            .result
            .as_ref()
            .expect("response result must be present")
            .status,
        StatusEnum::Ok as i32
    );
    assert!(
        response_envelope.timestamp.is_some(),
        "response envelope timestamp must be present"
    );
    assert!(
        response_message.timestamp.is_some(),
        "response message timestamp must be present"
    );
    assert_eq!(
        response_envelope.timestamp, response_message.timestamp,
        "response envelope timestamp must match response message timestamp"
    );

    assert!(matches!(
        verify_share_response(
            secret_id,
            channel_id,
            &shared_key,
            share_content,
            &response.wire_bytes,
        ),
        Ok(valid) if valid
    ));
}

#[test]
fn test_generate_verification_response_and_verify_failure() {
    let secret_id = "secret_id";
    let channel_id = ChannelId(2);
    let shared_key = [9u8; 32];
    let version = 4;

    let share_content = b"test_share_content";
    let wrong_share_content = b"wrong_content";

    let request = generate_verification_request(secret_id, channel_id, version, &shared_key)
        .expect("failed to generate verification request");

    let response = generate_verification_response(
        secret_id,
        channel_id,
        &shared_key,
        share_content,
        &request.wire_bytes,
    )
    .expect("failed to generate verification response");

    assert!(matches!(
        verify_share_response(
            secret_id,
            channel_id,
            &shared_key,
            wrong_share_content,
            &response.wire_bytes,
        ),
        Ok(valid) if !valid
    ));
}

#[test]
fn test_generate_verification_response_nonce_and_hash() {
    let secret_id = "secret_id";
    let version = 4;
    let channel_id = ChannelId(1);
    let shared_key = [3u8; 32];
    let share_content = b"abc123";

    let request = generate_verification_request(secret_id, channel_id, version, &shared_key)
        .expect("failed to generate verification request");

    let (_request_envelope, request_message) =
        extract_inner_message::<VerifyShareRequestMessage>(&request.wire_bytes, &shared_key)
            .expect("failed to decrypt verification request");

    let response = generate_verification_response(
        secret_id,
        channel_id,
        &shared_key,
        share_content,
        &request.wire_bytes,
    )
    .expect("failed to generate verification response");

    let (_response_envelope, response_message) =
        extract_inner_message::<VerifyShareResponseMessage>(&response.wire_bytes, &shared_key)
            .expect("failed to decrypt verification response");

    let mut hasher = Sha384::new();
    hasher.update(share_content);
    hasher.update(request_message.nonce.to_be_bytes());
    let expected_hash = hasher.finalize().to_vec();

    assert_eq!(response_message.nonce, request_message.nonce);
    assert_eq!(response_message.hash, expected_hash);
}

#[test]
fn test_verification_fails_with_modified_nonce() {
    let secret_id = "secret_id";
    let version = 4;
    let channel_id = ChannelId(1);
    let shared_key = [5u8; 32];
    let share_content = b"nonce_test_content";

    let request = generate_verification_request(secret_id, channel_id, version, &shared_key)
        .expect("failed to generate verification request");

    let response = generate_verification_response(
        secret_id,
        channel_id,
        &shared_key,
        share_content,
        &request.wire_bytes,
    )
    .expect("failed to generate verification response");

    let (response_envelope, mut response_message) =
        extract_inner_message::<VerifyShareResponseMessage>(&response.wire_bytes, &shared_key)
            .expect("failed to decrypt verification response");

    response_message.nonce = 123;

    let tampered_wire_bytes = crate::derec_message::DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(
            response_envelope
                .timestamp
                .expect("response envelope timestamp must be present"),
        )
        .message(&response_message)
        .encrypt(&shared_key)
        .expect("failed to encrypt tampered response")
        .build()
        .expect("failed to build tampered response envelope")
        .encode_to_vec();

    assert!(matches!(
        verify_share_response(
            secret_id,
            channel_id,
            &shared_key,
            share_content,
            &tampered_wire_bytes,
        ),
        Ok(valid) if !valid
    ));
}

#[test]
fn test_generate_verification_response_fails_when_request_envelope_timestamp_does_not_match() {
    let secret_id = "secret_id";
    let version = 4;
    let channel_id = ChannelId(1);
    let shared_key = [11u8; 32];
    let share_content = b"timestamp_test_content";

    let request = generate_verification_request(secret_id, channel_id, version, &shared_key)
        .expect("failed to generate verification request");

    let (request_envelope, request_message) =
        extract_inner_message::<VerifyShareRequestMessage>(&request.wire_bytes, &shared_key)
            .expect("failed to decrypt verification request");

    let original_timestamp = request_envelope
        .timestamp
        .expect("request envelope timestamp must be present");

    let mut tampered_timestamp = original_timestamp;
    tampered_timestamp.seconds += 1;

    let tampered_wire_bytes = crate::derec_message::DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(tampered_timestamp)
        .message(&request_message)
        .encrypt(&shared_key)
        .expect("failed to encrypt tampered request")
        .build()
        .expect("failed to build tampered request")
        .encode_to_vec();

    let result = generate_verification_response(
        secret_id,
        channel_id,
        &shared_key,
        share_content,
        &tampered_wire_bytes,
    );

    assert!(matches!(
        result,
        Err(Error::Invariant(
            "Envelope timestamp does not match request timestamp"
        ))
    ));
}

#[test]
fn test_verify_share_response_fails_when_response_envelope_timestamp_does_not_match() {
    let secret_id = "secret_id";
    let version = 4;
    let channel_id = ChannelId(1);
    let shared_key = [13u8; 32];
    let share_content = b"response_timestamp_test_content";

    let request = generate_verification_request(secret_id, channel_id, version, &shared_key)
        .expect("failed to generate verification request");

    let response = generate_verification_response(
        secret_id,
        channel_id,
        &shared_key,
        share_content,
        &request.wire_bytes,
    )
    .expect("failed to generate verification response");

    let (response_envelope, response_message) =
        extract_inner_message::<VerifyShareResponseMessage>(&response.wire_bytes, &shared_key)
            .expect("failed to decrypt verification response");

    let original_timestamp = response_envelope
        .timestamp
        .expect("response envelope timestamp must be present");

    let mut tampered_timestamp = original_timestamp;
    tampered_timestamp.seconds += 1;

    let tampered_wire_bytes = crate::derec_message::DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(tampered_timestamp)
        .message(&response_message)
        .encrypt(&shared_key)
        .expect("failed to encrypt tampered response")
        .build()
        .expect("failed to build tampered response")
        .encode_to_vec();

    let result = verify_share_response(
        secret_id,
        channel_id,
        &shared_key,
        share_content,
        &tampered_wire_bytes,
    );

    assert!(matches!(
        result,
        Err(Error::Invariant(
            "Envelope timestamp does not match response timestamp"
        ))
    ));
}
