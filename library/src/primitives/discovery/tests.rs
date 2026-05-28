// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    primitives::discovery::{
        DiscoveryError,
        request::{
            ExtractResult as ExtractRequestResult, ProduceResult as ProduceRequestResult,
            extract as extract_discovery_request, produce as produce_discovery_request,
        },
        response::{
            ExtractResult as ExtractResponseResult, ProcessResult,
            ProduceResult as ProduceResponseResult, SecretVersionEntry, VersionEntry,
            extract as extract_discovery_response, process as process_discovery_response,
            produce as produce_discovery_response,
        },
    },
    primitives::make_shared_key,
    types::ChannelId,
};
use derec_proto::{
    DeRecResult, GetSecretIdsVersionsResponseMessage, MessageBody, StatusEnum,
    get_secret_ids_versions_response_message::VersionList,
};
use prost::Message;

fn entry(id: u64, versions: &[(u32, &str)]) -> SecretVersionEntry {
    SecretVersionEntry {
        secret_id: id,
        versions: versions
            .iter()
            .map(|(v, desc)| VersionEntry {
                version: *v,
                description: desc.to_string(),
            })
            .collect(),
    }
}

fn build_response_envelope(
    channel_id: ChannelId,
    shared_key: &[u8; 32],
    result: Option<DeRecResult>,
    secret_list: Vec<VersionList>,
) -> Vec<u8> {
    let timestamp = current_timestamp();

    let message = GetSecretIdsVersionsResponseMessage {
        result,
        secret_list,
        timestamp: Some(timestamp),
    };

    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetSecretIdsVersionsResponse(message))
        .encrypt(shared_key)
        .expect("failed to encrypt response")
        .build()
        .expect("failed to build response envelope")
        .encode_to_vec()
}

fn build_response_envelope_with_mismatched_timestamp(
    channel_id: ChannelId,
    shared_key: &[u8; 32],
) -> Vec<u8> {
    let message_timestamp = current_timestamp();
    let mut envelope_timestamp = message_timestamp;
    envelope_timestamp.seconds += 1;

    let message = GetSecretIdsVersionsResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        secret_list: vec![],
        timestamp: Some(message_timestamp),
    };

    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message_body(MessageBody::GetSecretIdsVersionsResponse(message))
        .encrypt(shared_key)
        .expect("failed to encrypt response")
        .build()
        .expect("failed to build response envelope")
        .encode_to_vec()
}

#[test]
fn test_produce_discovery_request_returns_non_empty_envelope() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceRequestResult { envelope } =
        produce_discovery_request(channel_id, &shared_key).expect("produce should succeed");

    assert!(!envelope.is_empty());
}

#[test]
fn test_produce_extract_discovery_request_roundtrip() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceRequestResult { envelope } =
        produce_discovery_request(channel_id, &shared_key).expect("produce should succeed");

    let ExtractRequestResult { request } =
        extract_discovery_request(&envelope, &shared_key).expect("extract should succeed");

    assert!(request.timestamp.is_some());
}

#[test]
fn test_extract_discovery_request_wrong_key_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let wrong_key = make_shared_key(2);

    let ProduceRequestResult { envelope } =
        produce_discovery_request(channel_id, &shared_key).expect("produce should succeed");

    let result = extract_discovery_request(&envelope, &wrong_key);

    assert!(result.is_err());
}

#[test]
fn test_extract_discovery_request_invalid_bytes_fails() {
    let shared_key = make_shared_key(1);

    let result = extract_discovery_request(b"not a valid protobuf envelope", &shared_key);

    assert!(result.is_err());
}

#[test]
fn test_extract_discovery_request_mismatched_timestamp_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let message_timestamp = current_timestamp();
    let mut envelope_timestamp = message_timestamp;
    envelope_timestamp.seconds += 1;

    use derec_proto::GetSecretIdsVersionsRequestMessage;

    let message = GetSecretIdsVersionsRequestMessage {
        timestamp: Some(message_timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message_body(MessageBody::GetSecretIdsVersionsRequest(message))
        .encrypt(&shared_key)
        .expect("failed to encrypt")
        .build()
        .expect("failed to build")
        .encode_to_vec();

    let result = extract_discovery_request(&envelope, &shared_key);

    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_extract_discovery_request_wrong_message_type_fails() {
    use derec_proto::{GetShareRequestMessage, MessageBody};

    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let timestamp = current_timestamp();

    let message = GetShareRequestMessage {
        secret_id: 1,
        version: 1,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetShareRequest(message))
        .encrypt(&shared_key)
        .expect("failed to encrypt")
        .build()
        .expect("failed to build")
        .encode_to_vec();

    let result = extract_discovery_request(&envelope, &shared_key);

    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_produce_discovery_response_empty_list_succeeds() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceResponseResult { envelope } =
        produce_discovery_response(channel_id, &[], &shared_key)
            .expect("produce with empty list should succeed");

    assert!(!envelope.is_empty());
}

#[test]
fn test_produce_discovery_response_with_secrets_returns_non_empty_envelope() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let secret_list = vec![
        entry(1, &[(1, "first version"), (2, "second version")]),
        entry(2, &[(1, "initial")]),
    ];

    let ProduceResponseResult { envelope } =
        produce_discovery_response(channel_id, &secret_list, &shared_key)
            .expect("produce should succeed");

    assert!(!envelope.is_empty());
}

#[test]
fn test_produce_extract_discovery_response_roundtrip() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let secret_list = vec![
        entry(1, &[(1, "v1"), (2, "v2")]),
        entry(2, &[(3, "v3")]),
    ];

    let ProduceResponseResult { envelope } =
        produce_discovery_response(channel_id, &secret_list, &shared_key)
            .expect("produce should succeed");

    let ExtractResponseResult { response } =
        extract_discovery_response(&envelope, &shared_key).expect("extract should succeed");

    assert_eq!(response.secret_list.len(), 2);
    assert_eq!(response.secret_list[0].secret_id, 1);
    assert_eq!(response.secret_list[0].versions[0].version, 1);
    assert_eq!(
        response.secret_list[0].versions[0].version_description,
        "v1"
    );
    assert_eq!(response.secret_list[0].versions[1].version, 2);
    assert_eq!(
        response.secret_list[0].versions[1].version_description,
        "v2"
    );
    assert_eq!(response.secret_list[1].secret_id, 2);
    assert_eq!(response.secret_list[1].versions[0].version, 3);
    assert_eq!(
        response.secret_list[1].versions[0].version_description,
        "v3"
    );
}

#[test]
fn test_extract_discovery_response_wrong_key_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let wrong_key = make_shared_key(2);

    let ProduceResponseResult { envelope } =
        produce_discovery_response(channel_id, &[], &shared_key).expect("produce should succeed");

    let result = extract_discovery_response(&envelope, &wrong_key);

    assert!(result.is_err());
}

#[test]
fn test_extract_discovery_response_mismatched_timestamp_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let envelope = build_response_envelope_with_mismatched_timestamp(channel_id, &shared_key);

    let result = extract_discovery_response(&envelope, &shared_key);

    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_extract_discovery_response_wrong_message_type_fails() {
    use derec_proto::GetShareResponseMessage;

    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let timestamp = current_timestamp();

    let message = GetShareResponseMessage {
        share_algorithm: 0,
        committed_de_rec_share: vec![],
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        timestamp: Some(timestamp),
        secret_id: 0,
        version: 0,
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetShareResponse(message))
        .encrypt(&shared_key)
        .expect("failed to encrypt")
        .build()
        .expect("failed to build")
        .encode_to_vec();

    let result = extract_discovery_response(&envelope, &shared_key);

    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_process_discovery_response_ok_returns_secret_list() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let secret_list = vec![
        entry(1, &[(1, "first"), (2, "second")]),
        entry(2, &[(3, "third")]),
    ];

    let ProduceResponseResult { envelope } =
        produce_discovery_response(channel_id, &secret_list, &shared_key)
            .expect("produce should succeed");

    let ExtractResponseResult { response } =
        extract_discovery_response(&envelope, &shared_key).expect("extract should succeed");

    let ProcessResult {
        secret_list: parsed,
    } = process_discovery_response(&response).expect("process should succeed");

    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].secret_id, 1);
    assert_eq!(parsed[0].versions[0].version, 1);
    assert_eq!(parsed[0].versions[0].description, "first");
    assert_eq!(parsed[0].versions[1].version, 2);
    assert_eq!(parsed[0].versions[1].description, "second");
    assert_eq!(parsed[1].secret_id, 2);
    assert_eq!(parsed[1].versions[0].version, 3);
    assert_eq!(parsed[1].versions[0].description, "third");
}

#[test]
fn test_process_discovery_response_empty_list_ok() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceResponseResult { envelope } =
        produce_discovery_response(channel_id, &[], &shared_key).expect("produce should succeed");

    let ExtractResponseResult { response } =
        extract_discovery_response(&envelope, &shared_key).expect("extract should succeed");

    let ProcessResult { secret_list } =
        process_discovery_response(&response).expect("process should succeed");

    assert!(secret_list.is_empty());
}

#[test]
fn test_process_discovery_response_missing_result_fails() {
    let envelope = build_response_envelope(ChannelId(1), &make_shared_key(1), None, vec![]);

    let ExtractResponseResult { response } =
        extract_discovery_response(&envelope, &make_shared_key(1)).expect("extract should succeed");

    let result = process_discovery_response(&response);

    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_process_discovery_response_non_ok_status_fails() {
    let envelope = build_response_envelope(
        ChannelId(1),
        &make_shared_key(1),
        Some(DeRecResult {
            status: StatusEnum::Fail as i32,
            memo: "unauthorized".to_owned(),
        }),
        vec![],
    );

    let ExtractResponseResult { response } =
        extract_discovery_response(&envelope, &make_shared_key(1)).expect("extract should succeed");

    let result = process_discovery_response(&response);

    assert!(matches!(
        result,
        Err(Error::Discovery(DiscoveryError::NonOkStatus { .. }))
    ));
}

#[test]
fn test_full_discovery_roundtrip() {
    let channel_id = ChannelId(42);
    let shared_key = make_shared_key(7);

    // Owner → Helper: produce discovery request
    let ProduceRequestResult {
        envelope: request_envelope,
    } = produce_discovery_request(channel_id, &shared_key).expect("produce request should succeed");

    // Helper: extract discovery request
    let ExtractRequestResult { request } =
        extract_discovery_request(&request_envelope, &shared_key)
            .expect("extract request should succeed");

    assert!(request.timestamp.is_some());

    // Helper → Owner: produce discovery response
    let secret_list = vec![
        entry(100, &[(1, "My main wallet")]),
        entry(200, &[
            (1, "Work SSH key"),
            (2, "Work SSH key v2"),
            (3, "Work SSH key v3"),
        ]),
    ];

    let ProduceResponseResult {
        envelope: response_envelope,
    } = produce_discovery_response(channel_id, &secret_list, &shared_key)
        .expect("produce response should succeed");

    // Owner: extract + process
    let ExtractResponseResult { response } =
        extract_discovery_response(&response_envelope, &shared_key)
            .expect("extract response should succeed");

    let ProcessResult {
        secret_list: result,
    } = process_discovery_response(&response).expect("process response should succeed");

    assert_eq!(result.len(), 2);
    assert_eq!(result[0].secret_id, 100);
    assert_eq!(result[0].versions.len(), 1);
    assert_eq!(result[0].versions[0].version, 1);
    assert_eq!(result[0].versions[0].description, "My main wallet");
    assert_eq!(result[1].secret_id, 200);
    assert_eq!(result[1].versions.len(), 3);
    assert_eq!(result[1].versions[2].version, 3);
    assert_eq!(result[1].versions[2].description, "Work SSH key v3");
}

#[test]
fn test_version_descriptions_are_preserved_through_roundtrip() {
    let channel_id = ChannelId(10);
    let shared_key = make_shared_key(5);

    let secret_list = vec![SecretVersionEntry {
        secret_id: 42,
        versions: vec![
            VersionEntry {
                version: 1,
                description: "Draft".to_owned(),
            },
            VersionEntry {
                version: 2,
                description: "Final".to_owned(),
            },
            VersionEntry {
                version: 3,
                description: String::new(),
            },
        ],
    }];

    let ProduceResponseResult { envelope } =
        produce_discovery_response(channel_id, &secret_list, &shared_key)
            .expect("produce should succeed");

    let ExtractResponseResult { response } =
        extract_discovery_response(&envelope, &shared_key).expect("extract should succeed");

    let ProcessResult {
        secret_list: parsed,
    } = process_discovery_response(&response).expect("process should succeed");

    assert_eq!(parsed[0].versions[0].description, "Draft");
    assert_eq!(parsed[0].versions[1].description, "Final");
    assert_eq!(parsed[0].versions[2].description, "");
}
