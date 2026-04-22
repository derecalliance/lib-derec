// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    primitives::channels_discovery::{
        ChannelsDiscoveryError,
        request::{
            ExtractResult as ExtractRequestResult,
            ProduceResult as ProduceRequestResult,
            extract as extract_request,
            produce as produce_request,
        },
        response::{
            ChannelEntry,
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
use derec_proto::{MessageBody, ReplicaChannelsDiscoveryResponseMessage, ReplicaChannelsEntry};
use prost::Message;

fn make_shared_key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn make_entries(keys: &[(u64, u8)]) -> Vec<ChannelEntry> {
    keys.iter()
        .map(|&(cid, key_byte)| ChannelEntry {
            channel_id: ChannelId(cid),
            shared_key: make_shared_key(key_byte),
        })
        .collect()
}

// ─── request::produce ───────────────────────────────────────────────────────

#[test]
fn test_produce_request_returns_non_empty_envelope() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceRequestResult { envelope } =
        produce_request(channel_id, &shared_key, 0).expect("produce should succeed");

    assert!(!envelope.is_empty());
}

// ─── request::extract ───────────────────────────────────────────────────────

#[test]
fn test_produce_extract_request_roundtrip() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceRequestResult { envelope } =
        produce_request(channel_id, &shared_key, 3).expect("produce should succeed");

    let ExtractRequestResult { request } =
        extract_request(&envelope, &shared_key).expect("extract should succeed");

    assert_eq!(request.last_batch_index, 3);
    assert!(request.timestamp.is_some());
}

#[test]
fn test_extract_request_wrong_key_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let wrong_key = make_shared_key(2);

    let ProduceRequestResult { envelope } =
        produce_request(channel_id, &shared_key, 0).expect("produce should succeed");

    assert!(extract_request(&envelope, &wrong_key).is_err());
}

#[test]
fn test_extract_request_invalid_bytes_fails() {
    let shared_key = make_shared_key(1);
    assert!(extract_request(b"not valid protobuf", &shared_key).is_err());
}

#[test]
fn test_extract_request_mismatched_timestamp_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let message_timestamp = current_timestamp();
    let mut envelope_timestamp = message_timestamp;
    envelope_timestamp.seconds += 1;

    let message = derec_proto::ReplicaChannelsDiscoveryRequestMessage {
        last_batch_index: 0,
        timestamp: Some(message_timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message_body(MessageBody::ReplicaChannelsDiscoveryRequest(message))
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

// ─── response::produce ──────────────────────────────────────────────────────

#[test]
fn test_produce_response_empty_entries_succeeds() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceResponseResult { envelope } =
        produce_response(channel_id, &shared_key, &[], 1, 1)
            .expect("produce with empty entries should succeed");

    assert!(!envelope.is_empty());
}

#[test]
fn test_produce_response_with_entries_succeeds() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let entries = make_entries(&[(10, 0xAA), (20, 0xBB)]);

    let ProduceResponseResult { envelope } =
        produce_response(channel_id, &shared_key, &entries, 1, 1)
            .expect("produce should succeed");

    assert!(!envelope.is_empty());
}

#[test]
fn test_produce_response_invalid_batch_metadata_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    // current_batch > total_batches
    assert!(matches!(
        produce_response(channel_id, &shared_key, &[], 1, 2),
        Err(Error::ChannelsDiscovery(
            ChannelsDiscoveryError::InvalidBatchMetadata { .. }
        ))
    ));

    // total_batches = 0
    assert!(matches!(
        produce_response(channel_id, &shared_key, &[], 0, 1),
        Err(Error::ChannelsDiscovery(
            ChannelsDiscoveryError::InvalidBatchMetadata { .. }
        ))
    ));

    // current_batch = 0
    assert!(matches!(
        produce_response(channel_id, &shared_key, &[], 1, 0),
        Err(Error::ChannelsDiscovery(
            ChannelsDiscoveryError::InvalidBatchMetadata { .. }
        ))
    ));
}

// ─── response::extract ──────────────────────────────────────────────────────

#[test]
fn test_produce_extract_response_roundtrip() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let entries = make_entries(&[(10, 0xAA), (20, 0xBB)]);

    let ProduceResponseResult { envelope } =
        produce_response(channel_id, &shared_key, &entries, 2, 1)
            .expect("produce should succeed");

    let ExtractResponseResult { response } =
        extract_response(&envelope, &shared_key).expect("extract should succeed");

    assert_eq!(response.total_batches, 2);
    assert_eq!(response.current_batch, 1);
    assert_eq!(response.entries.len(), 2);
    assert_eq!(response.entries[0].channel_id, 10);
    assert_eq!(response.entries[1].channel_id, 20);
}

#[test]
fn test_extract_response_wrong_key_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let wrong_key = make_shared_key(2);

    let ProduceResponseResult { envelope } =
        produce_response(channel_id, &shared_key, &[], 1, 1)
            .expect("produce should succeed");

    assert!(extract_response(&envelope, &wrong_key).is_err());
}

#[test]
fn test_extract_response_mismatched_timestamp_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let message_timestamp = current_timestamp();
    let mut envelope_timestamp = message_timestamp;
    envelope_timestamp.seconds += 1;

    let message = ReplicaChannelsDiscoveryResponseMessage {
        total_batches: 1,
        current_batch: 1,
        entries: vec![],
        timestamp: Some(message_timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(envelope_timestamp)
        .message_body(MessageBody::ReplicaChannelsDiscoveryResponse(message))
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
fn test_process_response_returns_entries() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let entries = make_entries(&[(10, 0xAA), (20, 0xBB)]);

    let ProduceResponseResult { envelope } =
        produce_response(channel_id, &shared_key, &entries, 1, 1)
            .expect("produce should succeed");

    let ExtractResponseResult { response } =
        extract_response(&envelope, &shared_key).expect("extract should succeed");

    let ProcessResult {
        total_batches,
        current_batch,
        entries: parsed,
    } = process_response(&response).expect("process should succeed");

    assert_eq!(total_batches, 1);
    assert_eq!(current_batch, 1);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].channel_id, ChannelId(10));
    assert_eq!(parsed[0].shared_key, make_shared_key(0xAA));
    assert_eq!(parsed[1].channel_id, ChannelId(20));
    assert_eq!(parsed[1].shared_key, make_shared_key(0xBB));
}

#[test]
fn test_process_response_empty_entries_succeeds() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);

    let ProduceResponseResult { envelope } =
        produce_response(channel_id, &shared_key, &[], 1, 1)
            .expect("produce should succeed");

    let ExtractResponseResult { response } =
        extract_response(&envelope, &shared_key).expect("extract should succeed");

    let ProcessResult { entries, .. } =
        process_response(&response).expect("process should succeed");

    assert!(entries.is_empty());
}

#[test]
fn test_process_response_invalid_batch_metadata_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let timestamp = current_timestamp();

    let message = ReplicaChannelsDiscoveryResponseMessage {
        total_batches: 0,
        current_batch: 1,
        entries: vec![],
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::ReplicaChannelsDiscoveryResponse(message))
        .encrypt(&shared_key)
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec();

    let ExtractResponseResult { response } =
        extract_response(&envelope, &shared_key).expect("extract should succeed");

    assert!(matches!(
        process_response(&response),
        Err(Error::ChannelsDiscovery(
            ChannelsDiscoveryError::InvalidBatchMetadata { .. }
        ))
    ));
}

#[test]
fn test_process_response_invalid_shared_key_length_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let timestamp = current_timestamp();

    let message = ReplicaChannelsDiscoveryResponseMessage {
        total_batches: 1,
        current_batch: 1,
        entries: vec![ReplicaChannelsEntry {
            channel_id: 10,
            shared_key: vec![0xAA; 16], // wrong length
        }],
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::ReplicaChannelsDiscoveryResponse(message))
        .encrypt(&shared_key)
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec();

    let ExtractResponseResult { response } =
        extract_response(&envelope, &shared_key).expect("extract should succeed");

    assert!(matches!(
        process_response(&response),
        Err(Error::ChannelsDiscovery(
            ChannelsDiscoveryError::InvalidSharedKeyLength { index: 0, len: 16 }
        ))
    ));
}

#[test]
fn test_process_response_empty_shared_key_fails() {
    let channel_id = ChannelId(1);
    let shared_key = make_shared_key(1);
    let timestamp = current_timestamp();

    let message = ReplicaChannelsDiscoveryResponseMessage {
        total_batches: 1,
        current_batch: 1,
        entries: vec![ReplicaChannelsEntry {
            channel_id: 10,
            shared_key: vec![],
        }],
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::ReplicaChannelsDiscoveryResponse(message))
        .encrypt(&shared_key)
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec();

    let ExtractResponseResult { response } =
        extract_response(&envelope, &shared_key).expect("extract should succeed");

    assert!(matches!(
        process_response(&response),
        Err(Error::ChannelsDiscovery(
            ChannelsDiscoveryError::EmptySharedKey { index: 0 }
        ))
    ));
}

// ─── Full roundtrip ─────────────────────────────────────────────────────────

#[test]
fn test_full_channels_discovery_roundtrip() {
    let replica_channel_id = ChannelId(42);
    let replica_shared_key = make_shared_key(7);

    let helper_channels = make_entries(&[
        (100, 0x11),
        (200, 0x22),
        (300, 0x33),
    ]);

    // Replica → Owner: request channels
    let ProduceRequestResult { envelope: request_envelope } =
        produce_request(replica_channel_id, &replica_shared_key, 0)
            .expect("produce request should succeed");

    // Owner: extract request
    let ExtractRequestResult { request } =
        extract_request(&request_envelope, &replica_shared_key)
            .expect("extract request should succeed");

    assert_eq!(request.last_batch_index, 0);

    // Owner → Replica: respond with channels (single batch)
    let ProduceResponseResult { envelope: response_envelope } =
        produce_response(
            replica_channel_id,
            &replica_shared_key,
            &helper_channels,
            1,
            1,
        )
        .expect("produce response should succeed");

    // Replica: extract + process
    let ExtractResponseResult { response } =
        extract_response(&response_envelope, &replica_shared_key)
            .expect("extract response should succeed");

    let ProcessResult {
        total_batches,
        current_batch,
        entries,
    } = process_response(&response).expect("process response should succeed");

    assert_eq!(total_batches, 1);
    assert_eq!(current_batch, 1);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].channel_id, ChannelId(100));
    assert_eq!(entries[0].shared_key, make_shared_key(0x11));
    assert_eq!(entries[1].channel_id, ChannelId(200));
    assert_eq!(entries[2].channel_id, ChannelId(300));
}

// ─── Multi-batch roundtrip ──────────────────────────────────────────────────

#[test]
fn test_multi_batch_channels_discovery() {
    let replica_channel_id = ChannelId(42);
    let replica_shared_key = make_shared_key(7);

    let batch1 = make_entries(&[(100, 0x11), (200, 0x22)]);
    let batch2 = make_entries(&[(300, 0x33)]);

    // Batch 1
    let ProduceResponseResult { envelope: env1 } =
        produce_response(replica_channel_id, &replica_shared_key, &batch1, 2, 1)
            .expect("batch 1 produce should succeed");

    let ExtractResponseResult { response: resp1 } =
        extract_response(&env1, &replica_shared_key).expect("batch 1 extract should succeed");

    let result1 = process_response(&resp1).expect("batch 1 process should succeed");
    assert_eq!(result1.total_batches, 2);
    assert_eq!(result1.current_batch, 1);
    assert_eq!(result1.entries.len(), 2);

    // Batch 2
    let ProduceResponseResult { envelope: env2 } =
        produce_response(replica_channel_id, &replica_shared_key, &batch2, 2, 2)
            .expect("batch 2 produce should succeed");

    let ExtractResponseResult { response: resp2 } =
        extract_response(&env2, &replica_shared_key).expect("batch 2 extract should succeed");

    let result2 = process_response(&resp2).expect("batch 2 process should succeed");
    assert_eq!(result2.total_batches, 2);
    assert_eq!(result2.current_batch, 2);
    assert_eq!(result2.entries.len(), 1);
    assert_eq!(result2.entries[0].channel_id, ChannelId(300));
}
