use crate::{
    Error,
    sharing::{
        ProduceStoreShareRequestMessageResult, ProduceStoreShareResponseMessageResult,
        ProtectSecretResult, SharingError, process_store_share_response_message,
        produce_store_share_request_message, produce_store_share_response_message, protect_secret,
    },
    types::ChannelId,
};
use derec_proto::{CommittedDeRecShare, DeRecShare};
use prost::Message;

fn make_channel_ids(ids: &[u64]) -> Vec<ChannelId> {
    ids.iter().map(|&id| ChannelId(id)).collect()
}

#[test]
fn test_protect_secret_empty_channels() {
    let secret_id = b"secret-id";
    let secret_data = b"secret-data";
    let threshold = 2;
    let version = 1;

    let result = protect_secret(secret_id, secret_data, &[], threshold, version);

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::EmptyChannels))
    ));
}

#[test]
fn test_protect_secret_empty_secret_id() {
    let empty_secret_id = b"";
    let secret_data = b"secret-data";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 1;

    let result = protect_secret(empty_secret_id, secret_data, &channels, threshold, version);

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::EmptySecretId))
    ));
}

#[test]
fn test_protect_secret_empty_secret_data() {
    let secret_id = b"secret-id";
    let empty_secret_data = b"";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 1;

    let result = protect_secret(secret_id, empty_secret_data, &channels, threshold, version);

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::EmptySecretData))
    ));
}

#[test]
fn test_protect_secret_invalid_threshold_too_low() {
    let secret_id = b"secret-id";
    let secret_data = b"secret-data";
    let channels = make_channel_ids(&[1, 2, 3]);
    let too_low_threshold = 1;
    let version = 1;

    let result = protect_secret(
        secret_id,
        secret_data,
        &channels,
        too_low_threshold,
        version,
    );

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::InvalidThreshold {
            threshold: 1,
            channels: 3
        }))
    ));
}

#[test]
fn test_protect_secret_invalid_threshold_too_high() {
    let secret_id = b"secret-id";
    let secret_data = b"secret-data";
    let channels = make_channel_ids(&[1, 2, 3]);
    let too_high_threshold = 4;
    let version = 1;

    let result = protect_secret(
        secret_id,
        secret_data,
        &channels,
        too_high_threshold,
        version,
    );

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::InvalidThreshold {
            threshold: 4,
            channels: 3
        }))
    ));
}

#[test]
fn test_protect_secret_valid_sharing() {
    let secret_id = b"my_secret_id";
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;

    let ProtectSecretResult { shares } =
        protect_secret(secret_id, secret_data, &channels, threshold, version)
            .expect("protect_secret should succeed");

    assert_eq!(
        shares.len(),
        channels.len(),
        "invalid number of shares given the number of channels"
    );

    for channel_id in &channels {
        let committed = shares
            .get(channel_id)
            .expect("missing CommittedDeRecShare for channel");

        assert!(
            !committed.commitment.is_empty(),
            "commitment must not be empty"
        );

        assert!(
            !committed.merkle_path.is_empty(),
            "merkle_path must not be empty"
        );

        let inner = DeRecShare::decode(&committed.de_rec_share[..])
            .expect("failed to decode inner DeRecShare");

        assert_eq!(inner.secret_id, secret_id.to_vec());
        assert_eq!(inner.version, version);

        assert!(
            !inner.encrypted_secret.is_empty(),
            "encrypted_secret must not be empty"
        );
        assert!(!inner.x.is_empty(), "share x coordinate must not be empty");
        assert!(!inner.y.is_empty(), "share y coordinate must not be empty");
    }
}

#[test]
fn test_produce_store_share_request_message_valid() {
    let secret_id = b"my_secret_id";
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];

    let ProtectSecretResult { shares } =
        protect_secret(secret_id, secret_data, &channels, threshold, version)
            .expect("protect_secret should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult { wire_bytes } = produce_store_share_request_message(
        channel_id,
        version,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    assert!(!wire_bytes.is_empty(), "wire_bytes must not be empty");
}

#[test]
fn test_produce_store_share_request_message_with_keep_list_and_description() {
    let secret_id = b"my_secret_id";
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 3;
    let shared_key = [7u8; 32];

    let ProtectSecretResult { shares } =
        protect_secret(secret_id, secret_data, &channels, threshold, version)
            .expect("protect_secret should succeed");

    let channel_id = ChannelId(2);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 2");

    let ProduceStoreShareRequestMessageResult { wire_bytes } = produce_store_share_request_message(
        channel_id,
        version,
        committed_share,
        &[1, 2],
        "initial share distribution",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    assert!(!wire_bytes.is_empty(), "wire_bytes must not be empty");
}

#[test]
fn test_produce_store_share_response_message_valid() {
    let secret_id = b"my_secret_id";
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];

    let ProtectSecretResult { shares } =
        protect_secret(secret_id, secret_data, &channels, threshold, version)
            .expect("protect_secret should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult {
        wire_bytes: request_bytes,
    } = produce_store_share_request_message(
        channel_id,
        version,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    let ProduceStoreShareResponseMessageResult {
        wire_bytes,
        committed_share: returned_share,
    } = produce_store_share_response_message(channel_id, &shared_key, &request_bytes)
        .expect("produce_store_share_response_message should succeed");

    assert!(
        !wire_bytes.is_empty(),
        "response wire_bytes must not be empty"
    );

    // Committed share extracted from the request must match what was originally inserted.
    assert_eq!(
        returned_share.commitment, committed_share.commitment,
        "returned commitment must match original"
    );
    assert_eq!(
        returned_share.de_rec_share, committed_share.de_rec_share,
        "returned de_rec_share must match original"
    );
    assert_eq!(
        returned_share.merkle_path.len(),
        committed_share.merkle_path.len(),
        "returned merkle_path length must match original"
    );
}

#[test]
fn test_produce_store_share_response_message_wrong_key() {
    let secret_id = b"my_secret_id";
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];
    let wrong_key = [99u8; 32];

    let ProtectSecretResult { shares } =
        protect_secret(secret_id, secret_data, &channels, threshold, version)
            .expect("protect_secret should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult {
        wire_bytes: request_bytes,
    } = produce_store_share_request_message(
        channel_id,
        version,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    let result = produce_store_share_response_message(channel_id, &wrong_key, &request_bytes);
    assert!(result.is_err(), "should fail with wrong key");
}

#[test]
fn test_protect_secret_rejects_duplicate_channels() {
    let secret_id = b"secret-id";
    let secret_data = b"secret-data";
    let channels = make_channel_ids(&[1, 2, 3, 2, 1]);
    let threshold = 2;
    let version = 1;

    let result = protect_secret(secret_id, secret_data, &channels, threshold, version);

    assert!(
        matches!(result, Err(Error::Sharing(SharingError::DuplicateChannelId(_)))),
        "expected DuplicateChannelId error"
    );
}

#[test]
fn test_protect_secret_rejects_single_duplicate_channel() {
    let secret_id = b"secret-id";
    let secret_data = b"secret-data";
    let channels = make_channel_ids(&[1, 2, 2]);
    let threshold = 2;
    let version = 1;

    let result = protect_secret(secret_id, secret_data, &channels, threshold, version);

    assert!(
        matches!(result, Err(Error::Sharing(SharingError::DuplicateChannelId(2)))),
        "expected DuplicateChannelId(2)"
    );
}

#[test]
fn test_process_store_share_response_message_valid() {
    let secret_id = b"my_secret_id";
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];

    let ProtectSecretResult { shares } =
        protect_secret(secret_id, secret_data, &channels, threshold, version)
            .expect("protect_secret should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares.get(&channel_id).expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult {
        wire_bytes: request_bytes,
    } = produce_store_share_request_message(
        channel_id,
        version,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    let ProduceStoreShareResponseMessageResult {
        wire_bytes: response_bytes,
        ..
    } = produce_store_share_response_message(channel_id, &shared_key, &request_bytes)
        .expect("produce_store_share_response_message should succeed");

    process_store_share_response_message(version, &shared_key, &response_bytes)
        .expect("process_store_share_response_message should succeed");
}

#[test]
fn test_process_store_share_response_message_wrong_version() {
    let secret_id = b"my_secret_id";
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];

    let ProtectSecretResult { shares } =
        protect_secret(secret_id, secret_data, &channels, threshold, version)
            .expect("protect_secret should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares.get(&channel_id).expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult {
        wire_bytes: request_bytes,
    } = produce_store_share_request_message(
        channel_id,
        version,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    let ProduceStoreShareResponseMessageResult {
        wire_bytes: response_bytes,
        ..
    } = produce_store_share_response_message(channel_id, &shared_key, &request_bytes)
        .expect("produce_store_share_response_message should succeed");

    let wrong_version = version + 1;
    let result = process_store_share_response_message(wrong_version, &shared_key, &response_bytes);
    assert!(result.is_err(), "should fail when version does not match");
}

#[test]
fn test_process_store_share_response_message_wrong_key() {
    let secret_id = b"my_secret_id";
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];
    let wrong_key = [99u8; 32];

    let ProtectSecretResult { shares } =
        protect_secret(secret_id, secret_data, &channels, threshold, version)
            .expect("protect_secret should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares.get(&channel_id).expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult {
        wire_bytes: request_bytes,
    } = produce_store_share_request_message(
        channel_id,
        version,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    let ProduceStoreShareResponseMessageResult {
        wire_bytes: response_bytes,
        ..
    } = produce_store_share_response_message(channel_id, &shared_key, &request_bytes)
        .expect("produce_store_share_response_message should succeed");

    let result = process_store_share_response_message(version, &wrong_key, &response_bytes);
    assert!(result.is_err(), "should fail with wrong key");
}

// ── Merkle commitment / path validation ──────────────────────────────────────

/// Build a valid `StoreShareRequestMessage` wire envelope containing a `CommittedDeRecShare`
/// that has been mutated by `mutate`. Returns the wire bytes to pass to
/// `produce_store_share_response_message`.
fn make_request_with_mutated_share(
    mutate: impl FnOnce(&mut CommittedDeRecShare),
) -> Vec<u8> {
    let secret_id = b"test-id";
    let secret_data = b"test-data";
    let channels = make_channel_ids(&[1, 2, 3]);
    let shared_key = [1u8; 32];
    let version = 1;

    let ProtectSecretResult { mut shares } =
        protect_secret(secret_id, secret_data, &channels, 2, version)
            .expect("protect_secret should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares.get_mut(&channel_id).expect("missing share");
    mutate(committed_share);

    // Manually build the request bytes since produce_store_share_request_message
    // takes an immutable reference to a valid share — we bypass it here to inject
    // the tampered share directly.
    use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
    use derec_proto::StoreShareRequestMessage;

    let timestamp = current_timestamp();
    let msg = StoreShareRequestMessage {
        share: committed_share.encode_to_vec(),
        share_algorithm: 0,
        version,
        keep_list: vec![],
        version_description: String::new(),
        timestamp: Some(timestamp),
    };

    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(&msg)
        .encrypt(&shared_key)
        .expect("encrypt should succeed")
        .build()
        .expect("build should succeed")
        .encode_to_vec()
}

#[test]
fn test_produce_store_share_response_message_rejects_empty_commitment() {
    let request_bytes = make_request_with_mutated_share(|share| {
        share.commitment.clear();
    });

    let shared_key = [1u8; 32];
    let channel_id = ChannelId(1);

    let result = produce_store_share_response_message(channel_id, &shared_key, &request_bytes);
    assert!(
        result.is_err(),
        "should reject share with empty commitment"
    );
}

#[test]
fn test_produce_store_share_response_message_rejects_empty_merkle_path() {
    let request_bytes = make_request_with_mutated_share(|share| {
        share.merkle_path.clear();
    });

    let shared_key = [1u8; 32];
    let channel_id = ChannelId(1);

    let result = produce_store_share_response_message(channel_id, &shared_key, &request_bytes);
    assert!(
        result.is_err(),
        "should reject share with empty merkle_path"
    );
}

#[test]
fn test_produce_store_share_response_message_rejects_tampered_commitment() {
    let request_bytes = make_request_with_mutated_share(|share| {
        if let Some(first) = share.commitment.first_mut() {
            *first ^= 0xFF;
        }
    });

    let shared_key = [1u8; 32];
    let channel_id = ChannelId(1);

    let result = produce_store_share_response_message(channel_id, &shared_key, &request_bytes);
    assert!(
        result.is_err(),
        "should reject share whose commitment does not match Merkle proof"
    );
}
