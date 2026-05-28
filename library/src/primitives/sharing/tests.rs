use crate::{
    Error,
    primitives::sharing::{
        SharingError,
        request::{
            ExtractResult as ExtractStoreShareRequestResult,
            ProduceResult as ProduceStoreShareRequestMessageResult, SplitResult,
            extract as extract_store_share_request, produce as produce_store_share_request_message,
            split,
        },
        response::{
            ExtractResult as ExtractStoreShareResponseResult,
            ProduceResult as ProduceStoreShareResponseMessageResult,
            extract as extract_store_share_response,
            process as process_store_share_response_message,
            produce as produce_store_share_response_message,
        },
    },
    types::ChannelId,
};
use derec_proto::{CommittedDeRecShare, DeRecShare};
use prost::Message;

fn make_channel_ids(ids: &[u64]) -> Vec<ChannelId> {
    ids.iter().map(|&id| ChannelId(id)).collect()
}

/// Build a valid `StoreShareRequestMessage` with a `CommittedDeRecShare`
/// that has been mutated by `mutate`. Returns the `StoreShareRequestMessage`
/// to pass directly to `produce_store_share_response_message`.
fn make_request_with_mutated_share(
    mutate: impl FnOnce(&mut CommittedDeRecShare),
) -> derec_proto::StoreShareRequestMessage {
    use crate::derec_message::current_timestamp;

    let secret_id: u64 = 1;
    let secret_data = b"test-data";
    let channels = make_channel_ids(&[1, 2, 3]);
    let version = 1;

    let SplitResult { mut shares } =
        split(&channels, secret_id, version, secret_data, 2).expect("split should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares.get_mut(&channel_id).expect("missing share");
    mutate(committed_share);

    let timestamp = current_timestamp();
    derec_proto::StoreShareRequestMessage {
        share: committed_share.encode_to_vec(),
        share_algorithm: 0,
        version,
        keep_list: vec![],
        version_description: String::new(),
        timestamp: Some(timestamp),
        secret_id,
    }
}

#[test]
fn test_split_empty_channels() {
    let secret_id: u64 = 1;
    let secret_data = b"secret-data";
    let threshold = 2;
    let version = 1;

    let result = split(&[], secret_id, version, secret_data, threshold);

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::EmptyChannels))
    ));
}

#[test]
fn test_split_empty_secret_data() {
    let secret_id: u64 = 1;
    let empty_secret_data = b"";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 1;

    let result = split(&channels, secret_id, version, empty_secret_data, threshold);

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::EmptySecretData))
    ));
}

#[test]
fn test_split_invalid_threshold_too_low() {
    let secret_id: u64 = 1;
    let secret_data = b"secret-data";
    let channels = make_channel_ids(&[1, 2, 3]);
    let too_low_threshold = 1;
    let version = 1;

    let result = split(
        &channels,
        secret_id,
        version,
        secret_data,
        too_low_threshold,
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
fn test_split_invalid_threshold_too_high() {
    let secret_id: u64 = 1;
    let secret_data = b"secret-data";
    let channels = make_channel_ids(&[1, 2, 3]);
    let too_high_threshold = 4;
    let version = 1;

    let result = split(
        &channels,
        secret_id,
        version,
        secret_data,
        too_high_threshold,
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
fn test_split_valid_sharing() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, threshold).expect("split should succeed");

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

        assert_eq!(inner.secret_id, secret_id);
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
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, threshold).expect("split should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult { envelope } = produce_store_share_request_message(
        channel_id,
        version,
        secret_id,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    assert!(
        !envelope.is_empty(),
        "envelope wire bytes must not be empty"
    );
}

#[test]
fn test_produce_store_share_request_message_with_keep_list_and_description() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 3;
    let shared_key = [7u8; 32];

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, threshold).expect("split should succeed");

    let channel_id = ChannelId(2);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 2");

    let ProduceStoreShareRequestMessageResult { envelope } = produce_store_share_request_message(
        channel_id,
        version,
        secret_id,
        committed_share,
        &[1, 2],
        "initial share distribution",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    assert!(
        !envelope.is_empty(),
        "envelope wire bytes must not be empty"
    );
}

#[test]
fn test_produce_store_share_response_message_valid() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, threshold).expect("split should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult {
        envelope: request_envelope,
    } = produce_store_share_request_message(
        channel_id,
        version,
        secret_id,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    let ExtractStoreShareRequestResult { request } =
        extract_store_share_request(&request_envelope, &shared_key)
            .expect("extract_store_share_request should succeed");

    let ProduceStoreShareResponseMessageResult {
        envelope: response_envelope,
        committed_share: returned_share,
        secret_id: returned_secret_id,
        version: returned_version,
    } = produce_store_share_response_message(channel_id, &request, &shared_key)
        .expect("produce_store_share_response_message should succeed");

    assert!(
        !response_envelope.is_empty(),
        "response envelope wire bytes must not be empty"
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

    assert_eq!(
        returned_secret_id, secret_id,
        "returned secret_id must match the original"
    );
    assert_eq!(
        returned_version, version,
        "returned version must match the request version"
    );
}

#[test]
fn test_extract_store_share_request_wrong_key() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];
    let wrong_key = [99u8; 32];

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, threshold).expect("split should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult {
        envelope: request_envelope,
    } = produce_store_share_request_message(
        channel_id,
        version,
        secret_id,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    let result = extract_store_share_request(&request_envelope, &wrong_key);
    assert!(result.is_err(), "should fail with wrong key");
}

#[test]
fn test_split_rejects_duplicate_channels() {
    let secret_id: u64 = 1;
    let secret_data = b"secret-data";
    let channels = make_channel_ids(&[1, 2, 3, 2, 1]);
    let threshold = 2;
    let version = 1;

    let result = split(&channels, secret_id, version, secret_data, threshold);

    assert!(
        matches!(
            result,
            Err(Error::Sharing(SharingError::DuplicateChannelId(_)))
        ),
        "expected DuplicateChannelId error"
    );
}

#[test]
fn test_split_rejects_single_duplicate_channel() {
    let secret_id: u64 = 1;
    let secret_data = b"secret-data";
    let channels = make_channel_ids(&[1, 2, 2]);
    let threshold = 2;
    let version = 1;

    let result = split(&channels, secret_id, version, secret_data, threshold);

    assert!(
        matches!(
            result,
            Err(Error::Sharing(SharingError::DuplicateChannelId(2)))
        ),
        "expected DuplicateChannelId(2)"
    );
}

#[test]
fn test_process_store_share_response_message_valid() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, threshold).expect("split should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult {
        envelope: request_envelope,
    } = produce_store_share_request_message(
        channel_id,
        version,
        secret_id,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    let ExtractStoreShareRequestResult { request } =
        extract_store_share_request(&request_envelope, &shared_key)
            .expect("extract_store_share_request should succeed");

    let ProduceStoreShareResponseMessageResult {
        envelope: response_envelope,
        ..
    } = produce_store_share_response_message(channel_id, &request, &shared_key)
        .expect("produce_store_share_response_message should succeed");

    let ExtractStoreShareResponseResult { response } =
        extract_store_share_response(&response_envelope, &shared_key)
            .expect("extract_store_share_response should succeed");

    process_store_share_response_message(version, &response)
        .expect("process_store_share_response_message should succeed");
}

#[test]
fn test_process_store_share_response_message_wrong_version() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, threshold).expect("split should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult {
        envelope: request_envelope,
    } = produce_store_share_request_message(
        channel_id,
        version,
        secret_id,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    let ExtractStoreShareRequestResult { request } =
        extract_store_share_request(&request_envelope, &shared_key)
            .expect("extract_store_share_request should succeed");

    let ProduceStoreShareResponseMessageResult {
        envelope: response_envelope,
        ..
    } = produce_store_share_response_message(channel_id, &request, &shared_key)
        .expect("produce_store_share_response_message should succeed");

    let ExtractStoreShareResponseResult { response } =
        extract_store_share_response(&response_envelope, &shared_key)
            .expect("extract_store_share_response should succeed");

    let wrong_version = version + 1;
    let result = process_store_share_response_message(wrong_version, &response);
    assert!(result.is_err(), "should fail when version does not match");
}

#[test]
fn test_extract_store_share_response_wrong_key() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = [42u8; 32];
    let wrong_key = [99u8; 32];

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, threshold).expect("split should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares
        .get(&channel_id)
        .expect("missing share for channel 1");

    let ProduceStoreShareRequestMessageResult {
        envelope: request_envelope,
    } = produce_store_share_request_message(
        channel_id,
        version,
        secret_id,
        committed_share,
        &[],
        "",
        &shared_key,
    )
    .expect("produce_store_share_request_message should succeed");

    let ExtractStoreShareRequestResult { request } =
        extract_store_share_request(&request_envelope, &shared_key)
            .expect("extract_store_share_request should succeed");

    let ProduceStoreShareResponseMessageResult {
        envelope: response_envelope,
        ..
    } = produce_store_share_response_message(channel_id, &request, &shared_key)
        .expect("produce_store_share_response_message should succeed");

    let result = extract_store_share_response(&response_envelope, &wrong_key);
    assert!(result.is_err(), "should fail with wrong key");
}

#[test]
fn test_produce_store_share_response_message_rejects_empty_commitment() {
    let request = make_request_with_mutated_share(|share| {
        share.commitment.clear();
    });

    let shared_key = [1u8; 32];
    let channel_id = ChannelId(1);

    let result = produce_store_share_response_message(channel_id, &request, &shared_key);
    assert!(result.is_err(), "should reject share with empty commitment");
}

#[test]
fn test_produce_store_share_response_message_rejects_empty_merkle_path() {
    let request = make_request_with_mutated_share(|share| {
        share.merkle_path.clear();
    });

    let shared_key = [1u8; 32];
    let channel_id = ChannelId(1);

    let result = produce_store_share_response_message(channel_id, &request, &shared_key);
    assert!(
        result.is_err(),
        "should reject share with empty merkle_path"
    );
}

#[test]
fn test_produce_store_share_response_message_rejects_tampered_commitment() {
    let request = make_request_with_mutated_share(|share| {
        if let Some(first) = share.commitment.first_mut() {
            *first ^= 0xFF;
        }
    });

    let shared_key = [1u8; 32];
    let channel_id = ChannelId(1);

    let result = produce_store_share_response_message(channel_id, &request, &shared_key);
    assert!(
        result.is_err(),
        "should reject share whose commitment does not match Merkle proof"
    );
}
