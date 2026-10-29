// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::types::SharedKey;
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
    types::{ChannelId, WeightedChannel},
};
use derec_proto::{CommittedDeRecShare, DeRecShare};
use prost::Message;

/// Every channel at weight 1: one subshare each.
fn make_channel_ids(ids: &[u64]) -> Vec<WeightedChannel> {
    ids.iter().map(|&id| (ChannelId(id), 1)).collect()
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
        keep_version: 0,
        version_description: String::new(),
        timestamp: Some(timestamp),
        secret_id,
        reply_to_transports: Vec::new(),
        replica_id: None,
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
            channels: 3,
            subshares: 3
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
            channels: 3,
            subshares: 3
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

    for (channel_id, _) in &channels {
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
        assert_eq!(
            inner.subshares.len(),
            1,
            "every helper holds exactly one subshare"
        );
        assert!(
            !inner.subshares[0].x.is_empty(),
            "x coordinate must not be empty"
        );
        assert!(
            !inner.subshares[0].y.is_empty(),
            "y coordinate must not be empty"
        );
    }
}

#[test]
fn test_produce_store_share_request_message_valid() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = SharedKey::new([42u8; 32]);

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
        0,
        "",
        &shared_key,
        &[],
    )
    .expect("produce_store_share_request_message should succeed");

    assert!(
        !envelope.is_empty(),
        "envelope wire bytes must not be empty"
    );
}

#[test]
fn test_produce_store_share_request_message_with_keep_version_and_description() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 3;
    let shared_key = SharedKey::new([7u8; 32]);

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
        2,
        "initial share distribution",
        &shared_key,
        &[],
    )
    .expect("produce_store_share_request_message should succeed");

    let request = crate::primitives::sharing::request::extract(&envelope, &shared_key)
        .expect("extract should succeed")
        .request;
    assert_eq!(request.keep_version, 2);
}

#[test]
fn a_keep_version_at_or_above_the_shared_version_is_refused() {
    let secret_id: u64 = 1;
    let version = 3;
    let shared_key = SharedKey::new([7u8; 32]);
    let SplitResult { shares } = split(
        &make_channel_ids(&[1, 2, 3]),
        secret_id,
        version,
        b"super_secret_value",
        2,
    )
    .expect("split should succeed");
    let committed_share = shares.get(&ChannelId(1)).expect("missing share");

    for keep_version in [version, version + 1] {
        let err = produce_store_share_request_message(
            ChannelId(1),
            version,
            secret_id,
            committed_share,
            keep_version,
            "",
            &shared_key,
            &[],
        )
        .err()
        .expect("keep_version not below version must be refused");
        assert!(
            matches!(
                err,
                crate::Error::Sharing(SharingError::InvalidKeepVersion {
                    keep_version: k,
                    version: v,
                }) if k == keep_version && v == version
            ),
            "{err:?}"
        );
    }
}

#[test]
fn a_helper_refuses_a_keep_version_at_or_above_the_shared_version() {
    let mut request = make_request_with_mutated_share(|_| {});
    request.keep_version = request.version;
    let fault = crate::primitives::sharing::response::validate_share(&request)
        .expect_err("keep_version equal to version must be refused");
    assert_eq!(fault.status, derec_proto::StatusEnum::FormatError);
}

#[test]
fn test_produce_store_share_response_message_valid() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let shared_key = SharedKey::new([42u8; 32]);

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
        0,
        "",
        &shared_key,
        &[],
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
    let shared_key = SharedKey::new([42u8; 32]);
    let wrong_key = SharedKey::new([99u8; 32]);

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
        0,
        "",
        &shared_key,
        &[],
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
    let shared_key = SharedKey::new([42u8; 32]);

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
        0,
        "",
        &shared_key,
        &[],
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
    let shared_key = SharedKey::new([42u8; 32]);

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
        0,
        "",
        &shared_key,
        &[],
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
    let shared_key = SharedKey::new([42u8; 32]);
    let wrong_key = SharedKey::new([99u8; 32]);

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
        0,
        "",
        &shared_key,
        &[],
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

    let shared_key = SharedKey::new([1u8; 32]);
    let channel_id = ChannelId(1);

    let result = produce_store_share_response_message(channel_id, &request, &shared_key);
    assert!(result.is_err(), "should reject share with empty commitment");
}

#[test]
fn test_produce_store_share_response_message_rejects_empty_merkle_path() {
    let request = make_request_with_mutated_share(|share| {
        share.merkle_path.clear();
    });

    let shared_key = SharedKey::new([1u8; 32]);
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

    let shared_key = SharedKey::new([1u8; 32]);
    let channel_id = ChannelId(1);

    let result = produce_store_share_response_message(channel_id, &request, &shared_key);
    assert!(
        result.is_err(),
        "should reject share whose commitment does not match Merkle proof"
    );
}

/// The validator a Helper runs before storing classifies each failure by
/// the status it answers the Owner with.
#[test]
fn validate_share_classifies_each_failure_by_status() {
    use crate::primitives::sharing::response::validate_share;
    use derec_proto::StatusEnum;

    let status_of = |request: &derec_proto::StoreShareRequestMessage| {
        validate_share(request)
            .map(|_| ())
            .map_err(|f| (f.status, f.memo))
    };

    assert_eq!(status_of(&make_request_with_mutated_share(|_| {})), Ok(()));

    let mut empty = make_request_with_mutated_share(|_| {});
    empty.share.clear();
    assert_eq!(
        status_of(&empty).unwrap_err().0,
        StatusEnum::FormatError,
        "an empty share"
    );

    let mut garbage = make_request_with_mutated_share(|_| {});
    garbage.share = b"not a share".to_vec();
    assert_eq!(
        status_of(&garbage).unwrap_err().0,
        StatusEnum::FormatError,
        "bytes that are not a CommittedDeRecShare"
    );

    assert_eq!(
        status_of(&make_request_with_mutated_share(|s| s.commitment.clear())),
        Err((
            StatusEnum::FormatError,
            "CommittedDeRecShare.commitment is empty"
        )),
    );

    assert_eq!(
        status_of(&make_request_with_mutated_share(|s| {
            s.de_rec_share = b"not a share".to_vec();
        }))
        .unwrap_err()
        .0,
        StatusEnum::FormatError,
        "a de_rec_share that is not a DeRecShare"
    );

    assert_eq!(
        status_of(&make_request_with_mutated_share(|s| {
            s.merkle_path[0].hash[0] ^= 0xFF;
        }))
        .unwrap_err()
        .0,
        StatusEnum::VerificationFailed,
        "a Merkle path that does not lead to the commitment"
    );

    assert_eq!(
        status_of(&make_request_with_mutated_share(|s| {
            let mut inner = DeRecShare::decode(s.de_rec_share.as_slice()).expect("inner share");
            inner.subshares.clear();
            s.de_rec_share = inner.encode_to_vec();
        }))
        .unwrap_err()
        .0,
        StatusEnum::VerificationFailed,
        "a share with no subshares"
    );
}

/// A peer-supplied `reply_to` that declares `Protocol::Https` but ships
/// a URI with an unsupported scheme is rejected at extract — the
/// scheme-vs-protocol gate is what stops a malicious request sender
/// from redirecting our response onto an arbitrary non-HTTP(S) channel.
/// (`http://` is intentionally accepted as a dev-mode affordance and
/// is flagged via `tracing::warn!`; see `crate::transport`.)
#[test]
fn test_extract_store_share_request_rejects_scheme_mismatched_reply_to() {
    let secret_id: u64 = 1;
    let secret_data = b"share-extract-validation";
    let channels = make_channel_ids(&[1, 2, 3]);
    let version = 1;

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, 2).expect("split should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares.get(&channel_id).expect("missing share");
    let shared_key = SharedKey::new([1u8; 32]);

    let malicious_reply_to = derec_proto::TransportProtocol {
        uri: "ws://attacker.example/inbox".to_owned(),
        protocol: derec_proto::Protocol::Https as i32,
    };

    let ProduceStoreShareRequestMessageResult { envelope } = produce_store_share_request_message(
        channel_id,
        version,
        secret_id,
        committed_share,
        0,
        String::new(),
        &shared_key,
        std::slice::from_ref(&malicious_reply_to),
    )
    .expect("failed to produce store share request");

    let result = extract_store_share_request(&envelope, &shared_key);

    assert!(matches!(
        result,
        Err(Error::Transport(
            crate::transport::TransportValidationError::SchemeMismatch { .. }
        ))
    ));
}

/// Helper-bound requests carry no writer identity: the audience
/// invariant is enforced by construction, not by the caller.
#[test]
fn helper_bound_request_never_carries_a_replica_id() {
    let secret_id: u64 = 1;
    let secret_data = b"helper-bound-has-no-replica-id";
    let channels = make_channel_ids(&[1, 2, 3]);
    let version = 1;

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, 2).expect("split should succeed");

    let channel_id = ChannelId(1);
    let committed_share = shares.get(&channel_id).expect("missing share");
    let shared_key = SharedKey::new([42u8; 32]);

    let envelope = produce_store_share_request_message(
        channel_id,
        version,
        secret_id,
        committed_share,
        0,
        String::new(),
        &shared_key,
        &[],
    )
    .expect("helper-bound produce")
    .envelope;

    let extracted =
        extract_store_share_request(&envelope, &shared_key).expect("helper-bound extract");

    // Helpers know nothing about replicas. `SHARE_ALGORITHM_VSS` is
    // helper-bound, so the writer identity is unconditionally absent —
    // there is no argument by which a caller could set it.
    assert_eq!(
        extracted.request.share_algorithm,
        crate::primitives::sharing::request::SHARE_ALGORITHM_VSS
    );
    assert_eq!(extracted.request.replica_id, None);
}

/// A channel's subshares follow its own weight, not its position in the
/// slice: the input is sorted by channel ID before subshares are assigned, so
/// a weighted channel gets its extra subshares regardless of where it sorts
/// among the others. Channel 3 is the largest ID here, which exercises the
/// sort-ordering risk directly.
#[test]
fn test_split_gives_a_weighted_channel_its_subshares() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels: Vec<WeightedChannel> =
        vec![(ChannelId(3), 2), (ChannelId(1), 1), (ChannelId(2), 1)];
    let threshold = 3;
    let version = 1;

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, threshold).expect("split should succeed");

    for (channel_id, expected_subshares) in
        [(ChannelId(3), 2), (ChannelId(1), 1), (ChannelId(2), 1)]
    {
        let committed = shares.get(&channel_id).expect("missing share for channel");
        let inner = DeRecShare::decode(&committed.de_rec_share[..])
            .expect("failed to decode inner DeRecShare");
        assert_eq!(
            inner.subshares.len(),
            expected_subshares,
            "unexpected subshare count for channel {:?}",
            channel_id
        );
    }
}

#[test]
fn test_split_rejects_a_zero_weight() {
    let channels: Vec<WeightedChannel> =
        vec![(ChannelId(1), 0), (ChannelId(2), 1), (ChannelId(3), 1)];

    let result = split(&channels, 1, 1, b"secret-data", 2);

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::InvalidWeight {
            channel_id: 1,
            weight: 0
        }))
    ));
}

#[test]
fn test_split_rejects_a_weight_at_the_threshold() {
    let channels: Vec<WeightedChannel> =
        vec![(ChannelId(1), 3), (ChannelId(2), 1), (ChannelId(3), 1)];

    let result = split(&channels, 1, 1, b"secret-data", 3);

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::InvalidWeight {
            channel_id: 1,
            weight: 3
        }))
    ));
}

/// Weights are checked in ascending channel-ID order, so the reported
/// offender does not depend on the order the slice is given in.
#[test]
fn test_split_reports_the_lowest_invalid_weight_first() {
    let channels: Vec<WeightedChannel> =
        vec![(ChannelId(5), 0), (ChannelId(2), 9), (ChannelId(3), 1)];

    let result = split(&channels, 1, 1, b"secret-data", 3);

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::InvalidWeight {
            channel_id: 2,
            weight: 9
        }))
    ));
}

/// A channel ID listed twice is a duplicate even when the two entries carry
/// different weights.
#[test]
fn test_split_rejects_a_duplicate_channel_with_different_weights() {
    let channels: Vec<WeightedChannel> =
        vec![(ChannelId(1), 1), (ChannelId(2), 1), (ChannelId(1), 2)];

    let result = split(&channels, 1, 1, b"secret-data", 3);

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::DuplicateChannelId(1)))
    ));
}

/// Threshold validity is judged against the total subshare count (the sum of
/// weights), not the channel count: two channels can satisfy a threshold of 3
/// once one of them is weighted.
#[test]
fn test_split_threshold_counts_subshares() {
    let secret_id: u64 = 1;
    let secret_data = b"secret-data";
    let threshold = 3;
    let version = 1;

    let weighted: Vec<WeightedChannel> = vec![(ChannelId(1), 2), (ChannelId(2), 1)];
    let result = split(&weighted, secret_id, version, secret_data, threshold);
    assert!(result.is_ok(), "2 + 1 subshares should satisfy threshold 3");

    let unweighted = make_channel_ids(&[1, 2]);
    let result = split(&unweighted, secret_id, version, secret_data, threshold);
    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::InvalidThreshold {
            threshold: 3,
            channels: 2,
            subshares: 2
        }))
    ));
}

/// A weighted channel raises the subshare total but can still fall short of
/// the threshold; the error must report the subshare total actually reached,
/// not the channel count.
#[test]
fn test_split_invalid_threshold_reports_subshares_not_channel_count() {
    let channels: Vec<WeightedChannel> = vec![(ChannelId(1), 2), (ChannelId(2), 1)];

    let result = split(&channels, 1, 1, b"secret-data", 4);

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::InvalidThreshold {
            threshold: 4,
            channels: 2,
            subshares: 3
        }))
    ));
}

/// Every channel at weight 1 is the unweighted case: each channel gets
/// exactly one subshare.
#[test]
fn test_split_without_weights_is_unchanged() {
    let secret_id: u64 = 1;
    let secret_data = b"super_secret_value";
    let channels = make_channel_ids(&[1, 2, 3]);
    let threshold = 2;
    let version = 1;

    let SplitResult { shares } =
        split(&channels, secret_id, version, secret_data, threshold).expect("split should succeed");

    for (channel_id, _) in &channels {
        let committed = shares.get(channel_id).expect("missing share for channel");
        let inner = DeRecShare::decode(&committed.de_rec_share[..])
            .expect("failed to decode inner DeRecShare");
        assert_eq!(
            inner.subshares.len(),
            1,
            "every channel should hold exactly one subshare without weights"
        );
    }
}
