use super::*;
use crate::protocol::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecUserSecretStore,
};
use crate::protocol::types::{
    ChannelQuery, ChannelRecord, ChannelStatus, HelperInfo, ReplicaInfo, ReplicaRole, Replicas,
    Secret, SecretKind, SecretValue, Share, UserSecret, UserSecrets,
};
use crate::protocol::{DeRecFlow, DeRecProtocol, DeRecProtocolBuilder, NotRestoredReason};
use derec_proto::{Protocol, SenderKind, TransportProtocol};
use std::collections::HashMap;

use crate::Error;
use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::protocol::tests::{
    FailingTransport, InMemChannelStore, InMemPersistedStateStore, InMemSecretStore,
    InMemShareStore, InMemStateStore, InMemUserSecretStore, NoopTransport, RecordingTransport,
    StoreRig, run_async,
};
use crate::protocol::{StateItem, StateKey};
use crate::transport;
use crate::types::{ReplicaId, SharedKey};
use derec_proto::{DeRecResult, MessageBody, StatusEnum, UnpairResponseMessage};
use flate2::Compression;
use flate2::write::GzEncoder;
use prost::Message as _;

type TestProto = DeRecProtocol<
    InMemChannelStore,
    InMemShareStore,
    InMemSecretStore,
    InMemUserSecretStore,
    InMemStateStore,
    NoopTransport,
>;

/// Test bundle — keeps clone handles to every store so the test
/// can both pre-seed before construction AND inspect after the
/// restore call.
struct TestRig {
    protocol: TestProto,
    channel_store: InMemChannelStore,
    secret_store: InMemSecretStore,
    share_store: InMemShareStore,
    user_secret_store: InMemUserSecretStore,
}

fn build_rig(secret_id: u64) -> TestRig {
    build_rig_with_ack(secret_id, UnpairAck::Required)
}

fn build_rig_with_ack(secret_id: u64, unpair_ack: UnpairAck) -> TestRig {
    let rig = StoreRig::new();
    let protocol = DeRecProtocolBuilder::new(secret_id)
        .with_unpair_ack(unpair_ack)
        .with_channel_store(rig.channels.clone())
        .with_share_store(rig.shares.clone())
        .with_secret_store(rig.secrets.clone())
        .with_user_secret_store(rig.user_secrets.clone())
        .with_transport(NoopTransport)
        .with_state_store(InMemStateStore)
        .with_own_transports(["https://owner.example.com"])
        .with_threshold(2)
        .build()
        .expect("test rig builds");
    TestRig {
        protocol,
        channel_store: rig.channels,
        secret_store: rig.secrets,
        share_store: rig.shares,
        user_secret_store: rig.user_secrets,
    }
}

fn fixture_secret() -> Secret {
    Secret {
        helpers: vec![
            HelperInfo {
                channel_id: 11,
                transports: vec![TransportProtocol {
                    uri: "https://helper-a.example".to_owned(),
                    protocol: Protocol::Https as i32,
                }],
                shared_key: vec![0xAA; 32],
                communication_info: HashMap::from([("name".to_owned(), "HelperA".to_owned())]),
                weight: 1,
                key_epoch: 0,
            },
            HelperInfo {
                channel_id: 12,
                transports: vec![TransportProtocol {
                    uri: "https://helper-b.example".to_owned(),
                    protocol: Protocol::Https as i32,
                }],
                shared_key: vec![0xBB; 32],
                communication_info: HashMap::new(),
                weight: 1,
                key_epoch: 0,
            },
        ],
        secrets: vec![
            UserSecret {
                id: vec![0x01],
                name: "wallet".to_owned(),
                data: b"correct horse battery staple".to_vec(),
            },
            UserSecret {
                id: vec![0x02],
                name: "api token".to_owned(),
                data: b"hunter2".to_vec(),
            },
        ],
        replicas: Some(Replicas {
            channel_id: 21,
            members: vec![
                ReplicaInfo {
                    replica_id: 0xBEEF,
                    transports: vec![TransportProtocol {
                        uri: "https://owner.example".to_owned(),
                        protocol: Protocol::Https as i32,
                    }],
                    role: ReplicaRole::Source as i32,
                    communication_info: HashMap::new(),
                },
                ReplicaInfo {
                    replica_id: 0xCAFE,
                    transports: vec![TransportProtocol {
                        uri: "https://replica.example".to_owned(),
                        protocol: Protocol::Https as i32,
                    }],
                    role: ReplicaRole::Destination as i32,
                    communication_info: HashMap::new(),
                },
            ],
            shared_key: vec![0xCC; 32],
            key_epoch: 0,
        }),
        threshold: None,
    }
}

// ---------------- Happy path ----------------

/// Each Helper's channel is written with the roster's weight, so the next
/// publish gives it the same number of subshares. A protobuf-default `0`
/// is a roster written before weights existed and reads as `1`.
#[test]
fn restore_writes_each_roster_weight_into_the_helper_channel() {
    run_async(async {
        let secret_id: u64 = 0xDE_2ED;
        let mut rig = build_rig(secret_id);
        let mut secret = fixture_secret();
        secret.helpers[0].weight = 2;
        secret.helpers[1].weight = 0;

        rig.protocol
            .restore(&secret, 7, 7, &[])
            .await
            .expect("restore succeeds");

        for (hid, expected) in [(11_u64, 2_u32), (12, 1)] {
            let ch = rig
                .channel_store
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(hid),
                    },
                )
                .await
                .unwrap()
                .and_then(|r| r.as_helper().cloned())
                .expect("helper channel persisted");
            assert_eq!(ch.weight, expected, "helper {hid}");
        }
    });
}

/// A helper refuses a version older than the newest it stores, so the
/// snapshot of an older recovered version is committed at the newest
/// version the helpers reported: the next publish numbers above it.
#[test]
fn restore_commits_the_snapshot_at_the_newest_version() {
    run_async(async {
        let secret_id: u64 = 0xDE_2F0;
        let mut rig = build_rig(secret_id);

        rig.protocol
            .restore(&fixture_secret(), 7, 12, &[])
            .await
            .expect("restore succeeds");

        let snapshot = rig
            .user_secret_store
            .load_latest(secret_id)
            .await
            .unwrap()
            .expect("snapshot must exist");
        assert_eq!(snapshot.version, 12);
        assert_eq!(snapshot.secrets[0].name, "wallet");
    });
}

#[test]
fn restore_refuses_a_newest_version_below_the_recovered_one() {
    run_async(async {
        let secret_id: u64 = 0xDE_2F1;
        let mut rig = build_rig(secret_id);

        let err = rig
            .protocol
            .restore(&fixture_secret(), 7, 6, &[])
            .await
            .expect_err("a newest version below the recovered one is refused");

        assert!(
            matches!(err, Error::InvalidInput(_)),
            "expected InvalidInput, got {err:?}"
        );
        assert!(
            rig.user_secret_store
                .load_latest(secret_id)
                .await
                .unwrap()
                .is_none(),
            "nothing is committed"
        );
    });
}

#[test]
fn restore_happy_path_persists_canonical_state() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);

        rig.protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .expect("happy path must succeed");

        // Helper channels: status=Paired, role=Owner, no replica_id.
        for hid in [11_u64, 12] {
            let ch = rig
                .channel_store
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(hid),
                    },
                )
                .await
                .unwrap()
                .expect("helper channel must be persisted");
            let ChannelRecord::Helper(ch) = ch else {
                panic!("a helper query must never return a replica record");
            };
            assert_eq!(ch.status, ChannelStatus::Paired);
            assert_eq!(ch.peer_role, SenderKind::Helper);
            let sk = rig
                .secret_store
                .load(secret_id, ChannelId(hid), SecretKind::SharedKey)
                .await
                .unwrap()
                .expect("helper SharedKey must be persisted");
            assert!(matches!(sk, SecretValue::SharedKey(_)));
            // No tracking share. A fabricated one would hash to
            // something no Helper can produce, so verification would
            // report the Helper's data as corrupt rather than reporting
            // that this device has nothing to check against.
            let shares = rig
                .share_store
                .load(secret_id, ChannelId(hid), &[])
                .await
                .unwrap();
            assert!(
                shares.is_empty(),
                "restore must not invent tracking shares; got {shares:?}"
            );
        }

        // User-secret snapshot at recovered version.
        let snapshot = rig
            .user_secret_store
            .load_latest(secret_id)
            .await
            .unwrap()
            .expect("snapshot must exist");
        assert_eq!(snapshot.version, 7);
        assert_eq!(snapshot.secrets.len(), 2);
        assert_eq!(snapshot.secrets[0].name, "wallet");
        assert_eq!(snapshot.secrets[0].data, b"correct horse battery staple");
        assert_eq!(snapshot.secrets[1].name, "api token");

        // The device does not take the source's identity. The roster
        // names its source, but adopting that id is a takeover — a
        // separate decision with its own convergence rules — so a device
        // built without a replica_id still has none after restore.
        assert_eq!(
            rig.protocol.replica_id, None,
            "restore must not adopt the roster source's replica_id"
        );
    });
}

// ---------------- Endpoint rehydration ----------------

/// The roster stores a bare `transport_uri` and no protocol discriminant,
/// so restore has to derive one. Pairing it with a fixed `Https` made every
/// gRPC-paired peer come back as `{grpcs://…, Https}` — a combination
/// `TransportProtocol::validate` rejects outright, which breaks the first
/// send after every recovery.
#[test]
fn a_grpc_peer_is_rehydrated_as_grpc() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);

        let mut secret = fixture_secret();
        secret.helpers[0].transports = vec![TransportProtocol {
            uri: "grpcs://helper-a.example:443".to_owned(),
            protocol: Protocol::Grpc as i32,
        }];

        rig.protocol
            .restore(&secret, 7, 7, &[])
            .await
            .expect("a grpc roster must restore");

        let helper = rig
            .channel_store
            .load(
                secret_id,
                ChannelQuery::Helper {
                    channel_id: ChannelId(11),
                },
            )
            .await
            .unwrap()
            .expect("helper channel must be persisted");
        let ChannelRecord::Helper(helper) = helper else {
            panic!("a helper query must never return a replica record");
        };
        assert_eq!(helper.transports[0].uri, "grpcs://helper-a.example:443");
        assert_eq!(
            helper.transports[0].protocol,
            Protocol::Grpc as i32,
            "a grpcs:// helper must come back as Grpc, not the historical \
             hardcoded Https"
        );
        for endpoint in &helper.transports {
            transport::TransportProtocol::try_from(endpoint)
                .expect("every rehydrated endpoint must be self-consistent");
        }

        // The https:// entries in the same roster are unaffected — the
        // discriminant follows each URI, not the roster as a whole.
        let other = rig
            .channel_store
            .load(
                secret_id,
                ChannelQuery::Helper {
                    channel_id: ChannelId(12),
                },
            )
            .await
            .unwrap()
            .expect("helper channel must be persisted");
        let ChannelRecord::Helper(other) = other else {
            panic!("a helper query must never return a replica record");
        };
        assert_eq!(other.transports[0].protocol, Protocol::Https as i32);
    });
}

fn not_restored(events: &[DeRecEvent]) -> Vec<(ChannelId, Option<u64>, NotRestoredReason)> {
    events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::PeerNotRestored {
                channel_id,
                replica_id,
                reason,
            } => Some((*channel_id, *replica_id, *reason)),
            _ => None,
        })
        .collect()
}

async fn helper_record(rig: &TestRig, secret_id: u64, id: u64) -> Option<ChannelRecord> {
    rig.channel_store
        .load(
            secret_id,
            ChannelQuery::Helper {
                channel_id: ChannelId(id),
            },
        )
        .await
        .unwrap()
}

async fn member_record(
    rig: &TestRig,
    secret_id: u64,
    channel_id: u64,
    replica_id: u64,
) -> Option<ChannelRecord> {
    rig.channel_store
        .load(
            secret_id,
            ChannelQuery::Replica {
                channel_id: ChannelId(channel_id),
                replica_id: ReplicaId(replica_id),
            },
        )
        .await
        .unwrap()
}

async fn shared_key_at(rig: &TestRig, secret_id: u64, id: u64) -> Option<SecretValue> {
    rig.secret_store
        .load(secret_id, ChannelId(id), SecretKind::SharedKey)
        .await
        .unwrap()
}

// ---------------- Peers without an endpoint ----------------

/// A helper that names no endpoint would be a channel with nothing to
/// send to. It is skipped and reported; the reachable helper and the
/// snapshot are restored exactly as they would be without it.
#[test]
fn a_helper_without_an_endpoint_is_skipped_and_reported() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);

        let mut secret = Secret {
            replicas: None,
            ..fixture_secret()
        };
        secret.helpers[1].transports = Vec::new();

        let events = rig
            .protocol
            .restore(&secret, 7, 7, &[])
            .await
            .expect("an unreachable helper must not block the restore");

        assert_eq!(
            not_restored(&events),
            vec![(ChannelId(12), None, NotRestoredReason::NoTransports)],
            "exactly the unreachable helper is reported, got {events:?}"
        );

        assert!(helper_record(&rig, secret_id, 11).await.is_some());
        assert!(shared_key_at(&rig, secret_id, 11).await.is_some());
        assert!(
            helper_record(&rig, secret_id, 12).await.is_none(),
            "no channel is written for a helper with no endpoint"
        );
        assert!(
            shared_key_at(&rig, secret_id, 12).await.is_none(),
            "no key is written for a helper that has no channel"
        );

        let snapshot = rig
            .user_secret_store
            .load_latest(secret_id)
            .await
            .unwrap()
            .expect("the snapshot is committed");
        assert_eq!(snapshot.version, 7);
        assert_eq!(snapshot.secrets.len(), 2);
    });
}

/// Every member is dropped, reachable or not: a member with no endpoint is
/// reported as dropped with the group, not as unreachable.
#[test]
fn a_member_without_transports_is_reported_as_dropped() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);

        let mut secret = fixture_secret();
        secret.replicas.as_mut().unwrap().members[1].transports = Vec::new();

        let events = rig
            .protocol
            .restore(&secret, 7, 7, &[])
            .await
            .expect("restores");

        assert_eq!(
            not_restored(&events),
            vec![
                (
                    ChannelId(21),
                    Some(0xBEEF),
                    NotRestoredReason::ReplicaGroupDropped
                ),
                (
                    ChannelId(21),
                    Some(0xCAFE),
                    NotRestoredReason::ReplicaGroupDropped
                ),
            ],
        );
    });
}

/// Restore is for an owner that lost its devices, so the recovered group
/// is not carried forward: no member, no group key, one report per member
/// in roster order. The owner pairs again with any device it still has.
#[test]
fn restore_drops_the_replica_group() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);

        let events = rig
            .protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .expect("restores");

        assert_eq!(
            not_restored(&events),
            vec![
                (
                    ChannelId(21),
                    Some(0xBEEF),
                    NotRestoredReason::ReplicaGroupDropped
                ),
                (
                    ChannelId(21),
                    Some(0xCAFE),
                    NotRestoredReason::ReplicaGroupDropped
                ),
            ],
        );
        assert!(member_record(&rig, secret_id, 21, 0xBEEF).await.is_none());
        assert!(member_record(&rig, secret_id, 21, 0xCAFE).await.is_none());
        assert!(shared_key_at(&rig, secret_id, 21).await.is_none());
        assert!(helper_record(&rig, secret_id, 11).await.is_some());
        assert!(helper_record(&rig, secret_id, 12).await.is_some());
    });
}

/// With the group dropped, a restored device publishes as a lone owner,
/// with no replica identity to configure first.
#[test]
fn a_restored_device_with_a_dropped_group_can_publish() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);
        let secret = fixture_secret();

        rig.protocol
            .restore(&secret, 4, 4, &[])
            .await
            .expect("restores");

        let events = rig
            .protocol
            .start(DeRecFlow::ProtectSecret {
                secrets: secret.secrets.clone(),
                description: None,
                weights: HashMap::new(),
                threshold: None,
            })
            .await
            .expect("a restored owner publishes without a replica identity");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DeRecEvent::ProtectSecretStarted { version: 5, .. })),
            "got {events:?}"
        );
    });
}

/// With no reachable member there is no group to address, so neither the
/// group key nor any member record is written.
#[test]
fn a_group_with_no_reachable_member_writes_nothing() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);

        let mut secret = fixture_secret();
        for m in &mut secret.replicas.as_mut().unwrap().members {
            m.transports = Vec::new();
        }

        let events = rig
            .protocol
            .restore(&secret, 7, 7, &[])
            .await
            .expect("restores");

        assert_eq!(
            not_restored(&events),
            vec![
                (
                    ChannelId(21),
                    Some(0xBEEF),
                    NotRestoredReason::ReplicaGroupDropped
                ),
                (
                    ChannelId(21),
                    Some(0xCAFE),
                    NotRestoredReason::ReplicaGroupDropped
                ),
            ],
        );
        assert!(member_record(&rig, secret_id, 21, 0xBEEF).await.is_none());
        assert!(member_record(&rig, secret_id, 21, 0xCAFE).await.is_none());
        assert!(
            shared_key_at(&rig, secret_id, 21).await.is_none(),
            "a group key with no member to use it is not written"
        );
        assert!(helper_record(&rig, secret_id, 11).await.is_some());
    });
}

/// Restore claims only the ids it writes. A channel already at a skipped
/// helper's id is not overwritten, so it is no conflict; and it sits at a
/// roster id, so it is no recovery channel either — the wipe must not
/// send an unpair to a peer that holds a share.
#[test]
fn a_channel_at_a_skipped_helpers_id_is_neither_a_conflict_nor_wiped() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);
        rig.channel_store.helper_rows.lock().unwrap().insert(
            (secret_id, 12),
            HelperChannel {
                channel_id: ChannelId(12),
                transports: vec![TransportProtocol {
                    uri: "https://repaired.example".to_owned(),
                    protocol: 0,
                }],
                communication_info: HashMap::new(),
                status: ChannelStatus::Paired,
                created_at: 1,
                peer_role: SenderKind::Helper,
                weight: 1,
            },
        );
        rig.secret_store.data.lock().unwrap().insert(
            (secret_id, 12, SecretKind::SharedKey as u8),
            SecretValue::SharedKey(SharedKey::new([0x77; 32])),
        );

        let mut secret = Secret {
            replicas: None,
            ..fixture_secret()
        };
        secret.helpers[1].transports = Vec::new();

        let events = rig
            .protocol
            .restore(&secret, 7, 7, &[])
            .await
            .expect("a skipped helper's id must not be reported as a conflict");

        assert_eq!(
            not_restored(&events),
            vec![(ChannelId(12), None, NotRestoredReason::NoTransports)]
        );
        assert!(
            !events.iter().any(|e| matches!(
                e,
                DeRecEvent::Unpaired { channel_id, .. }
                    | DeRecEvent::UnpairStarted { channel_id, .. }
                    | DeRecEvent::UnpairFailed { channel_id, .. }
                    if *channel_id == ChannelId(12)
            )),
            "the channel at a roster id is not a recovery channel, got {events:?}"
        );
        let Some(ChannelRecord::Helper(kept)) = helper_record(&rig, secret_id, 12).await else {
            panic!("the pre-existing channel must survive");
        };
        assert_eq!(kept.transports[0].uri, "https://repaired.example");
        assert!(
            matches!(
                shared_key_at(&rig, secret_id, 12).await,
                Some(SecretValue::SharedKey(k)) if k == crate::types::SharedKey::new([0x77; 32])
            ),
            "its key is left as it was"
        );
    });
}

/// Skipping is about reachability, not validity: a skipped entry that
/// makes the `Secret` inconsistent still refuses the whole restore.
#[test]
fn a_skipped_helper_with_a_malformed_key_still_refuses_the_restore() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);

        let mut secret = fixture_secret();
        secret.helpers[1].transports = Vec::new();
        secret.helpers[1].shared_key = vec![0xBB; 31];

        let err = rig.protocol.restore(&secret, 7, 7, &[]).await.unwrap_err();
        assert!(
            matches!(err, Error::Restore(RestoreError::Invariant(_))),
            "got {err:?}"
        );
        assert!(
            helper_record(&rig, secret_id, 11).await.is_none(),
            "an invariant failure is reported before any write"
        );
        assert!(
            rig.user_secret_store
                .load_latest(secret_id)
                .await
                .unwrap()
                .is_none()
        );
    });
}

/// A malformed key on a later entry used to be found mid-write, after the
/// earlier helpers were already persisted. It is now part of the plan.
#[test]
fn a_malformed_helper_key_is_refused_before_any_write() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);

        let mut secret = fixture_secret();
        secret.helpers[1].shared_key = vec![0xBB; 31];

        let err = rig.protocol.restore(&secret, 7, 7, &[]).await.unwrap_err();
        assert!(matches!(err, Error::Restore(RestoreError::Invariant(_))));
        assert!(helper_record(&rig, secret_id, 11).await.is_none());
        assert!(shared_key_at(&rig, secret_id, 11).await.is_none());
    });
}

/// End to end from the bytes a pre-0.0.3 owner protected: a v2 roster
/// whose helper URI names a scheme this library does not serve decodes
/// with no endpoint, and restore skips that helper instead of refusing
/// the whole secret.
#[test]
fn a_legacy_roster_with_an_unserved_scheme_restores_the_rest() {
    use std::io::Write as _;
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);

        let json = r#"{
            "helpers": [
                {
                    "channel_id": "11",
                    "transport_uri": "ws://helper-a.example",
                    "shared_key": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="
                },
                {
                    "channel_id": "12",
                    "transport_uri": "https://helper-b.example",
                    "shared_key": "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s="
                }
            ],
            "secrets": [{"id": "AQ==", "name": "wallet", "data": "c2VjcmV0"}],
            "replicas": {
                "channel_id": "21",
                "shared_key": "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=",
                "members": [{
                    "replica_id": "48879",
                    "transport_uri": "https://owner.example",
                    "role": "Source"
                }]
            }
        }"#;
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(json.as_bytes()).unwrap();
        let mut bytes = vec![2_u8];
        bytes.extend(gz.finish().unwrap());

        let secret = Secret::decode(&bytes).expect("a v2 secret still decodes");
        assert!(secret.helpers[0].transports.is_empty());

        let events = rig
            .protocol
            .restore(&secret, 3, 3, &[])
            .await
            .expect("one unusable URI must not refuse the whole secret");

        assert_eq!(
            not_restored(&events),
            vec![
                (ChannelId(11), None, NotRestoredReason::NoTransports),
                (
                    ChannelId(21),
                    Some(0xBEEF),
                    NotRestoredReason::ReplicaGroupDropped
                ),
            ]
        );
        assert!(helper_record(&rig, secret_id, 11).await.is_none());
        assert!(helper_record(&rig, secret_id, 12).await.is_some());
        let snapshot = rig
            .user_secret_store
            .load_latest(secret_id)
            .await
            .unwrap()
            .expect("the snapshot is committed");
        assert_eq!(snapshot.version, 3);
        assert_eq!(snapshot.secrets[0].data, b"secret");
    });
}

// ---------------- Recovery-channel wipe ----------------

/// Seeds two recovery channels at ids that don't collide with any
/// canonical helper or replica id from `fixture_secret`. Each needs a
/// SharedKey in `secret_store` so the unpair handler can build the
/// encrypted request envelope.
fn seed_recovery_channels(rig: &TestRig, secret_id: u64) {
    seed_recovery_channels_into(&rig.channel_store, &rig.secret_store, secret_id);
}

fn seed_recovery_channels_into(
    channels: &InMemChannelStore,
    secrets: &InMemSecretStore,
    secret_id: u64,
) {
    for rcid in RECOVERY_IDS {
        channels.helper_rows.lock().unwrap().insert(
            (secret_id, rcid),
            HelperChannel {
                channel_id: ChannelId(rcid),
                transports: vec![TransportProtocol {
                    uri: format!("https://recovery-{rcid}.example"),
                    protocol: 0,
                }],
                communication_info: HashMap::new(),
                status: ChannelStatus::Paired,
                created_at: 1,
                peer_role: SenderKind::Helper,
                weight: 1,
            },
        );
        secrets.data.lock().unwrap().insert(
            (secret_id, rcid, SecretKind::SharedKey as u8),
            SecretValue::SharedKey(SharedKey::new([0x77; 32])),
        );
    }
}

const RECOVERY_IDS: [u64; 2] = [99, 100];

/// Under `UnpairAck::Required` a recovery channel waits for its helper's
/// answer like any other unpair: it is `Unpairing`, keeps its key so the
/// answer can be read, and no `Unpaired` is reported yet.
#[test]
fn restore_leaves_recovery_channels_unpairing_until_answered() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);
        seed_recovery_channels(&rig, secret_id);

        let events = rig
            .protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .expect("restore must succeed despite recovery channels");

        for rcid in RECOVERY_IDS {
            let channel = rig
                .channel_store
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(rcid),
                    },
                )
                .await
                .unwrap()
                .and_then(|record| record.as_helper().cloned())
                .expect("the recovery channel stays until its helper answers");
            assert_eq!(channel.status, ChannelStatus::Unpairing);
            assert!(
                rig.secret_store
                    .load(secret_id, ChannelId(rcid), SecretKind::SharedKey)
                    .await
                    .unwrap()
                    .is_some(),
                "the key stays, so the helper's answer can be decrypted"
            );
            assert!(events.iter().any(|e| matches!(
                e,
                DeRecEvent::UnpairStarted { channel_id, .. } if *channel_id == ChannelId(rcid)
            )));
        }
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, DeRecEvent::Unpaired { .. })),
            "no recovery channel is unpaired before its helper answers, got {events:?}"
        );
    });
}

type AnsweringProto = DeRecProtocol<
    InMemChannelStore,
    InMemShareStore,
    InMemSecretStore,
    InMemUserSecretStore,
    InMemPersistedStateStore,
    RecordingTransport,
>;

/// A restore rig whose pending unpairs persist, so a helper's answer can be
/// processed against them.
struct AnsweringRig {
    protocol: AnsweringProto,
    channel_store: InMemChannelStore,
    secret_store: InMemSecretStore,
    state: InMemPersistedStateStore,
}

fn build_answering_rig(secret_id: u64) -> AnsweringRig {
    let rig = StoreRig::new();
    let state = InMemPersistedStateStore::default();
    let protocol = DeRecProtocolBuilder::new(secret_id)
        .with_unpair_ack(UnpairAck::Required)
        .with_channel_store(rig.channels.clone())
        .with_share_store(rig.shares.clone())
        .with_secret_store(rig.secrets.clone())
        .with_user_secret_store(rig.user_secrets.clone())
        .with_transport(RecordingTransport::default())
        .with_state_store(state.clone())
        .with_own_transports(["https://owner.example.com"])
        .with_threshold(2)
        .build()
        .expect("test rig builds");
    seed_recovery_channels_into(&rig.channels, &rig.secrets, secret_id);
    AnsweringRig {
        protocol,
        channel_store: rig.channels,
        secret_store: rig.secrets,
        state,
    }
}

/// A recovery helper's answer to the unpair request restore sent on `rcid`.
fn recovery_unpair_answer(rcid: u64, status: StatusEnum) -> Vec<u8> {
    let ts = current_timestamp();
    DeRecMessageBuilder::channel()
        .channel_id(ChannelId(rcid))
        .timestamp(ts)
        .message_body(MessageBody::UnpairResponse(UnpairResponseMessage {
            result: Some(DeRecResult {
                status: status as i32,
                memo: String::new(),
            }),
            timestamp: Some(ts),
            channel_id: rcid,
        }))
        .encrypt(&ChannelKey::new(0, SharedKey::new([0x77; 32])))
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec()
}

/// Every recovery channel's pending entry is saved in one state-store write
/// and the channels are marked `Unpairing` in one channel-store write; each
/// entry says the channel goes whatever the helper answers.
#[test]
fn restore_marks_every_recovery_channel_unpairing_in_one_write() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_answering_rig(secret_id);

        rig.protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .expect("restore succeeds");

        assert_eq!(
            *rig.channel_store.save_calls.lock().unwrap(),
            0,
            "no channel is written on its own"
        );
        assert_eq!(
            *rig.channel_store.save_many_calls.lock().unwrap(),
            2,
            "one write restores the roster, one marks the recovery channels"
        );
        assert_eq!(
            (
                *rig.state.save_calls.lock().unwrap(),
                *rig.state.save_many_calls.lock().unwrap()
            ),
            (0, 1),
            "every pending entry is saved in one call"
        );
        for rcid in RECOVERY_IDS {
            let channel_id = ChannelId(rcid);
            assert_eq!(
                rig.channel_store
                    .helper_rows
                    .lock()
                    .unwrap()
                    .get(&(secret_id, rcid))
                    .map(|h| h.status),
                Some(ChannelStatus::Unpairing)
            );
            assert!(matches!(
                rig.state
                    .data
                    .lock()
                    .unwrap()
                    .get(&(secret_id, StateKey::PendingUnpair { channel_id })),
                Some(StateItem::PendingUnpair {
                    drop_on_rejection: true,
                    ..
                })
            ));
        }
    });
}

/// Pending entries that cannot be saved leave nothing to await: every
/// recovery channel is reported and dropped straight away, and none is left
/// `Unpairing`.
#[test]
fn unsaved_pending_entries_drop_every_recovery_channel_at_once() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_answering_rig(secret_id);
        *rig.state.fail_writes.lock().unwrap() = true;

        let events = rig
            .protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .expect("restore succeeds");

        for rcid in RECOVERY_IDS {
            let channel_id = ChannelId(rcid);
            let outcome: Vec<&DeRecEvent> = events
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        DeRecEvent::UnpairFailed { channel_id: c, .. }
                            | DeRecEvent::Unpaired { channel_id: c, .. }
                            if *c == channel_id
                    )
                })
                .collect();
            assert!(
                matches!(
                    outcome.as_slice(),
                    [DeRecEvent::UnpairFailed { .. }, DeRecEvent::Unpaired { .. }]
                ),
                "channel {rcid} is reported, then unpaired, got {events:?}"
            );
            assert!(
                !rig.channel_store
                    .helper_rows
                    .lock()
                    .unwrap()
                    .contains_key(&(secret_id, rcid))
            );
        }
        assert_eq!(*rig.state.save_many_calls.lock().unwrap(), 1);
    });
}

/// A helper refusing to unpair a recovery channel is reported, and the
/// channel is dropped all the same: restore's teardown never depends on the
/// answer.
#[test]
fn a_rejected_recovery_channel_unpair_still_drops_the_channel() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_answering_rig(secret_id);
        rig.protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .expect("restore succeeds");
        let rcid = RECOVERY_IDS[0];

        let events = rig
            .protocol
            .process(&recovery_unpair_answer(rcid, StatusEnum::Fail))
            .await
            .expect("processed");

        let channel_id = ChannelId(rcid);
        assert!(
            matches!(
                events.as_slice(),
                [
                    DeRecEvent::UnpairRejected { channel_id: rejected, .. },
                    DeRecEvent::Unpaired { channel_id: unpaired, acknowledged: false },
                ] if *rejected == channel_id && *unpaired == channel_id
            ),
            "the refusal is reported, then the channel is unpaired, got {events:?}"
        );
        assert!(
            !rig.channel_store
                .helper_rows
                .lock()
                .unwrap()
                .contains_key(&(secret_id, rcid))
        );
        assert!(
            rig.secret_store
                .load(secret_id, channel_id, SecretKind::SharedKey)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !rig.state
                .data
                .lock()
                .unwrap()
                .contains_key(&(secret_id, StateKey::PendingUnpair { channel_id }))
        );
    });
}

/// A helper accepting the unpair of a recovery channel completes it as any
/// acknowledged unpair does.
#[test]
fn an_accepted_recovery_channel_unpair_reports_unpaired() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_answering_rig(secret_id);
        rig.protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .expect("restore succeeds");
        let rcid = RECOVERY_IDS[1];

        let events = rig
            .protocol
            .process(&recovery_unpair_answer(rcid, StatusEnum::Ok))
            .await
            .expect("processed");

        assert!(
            matches!(
                events.as_slice(),
                [DeRecEvent::Unpaired { channel_id, acknowledged: true }] if *channel_id == ChannelId(rcid)
            ),
            "got {events:?}"
        );
        assert!(
            !rig.channel_store
                .helper_rows
                .lock()
                .unwrap()
                .contains_key(&(secret_id, rcid))
        );
    });
}

#[test]
fn restore_unpairs_pre_existing_recovery_channels() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig_with_ack(secret_id, UnpairAck::NotRequired);
        seed_recovery_channels(&rig, secret_id);

        rig.protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .expect("restore must succeed despite recovery channels");

        // Recovery channels and their SharedKeys are gone.
        for rcid in RECOVERY_IDS {
            assert!(
                rig.channel_store
                    .load(
                        secret_id,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(rcid),
                        },
                    )
                    .await
                    .unwrap()
                    .is_none(),
                "recovery channel {rcid} must be unpaired"
            );
            assert!(
                rig.secret_store
                    .load(secret_id, ChannelId(rcid), SecretKind::SharedKey)
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        // Canonical state is in place.
        assert!(
            rig.channel_store
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(11),
                    },
                )
                .await
                .unwrap()
                .is_some()
        );
    });
}

/// A channel on which this device is the Helper for another owner holds
/// that owner's share. It is no recovery channel: restore must leave it,
/// its key and the share untouched, whatever the unpair acknowledgement
/// mode, or the other owner silently loses a Helper it still counts.
#[test]
fn restore_leaves_channels_where_this_device_is_the_helper() {
    run_async(async {
        for unpair_ack in [UnpairAck::Required, UnpairAck::NotRequired] {
            const OWNER_CHANNEL: u64 = 101;
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig_with_ack(secret_id, unpair_ack);
            seed_recovery_channels(&rig, secret_id);
            rig.channel_store.helper_rows.lock().unwrap().insert(
                (secret_id, OWNER_CHANNEL),
                HelperChannel {
                    channel_id: ChannelId(OWNER_CHANNEL),
                    transports: vec![TransportProtocol {
                        uri: "https://other-owner.example".to_owned(),
                        protocol: 0,
                    }],
                    communication_info: HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: 1,
                    peer_role: SenderKind::Owner,
                    weight: 1,
                },
            );
            rig.secret_store.data.lock().unwrap().insert(
                (secret_id, OWNER_CHANNEL, SecretKind::SharedKey as u8),
                SecretValue::SharedKey(SharedKey::new([0x55; 32])),
            );
            rig.share_store
                .save(
                    secret_id,
                    ChannelId(OWNER_CHANNEL),
                    Share {
                        secret_id: 0x07E5,
                        version: 3,
                        bytes: vec![0xAB; 16],
                        subshares: None,
                        threshold: None,
                    },
                )
                .await
                .expect("seed the other owner's share");

            let events = rig
                .protocol
                .restore(&fixture_secret(), 7, 7, &[])
                .await
                .expect("restore succeeds");

            assert!(
                !events.iter().any(|e| match e {
                    DeRecEvent::UnpairStarted { channel_id, .. }
                    | DeRecEvent::Unpaired { channel_id, .. }
                    | DeRecEvent::UnpairFailed { channel_id, .. } =>
                        *channel_id == ChannelId(OWNER_CHANNEL),
                    _ => false,
                }),
                "{unpair_ack:?}: the other owner's channel is not unpaired, got {events:?}"
            );
            let channel = rig
                .channel_store
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(OWNER_CHANNEL),
                    },
                )
                .await
                .unwrap()
                .and_then(|record| record.as_helper().cloned())
                .expect("the other owner's channel stays");
            assert_eq!(channel.status, ChannelStatus::Paired);
            assert!(
                rig.secret_store
                    .load(secret_id, ChannelId(OWNER_CHANNEL), SecretKind::SharedKey)
                    .await
                    .unwrap()
                    .is_some(),
                "{unpair_ack:?}: its key stays"
            );
            assert_eq!(
                rig.share_store
                    .load(secret_id, ChannelId(OWNER_CHANNEL), &[3])
                    .await
                    .unwrap()
                    .len(),
                1,
                "{unpair_ack:?}: the share held for the other owner stays"
            );
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::UnpairStarted { channel_id, .. }
                        | DeRecEvent::Unpaired { channel_id, .. }
                        if *channel_id == ChannelId(RECOVERY_IDS[0])
                )),
                "{unpair_ack:?}: the recovery channels are still wiped"
            );
        }
    });
}

/// An old helper that has gone away is the *expected* condition
/// during recovery, so a failed teardown must not undo a committed
/// restore.
#[test]
fn restore_succeeds_when_recovery_channel_unpair_cannot_be_delivered() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let rig = StoreRig::new();
        let mut protocol = DeRecProtocolBuilder::new(secret_id)
            .with_channel_store(rig.channels.clone())
            .with_share_store(rig.shares.clone())
            .with_secret_store(rig.secrets.clone())
            .with_user_secret_store(rig.user_secrets.clone())
            .with_transport(FailingTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .build()
            .expect("test rig builds");

        rig.channels.helper_rows.lock().unwrap().insert(
            (secret_id, 99),
            HelperChannel {
                channel_id: ChannelId(99),
                transports: vec![TransportProtocol {
                    uri: "https://gone.example".to_owned(),
                    protocol: 0,
                }],
                communication_info: HashMap::new(),
                status: ChannelStatus::Paired,
                created_at: 1,
                peer_role: SenderKind::Helper,
                weight: 1,
            },
        );
        rig.secrets.data.lock().unwrap().insert(
            (secret_id, 99, SecretKind::SharedKey as u8),
            SecretValue::SharedKey(SharedKey::new([0x77; 32])),
        );

        let events = protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .expect("an unreachable peer must not fail the restore");

        assert!(
            events.iter().any(|e| matches!(
                e,
                DeRecEvent::UnpairFailed { channel_id, .. } if *channel_id == ChannelId(99)
            )),
            "the undeliverable teardown must be reported, got {events:?}"
        );
        assert!(
            events.iter().any(
                |e| matches!(e, DeRecEvent::Unpaired { channel_id, .. } if *channel_id == ChannelId(99))
            ),
            "local state is dropped regardless, so Unpaired still fires"
        );

        assert!(
            rig.channels
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(99),
                    },
                )
                .await
                .unwrap()
                .is_none(),
            "the ephemeral channel must not survive a failed send"
        );
        assert!(
            rig.user_secrets
                .load_latest(secret_id)
                .await
                .unwrap()
                .is_some(),
            "the recovered snapshot stays committed"
        );
        assert!(
            rig.channels
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(11),
                    },
                )
                .await
                .unwrap()
                .is_some(),
            "canonical helper channels stay in place"
        );
    });
}

// ---------------- Preconditions ----------------

/// Restore leaves the recovered version unverifiable, and one publish is
/// what buys verification back.
///
/// This is the sequence the restore docs point applications at, so it is
/// asserted rather than described: the snapshot committed at
/// `recovered_version` is what the next round derives `+ 1` from, and that
/// round writes tracking shares carrying the bytes it actually sent.
/// Without this, removing the fabricated share would look like a lost
/// capability instead of a relocated one.
#[test]
fn a_publish_after_restore_writes_real_tracking_shares() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);
        // Helpers only. A roster carrying a replica group cannot publish
        // until the application configures a `replica_id` the roster
        // names, which is a separate decision restore declines to make.
        let secret = Secret {
            replicas: None,
            ..fixture_secret()
        };

        rig.protocol
            .restore(&secret, 4, 4, &[])
            .await
            .expect("restore must succeed");

        let events = rig
            .protocol
            .start(DeRecFlow::ProtectSecret {
                secrets: secret.secrets.clone(),
                description: None,
                weights: HashMap::new(),
                threshold: None,
            })
            .await
            .expect("a restored owner must be able to publish again");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DeRecEvent::ProtectSecretStarted { version: 5, .. })),
            "the round after a restore at 4 must be 5; got {events:?}"
        );

        for hid in [11_u64, 12] {
            let rows = rig
                .share_store
                .load(secret_id, ChannelId(hid), &[])
                .await
                .unwrap();
            let versions: Vec<u32> = rows.iter().map(|r| r.version).collect();
            assert_eq!(
                versions,
                vec![5],
                "helper {hid} must hold exactly the published version, \
                 with nothing left over from the restore"
            );
            assert!(
                !rows[0].bytes.is_empty(),
                "helper {hid}'s tracking share must carry the committed \
                 bytes that were sent, or verification has nothing to hash"
            );
        }
    });
}

/// Seed a paired Helper channel the way a completed pairing leaves it.
async fn seed_paired_helper(rig: &mut TestRig, secret_id: u64, channel: u64) {
    rig.channel_store
        .save(
            secret_id,
            ChannelRecord::Helper(HelperChannel {
                channel_id: ChannelId(channel),
                transports: vec![TransportProtocol {
                    uri: format!("https://helper-{channel}.example"),
                    protocol: Protocol::Https as i32,
                }],
                communication_info: HashMap::new(),
                status: ChannelStatus::Paired,
                created_at: 0,
                peer_role: SenderKind::Helper,
                weight: 1,
            }),
        )
        .await
        .expect("seed helper");
    rig.secret_store
        .save(
            secret_id,
            ChannelId(channel),
            SecretValue::SharedKey(SharedKey::new([channel as u8; 32])),
        )
        .await
        .expect("seed key");
}

async fn publish_after_pairing(rig: &mut TestRig, channel: u64) {
    rig.protocol
        .maybe_auto_publish(
            &[DeRecEvent::PairingCompleted {
                channel_id: ChannelId(channel),
                pairing_channel_id: ChannelId(channel),
                kind: SenderKind::Owner,
                peer_communication_info: HashMap::new(),
            }],
            &std::collections::HashSet::new(),
        )
        .await
        .expect("the pairing publish runs");
}

async fn recorded_threshold(
    rig: &TestRig,
    secret_id: u64,
    channel: u64,
    version: u32,
) -> Option<u32> {
    rig.share_store
        .load(secret_id, ChannelId(channel), &[version])
        .await
        .unwrap()
        .first()
        .unwrap_or_else(|| panic!("no owner row for {channel} at v{version}"))
        .threshold
}

async fn stored_threshold(rig: &TestRig, secret_id: u64) -> Option<u32> {
    rig.user_secret_store
        .load_latest(secret_id)
        .await
        .unwrap()
        .expect("snapshot committed")
        .threshold
}

/// The roster's threshold is put back, so a device whose builder says 2
/// keeps splitting at the 3 the secret was shared under, including in
/// the publishes the library starts itself. An explicit threshold then
/// replaces it.
#[test]
fn restore_puts_the_rosters_threshold_back() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EE;
        let mut rig = build_rig(secret_id);
        let secret = Secret {
            replicas: None,
            threshold: Some(3),
            ..fixture_secret()
        };

        rig.protocol
            .restore(&secret, 4, 4, &[])
            .await
            .expect("restore succeeds");
        assert_eq!(stored_threshold(&rig, secret_id).await, Some(3));

        seed_paired_helper(&mut rig, secret_id, 13).await;
        publish_after_pairing(&mut rig, 13).await;
        for hid in [11, 12, 13] {
            assert_eq!(recorded_threshold(&rig, secret_id, hid, 5).await, Some(3));
        }

        seed_paired_helper(&mut rig, secret_id, 14).await;
        publish_after_pairing(&mut rig, 14).await;
        assert_eq!(recorded_threshold(&rig, secret_id, 14, 6).await, Some(3));

        rig.protocol
            .start(DeRecFlow::ProtectSecret {
                secrets: secret.secrets.clone(),
                description: None,
                weights: HashMap::new(),
                threshold: Some(4),
            })
            .await
            .expect("an explicit threshold publishes");
        for hid in [11, 12, 13, 14] {
            assert_eq!(recorded_threshold(&rig, secret_id, hid, 7).await, Some(4));
        }
        assert_eq!(stored_threshold(&rig, secret_id).await, Some(4));
    });
}

/// A roster that records no threshold restores none, and the builder's
/// threshold applies to the next publish.
#[test]
fn a_roster_without_a_threshold_restores_none() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EF;
        let mut rig = build_rig(secret_id);
        let secret = Secret {
            replicas: None,
            ..fixture_secret()
        };

        rig.protocol
            .restore(&secret, 4, 4, &[])
            .await
            .expect("restore succeeds");
        assert_eq!(stored_threshold(&rig, secret_id).await, None);

        seed_paired_helper(&mut rig, secret_id, 13).await;
        publish_after_pairing(&mut rig, 13).await;
        assert_eq!(recorded_threshold(&rig, secret_id, 11, 5).await, Some(2));
    });
}

/// A threshold below 2 is an inconsistent `Secret`, refused before any
/// write.
#[test]
fn a_roster_threshold_below_two_is_refused_before_any_write() {
    run_async(async {
        let secret_id: u64 = 0xDE_2F0;
        let mut rig = build_rig(secret_id);
        let secret = Secret {
            replicas: None,
            threshold: Some(1),
            ..fixture_secret()
        };

        let err = rig
            .protocol
            .restore(&secret, 4, 4, &[])
            .await
            .expect_err("a threshold of 1 is malformed");
        assert!(
            matches!(err, Error::Restore(RestoreError::Invariant(_))),
            "got {err:?}"
        );
        assert!(
            rig.user_secret_store
                .load_latest(secret_id)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn restore_returns_already_restored_when_snapshot_exists() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);
        rig.user_secret_store.data.lock().unwrap().insert(
            secret_id,
            UserSecrets {
                version: 1,
                secrets: Vec::new(),
                description: None,
                author_replica_id: None,
                threshold: None,
            },
        );

        let err = rig
            .protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Restore(RestoreError::AlreadyRestored)));

        // No mutation: no canonical channel written.
        assert!(
            rig.channel_store
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(11),
                    },
                )
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn restore_returns_conflict_on_canonical_id_collision() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);
        // Pre-seed a channel sitting at canonical helper id 11.
        rig.channel_store.helper_rows.lock().unwrap().insert(
            (secret_id, 11),
            HelperChannel {
                channel_id: ChannelId(11),
                transports: vec![TransportProtocol {
                    uri: "https://collision.example".to_owned(),
                    protocol: 0,
                }],
                communication_info: HashMap::new(),
                status: ChannelStatus::Paired,
                created_at: 1,
                peer_role: SenderKind::Helper,
                weight: 1,
            },
        );

        let err = rig
            .protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .unwrap_err();
        let Error::Restore(RestoreError::Conflict(ids)) = err else {
            panic!("expected Restore(Conflict), got {err:?}");
        };
        assert_eq!(ids, vec![ChannelId(11)]);

        // No mutation beyond the pre-seed.
        assert!(
            rig.user_secret_store
                .load_latest(secret_id)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn restore_invariant_error_when_replicas_present_but_group_key_missing() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        let mut rig = build_rig(secret_id);
        let mut secret = fixture_secret();
        if let Some(group) = secret.replicas.as_mut() {
            group.shared_key = Vec::new();
        }

        let err = rig.protocol.restore(&secret, 7, 7, &[]).await.unwrap_err();
        assert!(matches!(err, Error::Restore(RestoreError::Invariant(_))));

        // No mutation.
        assert!(
            rig.channel_store
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(11),
                    },
                )
                .await
                .unwrap()
                .is_none()
        );
    });
}

// ---------------- Explicit replica_id corner ----------------

#[test]
fn restore_does_not_overwrite_explicit_replica_id() {
    run_async(async {
        let secret_id: u64 = 0xDE_2EC;
        // Builder configured WITH a replica id — restore must leave it
        // alone even though the recovered Secret names a source member.
        let mut protocol = DeRecProtocolBuilder::new(secret_id)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .with_replica_id(0x1234)
            .build()
            .expect("build");

        protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .unwrap();
        assert_eq!(protocol.replica_id, Some(0x1234));
    });
}

// ---------------- Kept recovery channels ----------------

fn keep(roster: u64, recovery: u64) -> KeepRecoveryChannel {
    KeepRecoveryChannel {
        roster_channel_id: ChannelId(roster),
        recovery_channel_id: ChannelId(recovery),
    }
}

fn helper_at(rig: &TestRig, secret_id: u64, channel_id: u64) -> Option<HelperChannel> {
    rig.channel_store
        .helper_rows
        .lock()
        .unwrap()
        .get(&(secret_id, channel_id))
        .cloned()
}

/// A kept recovery channel stands in for its roster helper: the old
/// channel, whose key every lost device still holds, is not written, and
/// the recovery channel keeps its own endpoint and key, takes the roster
/// weight, and survives the wipe. Helpers not listed restore as before.
#[test]
fn a_kept_recovery_channel_replaces_its_roster_helper() {
    run_async(async {
        let secret_id: u64 = 0xDE_2F0;
        let mut rig = build_rig_with_ack(secret_id, UnpairAck::NotRequired);
        seed_recovery_channels(&rig, secret_id);
        let mut secret = fixture_secret();
        secret.helpers[0].weight = 2;

        rig.protocol
            .restore(&secret, 7, 7, &[keep(11, 99)])
            .await
            .expect("restore succeeds");

        assert!(helper_at(&rig, secret_id, 11).is_none());
        assert!(
            rig.secret_store
                .load(secret_id, ChannelId(11), SecretKind::KeyRing)
                .await
                .unwrap()
                .is_none()
        );
        let kept = helper_at(&rig, secret_id, 99).expect("recovery channel kept");
        assert_eq!(kept.status, ChannelStatus::Paired);
        assert_eq!(kept.weight, 2);
        assert_eq!(kept.transports[0].uri, "https://recovery-99.example");
        assert!(
            rig.secret_store
                .load(secret_id, ChannelId(99), SecretKind::SharedKey)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            helper_at(&rig, secret_id, 100).is_none(),
            "unkept recovery channel wiped"
        );
        assert!(
            helper_at(&rig, secret_id, 12).is_some(),
            "unlisted helper restored"
        );
    });
}

/// Restore writes every channel record, roster helpers and kept recovery
/// channels alike, in one channel-store call, and every key ring in one
/// secret-store call.
#[test]
fn restore_writes_channels_and_key_rings_in_one_call_per_store() {
    run_async(async {
        let secret_id: u64 = 0xDE_2F2;
        let mut rig = build_rig_with_ack(secret_id, UnpairAck::NotRequired);
        seed_recovery_channels(&rig, secret_id);

        rig.protocol
            .restore(&fixture_secret(), 7, 7, &[keep(11, 99)])
            .await
            .expect("restore succeeds");

        assert_eq!(*rig.channel_store.save_calls.lock().unwrap(), 0);
        assert_eq!(*rig.channel_store.save_many_calls.lock().unwrap(), 1);
        assert_eq!(*rig.secret_store.save_calls.lock().unwrap(), 0);
        assert_eq!(*rig.secret_store.save_many_calls.lock().unwrap(), 1);
        assert!(helper_at(&rig, secret_id, 12).is_some());
        assert!(helper_at(&rig, secret_id, 99).is_some());
    });
}

/// The key rings are written before the channel records, so a restore
/// whose key-ring write fails leaves no channel record behind and a retry
/// succeeds instead of reporting a conflict.
#[test]
fn a_restore_whose_key_ring_write_fails_can_be_retried() {
    run_async(async {
        let secret_id: u64 = 0xDE_2F3;
        let mut rig = build_rig(secret_id);
        *rig.secret_store.fail_save_many.lock().unwrap() = true;

        assert!(
            rig.protocol
                .restore(&fixture_secret(), 7, 7, &[])
                .await
                .is_err()
        );
        assert!(helper_at(&rig, secret_id, 11).is_none());

        *rig.secret_store.fail_save_many.lock().unwrap() = false;
        rig.protocol
            .restore(&fixture_secret(), 7, 7, &[])
            .await
            .expect("retry succeeds");
        assert!(helper_at(&rig, secret_id, 11).is_some());
    });
}

/// Every kept pair is checked before any write: a refused restore is
/// exactly as if it had never been called.
#[test]
fn invalid_kept_channels_are_refused_before_any_write() {
    run_async(async {
        let cases: [(&str, Vec<KeepRecoveryChannel>, u64); 7] = [
            ("roster id names no roster helper", vec![keep(21, 99)], 21),
            ("recovery id is a roster id", vec![keep(11, 12)], 12),
            ("recovery id names no channel", vec![keep(11, 77)], 77),
            ("recovery channel still pending", vec![keep(11, 100)], 100),
            (
                "recovery channel has an owner peer",
                vec![keep(11, 101)],
                101,
            ),
            ("roster id repeated", vec![keep(11, 99), keep(11, 100)], 11),
            ("recovery id repeated", vec![keep(11, 99), keep(12, 99)], 99),
        ];
        for (case, kept, refused) in cases {
            let secret_id: u64 = 0xDE_2F1;
            let mut rig = build_rig(secret_id);
            seed_recovery_channels(&rig, secret_id);
            if refused == 100 {
                rig.channel_store
                    .helper_rows
                    .lock()
                    .unwrap()
                    .get_mut(&(secret_id, 100))
                    .unwrap()
                    .status = ChannelStatus::Pending;
            }
            if refused == 101 {
                let mut owner_peer = helper_at(&rig, secret_id, 99).unwrap();
                owner_peer.channel_id = ChannelId(101);
                owner_peer.peer_role = SenderKind::Owner;
                rig.channel_store
                    .helper_rows
                    .lock()
                    .unwrap()
                    .insert((secret_id, 101), owner_peer);
            }

            let outcome = rig.protocol.restore(&fixture_secret(), 7, 7, &kept).await;

            assert!(
                matches!(
                    outcome,
                    Err(Error::Restore(RestoreError::InvalidKeptChannel(id))) if id == ChannelId(refused)
                ),
                "{case}: got {outcome:?}"
            );
            assert!(
                helper_at(&rig, secret_id, 11).is_none(),
                "{case}: nothing written"
            );
            assert!(
                rig.user_secret_store
                    .load_latest(secret_id)
                    .await
                    .unwrap()
                    .is_none(),
                "{case}: no snapshot"
            );
        }
    });
}
