// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#[cfg(test)]
mod handshake_tests {
    use super::super::*;
    use crate::protocol::tests::LocalFixture;
    use crate::protocol::tests::StoreRig;

    fn entries_of(c: &CommunicationInfo) -> Vec<(String, String)> {
        c.communication_info_entries
            .iter()
            .filter_map(|e| match &e.value {
                Some(Value::StringValue(s)) => Some((e.key.clone(), s.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn build_omits_reserved_key_when_no_replica_id_to_inject() {
        let mut info = HashMap::new();
        info.insert("name".to_owned(), "Alice".to_owned());

        let built = build_communication_info(&info, None).expect("entries present");
        let pairs = entries_of(&built);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("name".to_owned(), "Alice".to_owned()));
    }

    #[test]
    fn build_injects_reserved_key_when_replica_id_supplied() {
        let mut info = HashMap::new();
        info.insert("name".to_owned(), "Alice".to_owned());

        let built = build_communication_info(&info, Some(0xDEAD_BEEFu64)).expect("entries present");
        let pairs = entries_of(&built);

        let replica_entry = pairs
            .iter()
            .find(|(k, _)| k == reserved_keys::DEREC_REPLICA_ID_KEY)
            .expect("derec.replica_id should be injected");
        assert_eq!(replica_entry.1, "3735928559");

        assert!(pairs.iter().any(|(k, v)| k == "name" && v == "Alice"));
    }

    #[test]
    fn build_drops_app_supplied_entries_in_reserved_namespace() {
        let mut info = HashMap::new();
        info.insert("name".to_owned(), "Alice".to_owned());
        info.insert(
            reserved_keys::DEREC_REPLICA_ID_KEY.to_owned(),
            "ffffffffffff".to_owned(),
        );
        info.insert("derec.foo".to_owned(), "bar".to_owned());

        let built = build_communication_info(&info, Some(1)).expect("entries present");
        let pairs = entries_of(&built);

        assert_eq!(pairs.len(), 2);
        let replica_entry = pairs
            .iter()
            .find(|(k, _)| k == reserved_keys::DEREC_REPLICA_ID_KEY)
            .unwrap();
        assert_eq!(replica_entry.1, "1");
        assert!(!pairs.iter().any(|(k, _)| k == "derec.foo"));
    }

    #[test]
    fn extract_strips_reserved_key_and_returns_typed_id() {
        let info = Some(CommunicationInfo {
            communication_info_entries: vec![
                CommunicationInfoKeyValue {
                    key: "name".to_owned(),
                    value: Some(Value::StringValue("Bob".to_owned())),
                },
                CommunicationInfoKeyValue {
                    key: reserved_keys::DEREC_REPLICA_ID_KEY.to_owned(),
                    value: Some(Value::StringValue("3405691582".to_owned())),
                },
            ],
        });

        let (map, replica_id) =
            extract_communication_info(&info, SenderKind::ReplicaSource).unwrap();

        assert_eq!(map.len(), 1);
        assert_eq!(map.get("name").map(String::as_str), Some("Bob"));
        assert!(!map.contains_key(reserved_keys::DEREC_REPLICA_ID_KEY));
        assert_eq!(replica_id, Some(0xCAFE_BABEu64));
    }

    #[test]
    fn extract_rejects_replica_pairing_missing_reserved_key() {
        let info = Some(CommunicationInfo {
            communication_info_entries: vec![CommunicationInfoKeyValue {
                key: "name".to_owned(),
                value: Some(Value::StringValue("Bob".to_owned())),
            }],
        });

        let err =
            extract_communication_info(&info, SenderKind::ReplicaSource).expect_err("must reject");
        assert!(
            matches!(
                err,
                Error::Pairing(PairingError::MissingReplicaId { sender_kind })
                    if sender_kind == SenderKind::ReplicaSource
            ),
            "expected MissingReplicaId, got {err:?}"
        );
    }

    #[test]
    fn extract_rejects_non_replica_pairing_carrying_reserved_key() {
        let info = Some(CommunicationInfo {
            communication_info_entries: vec![CommunicationInfoKeyValue {
                key: reserved_keys::DEREC_REPLICA_ID_KEY.to_owned(),
                value: Some(Value::StringValue("12345".to_owned())),
            }],
        });

        let err = extract_communication_info(&info, SenderKind::Owner).expect_err("must reject");
        assert!(
            matches!(
                err,
                Error::Pairing(PairingError::UnexpectedReplicaId { sender_kind })
                    if sender_kind == SenderKind::Owner
            ),
            "expected UnexpectedReplicaId, got {err:?}"
        );
    }

    #[test]
    fn extract_rejects_replica_pairing_with_no_communication_info() {
        let err =
            extract_communication_info(&None, SenderKind::ReplicaSource).expect_err("must reject");
        assert!(matches!(
            err,
            Error::Pairing(PairingError::MissingReplicaId { .. })
        ));
    }

    #[test]
    fn extract_accepts_non_replica_pairing_with_no_communication_info() {
        let (map, id) = extract_communication_info(&None, SenderKind::Helper).unwrap();
        assert!(map.is_empty());
        assert_eq!(id, None);
    }

    #[test]
    fn require_replica_id_for_kind_short_circuits_non_replica() {
        assert_eq!(
            require_replica_id_for_kind(SenderKind::Owner, None).unwrap(),
            None
        );
        assert_eq!(
            require_replica_id_for_kind(SenderKind::Helper, Some(123)).unwrap(),
            None,
            "Helper kind ignores configured replica id"
        );
    }

    /// Selection picks which of the peer's endpoints we send to; this picks
    /// A PrePair request carries exactly one endpoint on the wire, so this
    /// side has to name one of its own. It names the first of its configured
    /// preference order — the application's stated preference — rather than
    /// matching the peer's, because there is no longer a "the peer's
    /// protocol" to match: the peer's whole offer set is recorded and the
    /// choice of which to dial is the application's.
    #[test]
    fn prepair_advertises_the_first_configured_own_endpoint() {
        let own = [
            TransportProtocol {
                uri: "grpcs://me.example:443".to_owned(),
                protocol: Protocol::Grpc as i32,
            },
            TransportProtocol {
                uri: "https://me.example/derec".to_owned(),
                protocol: Protocol::Https as i32,
            },
        ];

        let lf = LocalFixture {
            own_transports: own.to_vec(),
            ..LocalFixture::new(0)
        };
        assert_eq!(
            lf.local().primary().uri,
            "grpcs://me.example:443",
            "the caller's order decides which single endpoint PrePair advertises"
        );
    }

    /// A single-transport deployment has exactly one answer.
    #[test]
    fn prepair_advertises_the_sole_endpoint_when_only_one_is_served() {
        let own = [TransportProtocol {
            uri: "https://me.example/derec".to_owned(),
            protocol: Protocol::Https as i32,
        }];

        let lf = LocalFixture {
            own_transports: own.to_vec(),
            ..LocalFixture::new(0)
        };
        assert_eq!(lf.local().primary().uri, "https://me.example/derec");
    }

    #[test]
    fn require_replica_id_for_kind_passes_through_for_replica() {
        assert_eq!(
            require_replica_id_for_kind(SenderKind::ReplicaSource, Some(42)).unwrap(),
            Some(42)
        );
    }

    #[test]
    fn require_replica_id_for_kind_errors_when_replica_unconfigured() {
        let err = require_replica_id_for_kind(SenderKind::ReplicaSource, None).unwrap_err();
        assert!(matches!(err, Error::ReplicaIdNotConfigured));
    }

    use crate::protocol::traits::ChannelStoreFuture;
    use crate::protocol::types::{
        ChannelQuery, ChannelRecord, ChannelStatus, HelperChannel, HelperFilter, ReplicaFilter,
        ReplicaMember,
    };
    use derec_proto::communication_info_key_value::Value;
    use derec_proto::{CommunicationInfoKeyValue, Protocol};
    use std::future;
    use std::future::Future;
    use tokio::runtime::Builder;

    struct FixedChannelStore {
        seeded: Option<ChannelRecord>,
    }

    impl DeRecChannelStore for FixedChannelStore {
        fn load(&self, _: u64, _: ChannelQuery) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
            let v = self.seeded.clone();
            Box::pin(future::ready(Ok(v)))
        }
        fn save(&mut self, _: u64, _: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
            Box::pin(future::ready(Ok(())))
        }
        fn remove(&mut self, _: u64, _: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
            Box::pin(future::ready(Ok(false)))
        }
        fn remove_many(&mut self, _: u64, _: &[ChannelQuery]) -> ChannelStoreFuture<'_, ()> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn helpers(&self, _: u64, _: HelperFilter) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
            Box::pin(future::ready(Ok(Vec::new())))
        }
        fn replicas(&self, _: u64, _: ReplicaFilter) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
            Box::pin(future::ready(Ok(Vec::new())))
        }
        fn link_channel(
            &mut self,
            _: u64,
            _: ChannelId,
            _: ChannelId,
        ) -> ChannelStoreFuture<'_, ()> {
            Box::pin(future::ready(Ok(())))
        }
        fn linked_channels(
            &self,
            _: u64,
            cid: ChannelId,
        ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
            Box::pin(future::ready(Ok(vec![cid])))
        }
    }

    fn fake_channel(status: ChannelStatus, peer_role: SenderKind) -> ChannelRecord {
        ChannelRecord::Helper(HelperChannel {
            channel_id: ChannelId(1),
            transports: vec![TransportProtocol {
                uri: "https://example.com".to_owned(),
                protocol: 0,
            }],
            communication_info: HashMap::new(),
            status,
            created_at: 1_700_000_000,
            peer_role,
            weight: 1,
        })
    }

    fn run_async<F: Future<Output = ()>>(f: F) {
        Builder::new_current_thread()
            .build()
            .expect("test runtime")
            .block_on(f)
    }

    #[test]
    fn reject_start_on_channel_in_use_errors_when_channel_already_paired() {
        run_async(async {
            let lf = LocalFixture::new(42);
            let mut rig = StoreRig::with_channels(FixedChannelStore {
                seeded: Some(fake_channel(ChannelStatus::Paired, SenderKind::Helper)),
            });
            let err = reject_start_on_channel_in_use(&mut rig.stores(), &lf.local(), ChannelId(1))
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::ChannelAlreadyPaired { channel_id } if channel_id == ChannelId(1)),
                "expected Error::ChannelAlreadyPaired for ChannelId(1), got {err:?}"
            );
        });
    }

    #[test]
    fn reject_start_on_channel_in_use_allows_pending_retry() {
        run_async(async {
            let lf = LocalFixture::new(42);
            let mut rig = StoreRig::with_channels(FixedChannelStore {
                seeded: Some(fake_channel(ChannelStatus::Pending, SenderKind::Helper)),
            });
            reject_start_on_channel_in_use(&mut rig.stores(), &lf.local(), ChannelId(1))
                .await
                .expect("Pending channel must be accepted as a retry candidate");
        });
    }

    /// A channel still being unpaired keeps its key until the helper answers,
    /// so pairing over it would overwrite that key mid-teardown.
    #[test]
    fn reject_start_on_channel_in_use_errors_while_unpairing() {
        run_async(async {
            let lf = LocalFixture::new(42);
            let mut rig = StoreRig::with_channels(FixedChannelStore {
                seeded: Some(fake_channel(ChannelStatus::Unpairing, SenderKind::Helper)),
            });
            let err = reject_start_on_channel_in_use(&mut rig.stores(), &lf.local(), ChannelId(1))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::ChannelAlreadyPaired { .. }));
        });
    }

    #[test]
    fn reject_start_on_channel_in_use_allows_when_no_channel_record() {
        run_async(async {
            let lf = LocalFixture::new(42);
            let mut rig = StoreRig::with_channels(FixedChannelStore { seeded: None });
            reject_start_on_channel_in_use(&mut rig.stores(), &lf.local(), ChannelId(1))
                .await
                .expect("absent channel record must be accepted");
        });
    }

    #[test]
    fn reject_start_on_channel_in_use_errors_for_paired_replica() {
        run_async(async {
            let lf = LocalFixture::new(42);
            let mut rig = StoreRig::with_channels(FixedChannelStore {
                seeded: Some(fake_channel(
                    ChannelStatus::Paired,
                    SenderKind::ReplicaSource,
                )),
            });
            let err = reject_start_on_channel_in_use(&mut rig.stores(), &lf.local(), ChannelId(1))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::ChannelAlreadyPaired { .. }));
        });
    }
}

/// D6: no two members of a group may share a `replica_id`.
#[cfg(test)]
mod prepair_record_shape_tests {
    use super::super::*;
    use crate::protocol::tests::LocalFixture;
    use crate::protocol::tests::{StoreRig, run_async};
    use crate::protocol::types::{
        ChannelQuery, ChannelRecord, ChannelStatus, HelperChannel, ReplicaFilter, ReplicaMember,
        ReplicaRole,
    };
    use crate::types::ReplicaId;
    use derec_proto::Protocol;
    use std::collections::HashMap;

    const SECRET_ID: u64 = 0x0B0E_9A19;
    const CHANNEL: ChannelId = ChannelId(6000);
    const OWN_REPLICA: u64 = 0xA11CE;

    fn endpoint() -> TransportProtocol {
        TransportProtocol {
            uri: "https://peer.example".to_owned(),
            protocol: Protocol::Https as i32,
        }
    }

    fn endpoints() -> Vec<TransportProtocol> {
        vec![endpoint()]
    }

    /// A replica scanner records its pairing like any other: a `Pending`
    /// placeholder carrying the peer's role, from which the PrePair and pair
    /// responses resolve the local kind. Nothing enters the replica roster —
    /// a pairing in flight is not group membership.
    #[test]
    fn a_replica_scanner_is_recorded_as_a_pending_placeholder() {
        run_async(async {
            let lf = LocalFixture::new(SECRET_ID);
            let mut rig = StoreRig::new();
            persist_start_record(
                &mut rig.stores(),
                &lf.local(),
                CHANNEL,
                endpoints(),
                HashMap::new(),
                SenderKind::ReplicaDestination,
            )
            .await
            .expect("persist start record");

            let placeholder = rig
                .channels
                .load(
                    SECRET_ID,
                    ChannelQuery::Helper {
                        channel_id: CHANNEL,
                    },
                )
                .await
                .expect("load")
                .and_then(|r| r.as_helper().cloned())
                .expect("the replica scanner records a placeholder");
            assert_eq!(placeholder.peer_role, SenderKind::ReplicaSource);
            assert_eq!(placeholder.status, ChannelStatus::Pending);
            assert!(
                rig.channels
                    .replicas(SECRET_ID, ReplicaFilter::default())
                    .await
                    .expect("list members")
                    .is_empty(),
                "no roster row is written before the pairing is confirmed"
            );
        });
    }

    /// The own roster row carries every endpoint this device advertises and
    /// its `communication_info`, filtered the way a peer would store it — the
    /// same shape a peer's row has, so a published roster names and reaches its
    /// writer as well as everyone else.
    #[test]
    fn the_own_roster_row_carries_what_this_device_advertises() {
        run_async(async {
            let lf = LocalFixture {
                own_transports: vec![
                    endpoint(),
                    TransportProtocol {
                        uri: "grpcs://peer.example:443".to_owned(),
                        protocol: Protocol::Grpc as i32,
                    },
                ],
                communication_info: HashMap::from([
                    ("name".to_owned(), "Alice-1".to_owned()),
                    ("blank".to_owned(), "  ".to_owned()),
                    ("derec.replica_id".to_owned(), "spoofed".to_owned()),
                ]),
                replica_id: Some(OWN_REPLICA),
                ..LocalFixture::new(SECRET_ID)
            };
            let mut rig = StoreRig::new();
            claim_own_member(&mut rig.stores(), &lf.local(), CHANNEL, ReplicaRole::Source)
                .await
                .expect("claim own row");

            let member = rig
                .channels
                .load(
                    SECRET_ID,
                    ChannelQuery::Replica {
                        channel_id: CHANNEL,
                        replica_id: ReplicaId(OWN_REPLICA),
                    },
                )
                .await
                .expect("load")
                .and_then(|r| r.as_replica().cloned())
                .expect("own roster row present");
            assert_eq!(member.status, ChannelStatus::Paired);
            assert_eq!(
                member.transports, lf.own_transports,
                "every advertised endpoint, in preference order"
            );
            assert_eq!(
                member.communication_info,
                HashMap::from([("name".to_owned(), "Alice-1".to_owned())]),
            );
        });
    }

    /// The first confirmed pairing fixes the group's channel: a later one
    /// leaves a `Paired` own row where it is, while an own row that is not
    /// `Paired` names no group and is replaced.
    #[test]
    fn claiming_the_own_row_keeps_a_group_and_replaces_anything_else() {
        run_async(async {
            const GROUP: ChannelId = ChannelId(5001);
            const LATER: ChannelId = ChannelId(7001);
            let lf = LocalFixture {
                replica_id: Some(OWN_REPLICA),
                ..LocalFixture::new(SECRET_ID)
            };
            let own_channel = |rig: &StoreRig| {
                rig.channels
                    .member_rows
                    .lock()
                    .unwrap()
                    .get(&(SECRET_ID, OWN_REPLICA))
                    .map(|m| (m.channel_id, m.status))
            };

            let mut rig = StoreRig::new();
            rig.channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Replica(ReplicaMember {
                        channel_id: ChannelId(100),
                        replica_id: ReplicaId(OWN_REPLICA),
                        transports: endpoints(),
                        communication_info: HashMap::new(),
                        role: ReplicaRole::Source,
                        status: ChannelStatus::Pending,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed a leftover own row");

            claim_own_member(&mut rig.stores(), &lf.local(), GROUP, ReplicaRole::Source)
                .await
                .expect("first claim");
            assert_eq!(own_channel(&rig), Some((GROUP, ChannelStatus::Paired)));

            claim_own_member(&mut rig.stores(), &lf.local(), LATER, ReplicaRole::Source)
                .await
                .expect("later claim");
            assert_eq!(
                own_channel(&rig),
                Some((GROUP, ChannelStatus::Paired)),
                "a device in a group keeps its channel"
            );
        });
    }

    /// The helper path is unchanged: it still records the peer's role and the
    /// local kind is its counterparty.
    #[test]
    fn a_helper_scanner_is_recorded_as_a_helper_channel() {
        run_async(async {
            let lf = LocalFixture::new(SECRET_ID);
            let mut rig = StoreRig::new();
            persist_start_record(
                &mut rig.stores(),
                &lf.local(),
                CHANNEL,
                endpoints(),
                HashMap::new(),
                SenderKind::Owner,
            )
            .await
            .expect("persist start record");

            let helper: HelperChannel = rig
                .channels
                .load(
                    SECRET_ID,
                    ChannelQuery::Helper {
                        channel_id: CHANNEL,
                    },
                )
                .await
                .expect("load")
                .and_then(|r| r.as_helper().cloned())
                .expect("helper record present");
            assert_eq!(helper.peer_role.counterparty(), SenderKind::Owner);
            assert_eq!(helper.status, ChannelStatus::Pending);
            let _ = ChannelRecord::Replica(ReplicaMember {
                channel_id: CHANNEL,
                replica_id: ReplicaId(OWN_REPLICA),
                transports: endpoints(),
                communication_info: HashMap::new(),
                role: ReplicaRole::Destination,
                status: ChannelStatus::Pending,
                created_at: 0,
            });
        });
    }
}

#[cfg(test)]
mod pairing_material_cleanup_tests {
    use super::super::*;
    use crate::protocol::tests::StoreRig;
    use crate::protocol::tests::run_async;
    use crate::protocol::{DeRecSecretStore, SecretKind, SecretValue};

    const SECRET_ID: u64 = 0x0C00_7AC7;
    const TRANSIENT: ChannelId = ChannelId(1004);

    /// A completed pairing must leave nothing behind at the transient channel.
    ///
    /// `create_contact` stores a `PairingContact` rather than a
    /// `PairingSecret` under `NoKeys` — that mode has no key material yet, and
    /// the contact is what authenticates the later `PrePairRequest` by nonce.
    /// The accept path used to remove only the secret, so every `NoKeys`
    /// pairing stranded one contact row at an id nothing addresses again.
    #[test]
    fn a_spent_pairing_contact_is_dropped() {
        run_async(async {
            let mut rig = StoreRig::new();
            rig.secrets
                .save(
                    SECRET_ID,
                    TRANSIENT,
                    SecretValue::PairingContact(Default::default()),
                )
                .await
                .expect("seed contact");

            let _ = rig
                .secrets
                .remove(SECRET_ID, TRANSIENT, SecretKind::PairingSecret)
                .await;
            let _ = rig
                .secrets
                .remove(SECRET_ID, TRANSIENT, SecretKind::PairingContact)
                .await;

            let left = rig
                .secrets
                .load(SECRET_ID, TRANSIENT, SecretKind::PairingContact)
                .await
                .expect("load");
            assert!(
                left.is_none(),
                "the transient contact must not outlive the handshake"
            );
        });
    }
}

#[cfg(test)]
mod replica_id_conflict_tests {
    use super::super::pair::abandon_pairing;
    use super::super::replica_id_is_taken;
    use crate::protocol::context::PairingConfig;
    use crate::protocol::tests::LocalFixture;
    use crate::protocol::tests::StoreRig;
    use crate::protocol::tests::{InMemChannelStore, run_async};
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, ReplicaFilter, ReplicaMember, ReplicaRole, Timeouts,
    };
    use crate::protocol::{
        DeRecChannelStore, DeRecSecretStore, PairingKeyMaterial, SecretKind, SecretValue,
    };
    use crate::types::{ChannelId, ReplicaId};
    use derec_proto::{Protocol, TransportProtocol};
    use std::collections::HashMap;

    const SECRET_ID: u64 = 0xD6;
    const GROUP: ChannelId = ChannelId(5001);
    const PAIRING: ChannelId = ChannelId(77);

    async fn seed_member(channels: &mut InMemChannelStore, id: u64, channel_id: ChannelId) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id,
                    replica_id: ReplicaId(id),
                    transports: vec![TransportProtocol {
                        uri: "https://peer.example".to_owned(),
                        protocol: Protocol::Https as i32,
                    }],
                    communication_info: HashMap::new(),
                    role: ReplicaRole::Source,
                    status: ChannelStatus::Paired,
                    created_at: 0,
                }),
            )
            .await
            .expect("seed member");
    }

    /// The roster carries this device's own row, so a peer announcing our own
    /// id collides — the common case, since both ends of a first pairing are
    /// usually configured by one person.
    #[test]
    fn our_own_id_counts_as_taken() {
        run_async(async {
            let lf = LocalFixture::new(SECRET_ID);
            let mut rig = StoreRig::new();
            seed_member(&mut rig.channels, 1001, GROUP).await;

            assert!(
                replica_id_is_taken(&mut rig.stores(), &lf.local(), 1001)
                    .await
                    .expect("check"),
                "a peer announcing our own id must be refused"
            );
            assert!(
                !replica_id_is_taken(&mut rig.stores(), &lf.local(), 1002)
                    .await
                    .expect("check"),
                "a distinct id is free"
            );
        });
    }

    /// A device not yet in a group created its own row during this handshake,
    /// pointing at a channel that is about to disappear. Abandoning must take
    /// it with them, or a later publish resolves the group to a dead channel.
    #[test]
    fn abandoning_a_first_pairing_removes_the_row_it_created() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
            let mut rig = StoreRig::new();
            seed_member(&mut rig.channels, 1001, PAIRING).await;
            rig.secrets
                .save(
                    SECRET_ID,
                    PAIRING,
                    SecretValue::SharedKey(crate::types::SharedKey::new([0x22; 32])),
                )
                .await
                .expect("seed key");

            abandon_pairing(&mut rig.stores(), &lf.local(), PAIRING)
                .await
                .expect("abandon succeeds");

            assert!(
                rig.channels
                    .replicas(SECRET_ID, ReplicaFilter::default())
                    .await
                    .expect("roster")
                    .is_empty(),
                "the row this pairing created must not outlive it"
            );
        });
    }

    /// A device already in a group keeps its identity: the failed pairing has
    /// no claim on it, and removing it would evict the device from a group it
    /// legitimately belongs to.
    #[test]
    fn abandoning_keeps_an_existing_group_membership() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
            let mut rig = StoreRig::new();
            seed_member(&mut rig.channels, 1001, GROUP).await;
            seed_member(&mut rig.channels, 1002, GROUP).await;

            abandon_pairing(&mut rig.stores(), &lf.local(), PAIRING)
                .await
                .expect("abandon succeeds");

            let roster = rig
                .channels
                .replicas(SECRET_ID, ReplicaFilter::default())
                .await
                .expect("roster");
            assert_eq!(
                roster.len(),
                2,
                "an established group survives a failed pairing attempt"
            );
        });
    }

    /// The transient pairing channel and its key go, whichever case applies.
    #[test]
    fn abandoning_clears_the_pairing_channel() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
            let mut rig = StoreRig::new();
            rig.secrets
                .save(
                    SECRET_ID,
                    PAIRING,
                    SecretValue::PairingSecret(PairingKeyMaterial::from_bytes(vec![0x01, 0x02])),
                )
                .await
                .expect("seed pairing secret");

            abandon_pairing(&mut rig.stores(), &lf.local(), PAIRING)
                .await
                .expect("abandon succeeds");

            assert!(
                rig.secrets
                    .load(SECRET_ID, PAIRING, SecretKind::PairingSecret)
                    .await
                    .expect("load")
                    .is_none(),
                "the pairing secret must not survive an abandoned handshake"
            );
        });
    }

    /// `accept()` must record the requester's whole `supportedTransports`
    /// offer list. The peer here offers HTTPS first and gRPCS second, and
    /// gRPCS is the only protocol this responder actually serves.
    #[test]
    fn accept_offers_the_transport_every_advertised_endpoint() {
        use super::super::pair::accept;
        use crate::primitives::pairing::request;
        use derec_proto::{ContactMode, SenderKind};

        run_async(async {
            let channel_id = ChannelId(0xACCE_9701);
            let secret_id = 0x60A7;

            let request::CreateContactResult {
                contact_message,
                secret_key,
            } = request::create_contact(
                channel_id,
                ContactMode::InlineKeys,
                vec![TransportProtocol {
                    uri: "https://initiator.example/derec".to_owned(),
                    protocol: Protocol::Https as i32,
                }],
                None,
            )
            .expect("create_contact");
            let initiator_secret = secret_key.expect("InlineKeys always returns key material");

            // Built through the real crypto path so the request decrypts
            // and finalizes normally; only the transport fields are then
            // overwritten to the scenario under test.
            let request::ProduceResult {
                envelope: request_envelope,
                ..
            } = request::produce(
                SenderKind::Helper,
                vec![TransportProtocol {
                    uri: "https://peer.example.com/derec".to_owned(),
                    protocol: Protocol::Https as i32,
                }],
                &contact_message,
                None,
                None,
            )
            .expect("produce");

            let request::ExtractResult {
                request: mut pair_request,
            } = request::extract(&request_envelope, initiator_secret.ecies_secret_key(), None)
                .expect("extract");

            pair_request.supported_transports = vec![
                TransportProtocol {
                    uri: "https://peer.example.com/derec".to_owned(),
                    protocol: Protocol::Https as i32,
                },
                TransportProtocol {
                    uri: "grpcs://peer.example.com:443".to_owned(),
                    protocol: Protocol::Grpc as i32,
                },
            ];

            let mut rig = StoreRig::new();
            rig.secrets
                .save(
                    secret_id,
                    channel_id,
                    SecretValue::PairingSecret(PairingKeyMaterial::from_secret(&initiator_secret)),
                )
                .await
                .expect("save pairing secret");
            rig.secrets
                .save(
                    secret_id,
                    channel_id,
                    SecretValue::PairingContact(contact_message.clone()),
                )
                .await
                .expect("save contact");

            // This responder serves only gRPCS.
            let lf = LocalFixture {
                own_transports: vec![TransportProtocol {
                    uri: "grpcs://me.example.com:443".to_owned(),
                    protocol: Protocol::Grpc as i32,
                }],
                ..LocalFixture::new(secret_id)
            };
            let pairing_cfg = PairingConfig {
                parameter_range: None,
                lifetime: Timeouts::default().pairing,
            };

            accept(
                &mut rig.stores(),
                &lf.local(),
                &pairing_cfg,
                channel_id,
                &pair_request,
                SenderKind::Owner,
                0,
            )
            .await
            .expect("accept must succeed when one offered endpoint is servable");

            // The library must hand the transport everything the peer
            // advertised, in the peer's order. Which of these to dial is the
            // application's call,
            // so this asserts what was *offered*, not what was chosen.
            assert_eq!(
                rig.transport.sent_endpoint_sets(),
                vec![vec![
                    TransportProtocol {
                        uri: "https://peer.example.com/derec".to_owned(),
                        protocol: Protocol::Https as i32,
                    },
                    TransportProtocol {
                        uri: "grpcs://peer.example.com:443".to_owned(),
                        protocol: Protocol::Grpc as i32,
                    },
                ]],
                "accept() must offer the transport every endpoint the peer \
                 advertised"
            );
        });
    }
}

#[cfg(test)]
mod fingerprint_gate_tests {
    use super::super::pair::completed_pairing_status;
    use crate::protocol::types::ChannelStatus;
    use derec_proto::{ContactMode, SenderKind};

    /// The two key-bearing modes are usable the moment the handshake lands:
    /// the contact carried the keys outright, or a commitment the scanner has
    /// already checked them against.
    #[test]
    fn helper_pairings_with_a_key_binding_are_paired_at_once() {
        for mode in [ContactMode::InlineKeys, ContactMode::HashedKeys] {
            for kind in [SenderKind::Owner, SenderKind::Helper] {
                assert_eq!(
                    completed_pairing_status(kind, Some(mode as i32)),
                    ChannelStatus::Paired,
                    "{kind:?} over {mode:?} must not wait for a fingerprint"
                );
            }
        }
    }

    /// `NoKeys` binds nothing to the contact, so the fingerprint is the only
    /// check that catches a substituted key and the channel stays inert until
    /// it passes — helper pairings included, which is what this gate changed.
    #[test]
    fn no_keys_pairings_wait_for_the_fingerprint() {
        for kind in [
            SenderKind::Owner,
            SenderKind::Helper,
            SenderKind::ReplicaSource,
            SenderKind::ReplicaDestination,
        ] {
            assert_eq!(
                completed_pairing_status(kind, Some(ContactMode::NoKeys as i32)),
                ChannelStatus::Pending,
                "{kind:?} over NoKeys must wait for a fingerprint"
            );
        }
    }

    /// Replica pairings are gated whatever the contact mode — admitting a
    /// second device to the group is a human decision on every path.
    #[test]
    fn replica_pairings_wait_regardless_of_mode() {
        for mode in [
            ContactMode::InlineKeys,
            ContactMode::HashedKeys,
            ContactMode::NoKeys,
        ] {
            for kind in [SenderKind::ReplicaSource, SenderKind::ReplicaDestination] {
                assert_eq!(
                    completed_pairing_status(kind, Some(mode as i32)),
                    ChannelStatus::Pending,
                    "{kind:?} over {mode:?} must wait for a fingerprint"
                );
            }
        }
    }

    /// The responder stores a contact only for `NoKeys`; the other modes leave
    /// a `PairingSecret` instead, so the mode reads as absent and the decision
    /// falls to the kind alone.
    #[test]
    fn an_absent_contact_leaves_the_decision_to_the_kind() {
        assert_eq!(
            completed_pairing_status(SenderKind::Helper, None),
            ChannelStatus::Paired
        );
        assert_eq!(
            completed_pairing_status(SenderKind::ReplicaDestination, None),
            ChannelStatus::Pending
        );
    }
}

/// Where the initiator's own roster row points once a replica handshake
/// completes.
#[cfg(test)]
mod own_member_channel_tests {
    use super::super::{build_communication_info, claim_own_member, pair, start};
    use crate::primitives::pairing::{request, response};
    use crate::protocol::context::PairingConfig;
    use crate::protocol::tests::{LocalFixture, StoreRig, run_async};
    use crate::protocol::types::{
        ChannelQuery, ChannelRecord, ChannelStatus, ReplicaMember, ReplicaRole, Timeouts,
    };
    use crate::protocol::{DeRecChannelStore, DeRecSecretStore, SecretKind, SecretValue};
    use crate::types::{ChannelId, ReplicaId};
    use derec_proto::{ContactMode, Protocol, SenderKind, TransportProtocol};
    use std::collections::HashMap;

    const SECRET_ID: u64 = 0x0A11_CE00;
    const OWN: u64 = 1001;
    const GROUP: ChannelId = ChannelId(0x6E0_0001);

    fn endpoint(host: &str) -> Vec<TransportProtocol> {
        vec![TransportProtocol {
            uri: format!("https://{host}.example/derec"),
            protocol: Protocol::Https as i32,
        }]
    }

    async fn own_channel(rig: &StoreRig) -> ChannelId {
        rig.channels
            .load(
                SECRET_ID,
                ChannelQuery::Replica {
                    channel_id: GROUP,
                    replica_id: ReplicaId(OWN),
                },
            )
            .await
            .expect("load")
            .and_then(|r| r.as_replica().cloned())
            .expect("own roster row present")
            .channel_id
    }

    /// Drives a full handshake in which this device scans a joiner's contact:
    /// `start`, the joiner's real `PairResponse`, then `on_response`. Returns
    /// the rekeyed channel the joiner was admitted on.
    async fn admit_joiner(
        rig: &mut StoreRig,
        lf: &LocalFixture,
        contact_channel: ChannelId,
        joiner_id: u64,
    ) -> ChannelId {
        let pairing_cfg = PairingConfig {
            parameter_range: None,
            lifetime: Timeouts::default().pairing,
        };
        let request::CreateContactResult {
            contact_message,
            secret_key,
        } = request::create_contact(
            contact_channel,
            ContactMode::InlineKeys,
            endpoint("joiner"),
            None,
        )
        .expect("create_contact");
        let joiner_secret = secret_key.expect("InlineKeys returns key material");

        let sent_before = rig.transport.sent_envelopes().len();
        start(
            &mut rig.stores(),
            &lf.local(),
            &pairing_cfg,
            SenderKind::ReplicaSource,
            contact_message,
            HashMap::new(),
            0,
        )
        .await
        .expect("start");
        let request_envelope = rig.transport.sent_envelopes()[sent_before].clone();

        let request::ExtractResult {
            request: pair_request,
        } = request::extract(&request_envelope, joiner_secret.ecies_secret_key(), None)
            .expect("joiner extracts the request");
        let produced = response::produce(
            contact_channel,
            &pair_request,
            &joiner_secret,
            build_communication_info(&HashMap::new(), Some(joiner_id)),
            None,
            lf.policy,
        )
        .expect("joiner produces the response");

        let Some(SecretValue::PairingSecret(own_secret)) = rig
            .secrets
            .load(SECRET_ID, contact_channel, SecretKind::PairingSecret)
            .await
            .expect("load pairing secret")
        else {
            panic!("start stores the initiator's pairing secret");
        };
        let own_secret = own_secret.to_secret().expect("pairing secret");
        let response::ExtractResult {
            response: pair_response,
        } = response::extract(&produced.envelope, own_secret.ecies_secret_key())
            .expect("initiator extracts the response");

        pair::on_response(
            &mut rig.stores(),
            &lf.local(),
            &pairing_cfg,
            contact_channel,
            &pair_response,
            &own_secret,
        )
        .await
        .expect("on_response");
        produced.channel_id
    }

    /// A member admitting a joiner keeps its row on the group channel: the
    /// rekeyed channel belongs to the joiner alone.
    #[test]
    fn an_existing_member_keeps_its_row_on_the_group_channel() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, OWN);
            let mut rig = StoreRig::new();
            rig.channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Replica(ReplicaMember {
                        channel_id: GROUP,
                        replica_id: ReplicaId(OWN),
                        transports: lf.own_transports.clone(),
                        communication_info: HashMap::new(),
                        role: ReplicaRole::Source,
                        status: ChannelStatus::Paired,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed own row");

            let joiner_channel = admit_joiner(&mut rig, &lf, ChannelId(0x0C0_0001), 2002).await;

            assert_ne!(joiner_channel, GROUP);
            assert_eq!(
                own_channel(&rig).await,
                GROUP,
                "admitting a joiner must not move this device off the group channel"
            );
        });
    }

    /// A first-time initiator holds no own row until it confirms a pairing;
    /// the first confirmed channel becomes the group's, and confirming a later
    /// admission leaves it there.
    #[test]
    fn joiners_admitted_in_sequence_keep_the_first_confirmed_group_channel() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, OWN);
            let mut rig = StoreRig::new();

            let first_contact = ChannelId(0x0C0_0002);
            let group = admit_joiner(&mut rig, &lf, first_contact, 2002).await;
            assert_ne!(group, first_contact);
            assert!(
                rig.channels
                    .member_rows
                    .lock()
                    .unwrap()
                    .get(&(SECRET_ID, OWN))
                    .is_none(),
                "a completed but unconfirmed pairing writes no own row"
            );
            claim_own_member(&mut rig.stores(), &lf.local(), group, ReplicaRole::Source)
                .await
                .expect("confirming claims the group channel");
            assert_eq!(own_channel(&rig).await, group);

            let second = admit_joiner(&mut rig, &lf, ChannelId(0x0C0_0003), 2003).await;
            assert_ne!(second, group);
            claim_own_member(&mut rig.stores(), &lf.local(), second, ReplicaRole::Source)
                .await
                .expect("confirming a later admission");
            assert_eq!(
                own_channel(&rig).await,
                group,
                "the second admission must keep the first group channel"
            );
        });
    }
}

#[cfg(test)]
mod refusal_memo_tests {
    use super::super::*;

    /// The memo is read by the requester, so its own range comes first and
    /// the responder's range is the accepted one.
    #[test]
    fn parameter_range_memo_reads_from_the_requester_side() {
        let err = PairingError::IncompatibleParameterRange {
            field: "shareSize",
            local_min: 1_000,
            local_max: 5_000,
            peer_min: 10,
            peer_max: 500,
        };
        assert_eq!(
            parameter_range_memo(&err),
            "`shareSize` range [10, 500] does not overlap the accepted range [1000, 5000]"
        );
    }
}

/// A pairing may not start on a channel identifier this device already uses:
/// the identifier is chosen by whoever created the contact, and a replica
/// group's identifier travels in the clear on every envelope of the group.
#[cfg(test)]
mod channel_in_use_tests {
    use super::super::*;
    use crate::protocol::DeRecSecretStore;
    use crate::protocol::tests::{LocalFixture, StoreRig, run_async};
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, ReplicaMember, ReplicaRole, SecretValue,
    };
    use crate::types::ReplicaId;

    const SECRET_ID: u64 = 42;
    const OWN_REPLICA_ID: u64 = 9;
    const GROUP: ChannelId = ChannelId(9000);

    async fn seed_member(rig: &mut StoreRig, replica_id: u64) {
        rig.channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: GROUP,
                    replica_id: ReplicaId(replica_id),
                    transports: Vec::new(),
                    communication_info: HashMap::new(),
                    role: ReplicaRole::Destination,
                    status: ChannelStatus::Paired,
                    created_at: 1_700_000_000,
                }),
            )
            .await
            .expect("seed member");
    }

    async fn seed_key(rig: &mut StoreRig) {
        rig.secrets
            .save(
                SECRET_ID,
                GROUP,
                SecretValue::SharedKey(crate::types::SharedKey::new([3u8; 32])),
            )
            .await
            .expect("seed group key");
    }

    #[test]
    fn a_pairing_on_the_replica_group_channel_is_refused() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, OWN_REPLICA_ID);
            let mut rig = StoreRig::new();
            seed_member(&mut rig, OWN_REPLICA_ID).await;
            seed_member(&mut rig, 8).await;
            seed_key(&mut rig).await;

            let err = reject_start_on_channel_in_use(&mut rig.stores(), &lf.local(), GROUP)
                .await
                .expect_err("the group channel is in use");
            assert!(
                matches!(err, Error::ChannelAlreadyPaired { channel_id } if channel_id == GROUP),
                "expected ChannelAlreadyPaired for the group channel, got {err:?}"
            );
        });
    }

    #[test]
    fn a_pairing_on_a_channel_holding_a_key_is_refused() {
        run_async(async {
            let lf = LocalFixture::new(SECRET_ID);
            let mut rig = StoreRig::new();
            seed_key(&mut rig).await;

            let err = reject_start_on_channel_in_use(&mut rig.stores(), &lf.local(), GROUP)
                .await
                .expect_err("a channel holding a key is in use");
            assert!(matches!(err, Error::ChannelAlreadyPaired { .. }));
        });
    }
}

/// A pairing has a lifetime, `Timeouts::pairing`, counted from the contact's
/// timestamp for the contact and from the request's timestamp for the
/// request. Past it, the scanner refuses to start and the creator neither
/// prompts, accepts nor answers.
#[cfg(test)]
mod pairing_expiry_tests {
    use crate::Error;
    use crate::extensions::channel_store::ChannelStoreExt as _;
    use crate::primitives::pairing::PairingError;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::tests::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, RecordingTransport, run_async,
    };
    use crate::protocol::types::HelperFilter;
    use crate::protocol::{
        AutoAcceptPolicy, DeRecEvent, DeRecFlow, DeRecProtocol, DeRecSecretStore, IgnoreReason,
        PendingAction, SecretKind, SecretValue, Timeouts,
    };
    use crate::types::ChannelId;
    use crate::utils::now_secs;
    use derec_proto::{ContactMessage, ContactMode, SenderKind};
    use prost_types::Timestamp;
    use std::collections::HashMap;
    use std::time::Duration;

    const SECRET_ID: u64 = 0x18;
    const CONTACT_CHANNEL: ChannelId = ChannelId(0x1818);
    const WINDOW: u64 = 300;

    type Device = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        RecordingTransport,
    >;

    fn device(uri: &str, auto_accept_pairing: bool) -> Device {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(RecordingTransport::default())
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports([uri])
            .with_timeouts(Timeouts {
                pairing: Duration::from_secs(WINDOW),
                ..Default::default()
            })
            .with_auto_accept(AutoAcceptPolicy {
                pairing: auto_accept_pairing,
                pre_pair: auto_accept_pairing,
                ..Default::default()
            })
            .build()
            .expect("device builds")
    }

    fn new_creator(auto_accept_pairing: bool) -> Device {
        device("https://helper.example", auto_accept_pairing)
    }

    fn new_scanner() -> Device {
        device("https://owner.example", true)
    }

    /// A timestamp `secs` seconds in the past.
    fn aged(secs: u64) -> Option<Timestamp> {
        Some(Timestamp {
            seconds: (now_secs() - secs) as i64,
            nanos: 0,
        })
    }

    async fn new_contact(creator: &mut Device, mode: ContactMode) -> ContactMessage {
        creator
            .create_contact(Some(CONTACT_CHANNEL), mode, Some(7))
            .await
            .expect("contact")
    }

    async fn scan(scanner: &mut Device, contact: ContactMessage) -> Result<u64, Error> {
        scanner
            .start(DeRecFlow::Pairing {
                kind: SenderKind::Owner,
                contact,
                peer_communication_info: HashMap::new(),
            })
            .await
            .map(|_| 0)
    }

    /// The envelope `device` sent last.
    fn last_sent(device: &Device) -> Vec<u8> {
        device
            .transport
            .sent_envelopes()
            .pop()
            .expect("an envelope was sent")
    }

    /// Rewrite the creator's stored copy of its contact as if it had been
    /// created `secs` seconds ago.
    async fn age_stored_contact(creator: &mut Device, secs: u64) {
        let Some(SecretValue::PairingContact(mut stored)) = creator
            .secret_store
            .load(SECRET_ID, CONTACT_CHANNEL, SecretKind::PairingContact)
            .await
            .expect("load")
        else {
            panic!("the creator keeps its contact");
        };
        stored.timestamp = aged(secs);
        creator
            .secret_store
            .save(
                SECRET_ID,
                CONTACT_CHANNEL,
                SecretValue::PairingContact(stored),
            )
            .await
            .expect("save");
    }

    async fn holds_pairing_material(device: &Device) -> bool {
        let secret = device
            .secret_store
            .load(SECRET_ID, CONTACT_CHANNEL, SecretKind::PairingSecret)
            .await
            .expect("load");
        let contact = device
            .secret_store
            .load(SECRET_ID, CONTACT_CHANNEL, SecretKind::PairingContact)
            .await
            .expect("load");
        secret.is_some() || contact.is_some()
    }

    async fn holds_no_channel(device: &Device) -> bool {
        device
            .channel_store
            .helpers_matching(SECRET_ID, HelperFilter::default())
            .await
            .expect("helpers")
            .is_empty()
    }

    fn pairing_action(events: &[DeRecEvent]) -> PendingAction {
        events
            .iter()
            .find_map(|event| match event {
                DeRecEvent::ActionRequired { action, .. } => Some(action.clone()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("expected ActionRequired, got {events:?}"))
    }

    fn is_expired(error: &Error) -> bool {
        matches!(error, Error::Pairing(PairingError::Expired(_)))
    }

    fn ignored_as_expired(events: &[DeRecEvent]) -> bool {
        events.iter().any(|event| {
            matches!(
                event,
                DeRecEvent::MessageIgnored {
                    channel_id: CONTACT_CHANNEL,
                    reason: IgnoreReason::Expired,
                    ..
                }
            )
        })
    }

    /// The auditors' scenario: the creator's user accepts after the window.
    /// Nothing is recorded and nothing is sent, and the contact stays usable,
    /// so the scanner simply starts again.
    #[test]
    fn a_late_accept_is_refused_and_a_retry_pairs() {
        run_async(async {
            let mut creator = new_creator(false);
            let mut scanner = new_scanner();
            let contact = new_contact(&mut creator, ContactMode::InlineKeys).await;

            scan(&mut scanner, contact.clone()).await.expect("scan");
            let events = creator.process(&last_sent(&scanner)).await.expect("prompt");
            let action = pairing_action(&events);
            let crate::protocol::Action::Pairing {
                request,
                kind,
                peer_communication_info,
            } = action.action()
            else {
                panic!("expected a pairing action, got {action:?}");
            };
            let mut request = request.clone();
            request.timestamp = aged(WINDOW + 1);
            let action = PendingAction::pairing(
                action.channel_id(),
                action.trace_id(),
                request,
                *kind,
                peer_communication_info.clone(),
            );

            let error = creator.accept(action).await.expect_err("too late");

            assert!(is_expired(&error), "got {error:?}");
            assert!(
                creator.transport.sent_envelopes().is_empty(),
                "nothing is sent"
            );
            assert!(holds_no_channel(&creator).await, "no channel is recorded");
            assert!(
                holds_pairing_material(&creator).await,
                "the contact is still valid"
            );

            scan(&mut scanner, contact).await.expect("scan again");
            let events = creator.process(&last_sent(&scanner)).await.expect("prompt");
            let events = creator
                .accept(pairing_action(&events))
                .await
                .expect("accept");
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::PairingCompleted { .. })),
                "the retry pairs: {events:?}"
            );
        });
    }

    /// The contact expires while the prompt waits: the accept is refused and
    /// the contact's material goes with it.
    #[test]
    fn an_accept_on_an_expired_contact_is_refused() {
        run_async(async {
            let mut creator = new_creator(false);
            let mut scanner = new_scanner();
            let contact = new_contact(&mut creator, ContactMode::InlineKeys).await;

            scan(&mut scanner, contact).await.expect("scan");
            let events = creator.process(&last_sent(&scanner)).await.expect("prompt");
            age_stored_contact(&mut creator, WINDOW + 1).await;

            let error = creator
                .accept(pairing_action(&events))
                .await
                .expect_err("expired contact");

            assert!(is_expired(&error), "got {error:?}");
            assert!(
                creator.transport.sent_envelopes().is_empty(),
                "nothing is sent"
            );
            assert!(holds_no_channel(&creator).await, "no channel is recorded");
            assert!(
                !holds_pairing_material(&creator).await,
                "an expired contact's material is dropped"
            );
        });
    }

    /// A request on an expired contact is ignored on arrival, before any
    /// prompt, whether pairing is accepted by hand or automatically.
    #[test]
    fn a_request_on_an_expired_contact_is_ignored() {
        run_async(async {
            for auto_accept in [false, true] {
                let mut creator = new_creator(auto_accept);
                let mut scanner = new_scanner();
                let contact = new_contact(&mut creator, ContactMode::InlineKeys).await;
                age_stored_contact(&mut creator, WINDOW + 1).await;

                scan(&mut scanner, contact).await.expect("scan");
                let events = creator
                    .process(&last_sent(&scanner))
                    .await
                    .expect("ignored, not an error");

                assert!(
                    ignored_as_expired(&events),
                    "auto_accept={auto_accept}: got {events:?}"
                );
                assert!(
                    creator.transport.sent_envelopes().is_empty(),
                    "auto_accept={auto_accept}: nothing is sent"
                );
                assert!(
                    holds_no_channel(&creator).await,
                    "auto_accept={auto_accept}: no channel is recorded"
                );
                assert!(
                    !holds_pairing_material(&creator).await,
                    "auto_accept={auto_accept}: the expired contact's material is dropped"
                );
            }
        });
    }

    /// The `PrePair` leg follows the same rules: a request on an expired
    /// contact is ignored, and a late accept is refused.
    #[test]
    fn the_pre_pair_leg_expires_like_the_pair_leg() {
        run_async(async {
            for mode in [ContactMode::HashedKeys, ContactMode::NoKeys] {
                let mut creator = new_creator(false);
                let mut scanner = new_scanner();
                let contact = new_contact(&mut creator, mode).await;
                age_stored_contact(&mut creator, WINDOW + 1).await;
                scan(&mut scanner, contact).await.expect("scan");
                let events = creator
                    .process(&last_sent(&scanner))
                    .await
                    .expect("ignored");
                assert!(ignored_as_expired(&events), "{mode:?}: got {events:?}");
                assert!(creator.transport.sent_envelopes().is_empty(), "{mode:?}");

                let mut creator = new_creator(false);
                let mut scanner = new_scanner();
                let contact = new_contact(&mut creator, mode).await;
                scan(&mut scanner, contact).await.expect("scan");
                let events = creator.process(&last_sent(&scanner)).await.expect("prompt");
                let action = pairing_action(&events);
                let crate::protocol::Action::PrePair(request) = action.action() else {
                    panic!("{mode:?}: expected a pre-pair action, got {action:?}");
                };
                let mut request = request.clone();
                request.timestamp = aged(WINDOW + 1);
                let action =
                    PendingAction::pre_pair(action.channel_id(), action.trace_id(), request);
                let error = creator.accept(action).await.expect_err("too late");
                assert!(is_expired(&error), "{mode:?}: got {error:?}");
                assert!(creator.transport.sent_envelopes().is_empty(), "{mode:?}");
            }
        });
    }

    /// The scanner refuses a contact older than the window before storing or
    /// sending anything.
    #[test]
    fn the_scanner_refuses_an_expired_contact() {
        run_async(async {
            for mode in [
                ContactMode::InlineKeys,
                ContactMode::HashedKeys,
                ContactMode::NoKeys,
            ] {
                let mut creator = new_creator(true);
                let mut scanner = new_scanner();
                let mut contact = new_contact(&mut creator, mode).await;
                contact.timestamp = aged(WINDOW + 1);

                let error = scan(&mut scanner, contact).await.expect_err("expired");

                assert!(is_expired(&error), "{mode:?}: got {error:?}");
                assert!(scanner.transport.sent_envelopes().is_empty(), "{mode:?}");
                assert!(holds_no_channel(&scanner).await, "{mode:?}");
                assert!(!holds_pairing_material(&scanner).await, "{mode:?}");
            }
        });
    }

    /// A contact without a timestamp cannot be shown to be fresh.
    #[test]
    fn the_scanner_refuses_a_contact_without_a_timestamp() {
        run_async(async {
            let mut creator = new_creator(true);
            let mut scanner = new_scanner();
            let mut contact = new_contact(&mut creator, ContactMode::InlineKeys).await;
            contact.timestamp = None;

            let error = scan(&mut scanner, contact).await.expect_err("no timestamp");

            assert!(
                matches!(
                    error,
                    Error::Pairing(PairingError::InvalidContactMessage(_))
                ),
                "got {error:?}"
            );
            assert!(scanner.transport.sent_envelopes().is_empty());
        });
    }

    /// A contact just inside the window still pairs.
    #[test]
    fn a_contact_inside_the_window_pairs() {
        run_async(async {
            let mut creator = new_creator(true);
            let mut scanner = new_scanner();
            let mut contact = new_contact(&mut creator, ContactMode::InlineKeys).await;
            contact.timestamp = aged(WINDOW - 5);
            age_stored_contact(&mut creator, WINDOW - 5).await;

            scan(&mut scanner, contact).await.expect("scan");
            let events = creator.process(&last_sent(&scanner)).await.expect("pairs");

            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::PairingCompleted { .. })),
                "got {events:?}"
            );
        });
    }
}
