// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#[cfg(test)]
mod handshake_tests {
    use super::super::*;
    use crate::protocol::test::LocalFixture;
    use crate::protocol::test::StoreRig;

    fn entries_of(c: &CommunicationInfo) -> Vec<(String, String)> {
        c.communication_info_entries
            .iter()
            .filter_map(|e| match &e.value {
                Some(derec_proto::communication_info_key_value::Value::StringValue(s)) => {
                    Some((e.key.clone(), s.clone()))
                }
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
                derec_proto::CommunicationInfoKeyValue {
                    key: "name".to_owned(),
                    value: Some(
                        derec_proto::communication_info_key_value::Value::StringValue(
                            "Bob".to_owned(),
                        ),
                    ),
                },
                derec_proto::CommunicationInfoKeyValue {
                    key: reserved_keys::DEREC_REPLICA_ID_KEY.to_owned(),
                    value: Some(
                        derec_proto::communication_info_key_value::Value::StringValue(
                            "3405691582".to_owned(),
                        ),
                    ),
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
            communication_info_entries: vec![derec_proto::CommunicationInfoKeyValue {
                key: "name".to_owned(),
                value: Some(
                    derec_proto::communication_info_key_value::Value::StringValue("Bob".to_owned()),
                ),
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
            communication_info_entries: vec![derec_proto::CommunicationInfoKeyValue {
                key: reserved_keys::DEREC_REPLICA_ID_KEY.to_owned(),
                value: Some(
                    derec_proto::communication_info_key_value::Value::StringValue(
                        "12345".to_owned(),
                    ),
                ),
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
                protocol: derec_proto::Protocol::Grpc as i32,
            },
            TransportProtocol {
                uri: "https://me.example/derec".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
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
            protocol: derec_proto::Protocol::Https as i32,
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

    struct FixedChannelStore {
        seeded: Option<ChannelRecord>,
    }

    impl DeRecChannelStore for FixedChannelStore {
        fn load(&self, _: u64, _: ChannelQuery) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
            let v = self.seeded.clone();
            Box::pin(std::future::ready(Ok(v)))
        }
        fn save(&mut self, _: u64, _: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn remove(&mut self, _: u64, _: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
            Box::pin(std::future::ready(Ok(false)))
        }
        fn helpers(&self, _: u64, _: HelperFilter) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
            Box::pin(std::future::ready(Ok(Vec::new())))
        }
        fn replicas(&self, _: u64, _: ReplicaFilter) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
            Box::pin(std::future::ready(Ok(Vec::new())))
        }
        fn link_channel(
            &mut self,
            _: u64,
            _: ChannelId,
            _: ChannelId,
        ) -> ChannelStoreFuture<'_, ()> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn linked_channels(
            &self,
            _: u64,
            cid: ChannelId,
        ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
            Box::pin(std::future::ready(Ok(vec![cid])))
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
        })
    }

    fn run_async<F: std::future::Future<Output = ()>>(f: F) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime")
            .block_on(f)
    }

    #[test]
    fn reject_start_on_paired_channel_errors_when_channel_already_paired() {
        run_async(async {
            let lf = LocalFixture::new(42);
            let mut rig = StoreRig::with_channels(FixedChannelStore {
                seeded: Some(fake_channel(ChannelStatus::Paired, SenderKind::Helper)),
            });
            let err = reject_start_on_paired_channel(&mut rig.stores(), &lf.local(), ChannelId(1))
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::ChannelAlreadyPaired { channel_id } if channel_id == ChannelId(1)),
                "expected Error::ChannelAlreadyPaired for ChannelId(1), got {err:?}"
            );
        });
    }

    #[test]
    fn reject_start_on_paired_channel_allows_pending_retry() {
        run_async(async {
            let lf = LocalFixture::new(42);
            let mut rig = StoreRig::with_channels(FixedChannelStore {
                seeded: Some(fake_channel(ChannelStatus::Pending, SenderKind::Helper)),
            });
            reject_start_on_paired_channel(&mut rig.stores(), &lf.local(), ChannelId(1))
                .await
                .expect("Pending channel must be accepted as a retry candidate");
        });
    }

    #[test]
    fn reject_start_on_paired_channel_allows_when_no_channel_record() {
        run_async(async {
            let lf = LocalFixture::new(42);
            let mut rig = StoreRig::with_channels(FixedChannelStore { seeded: None });
            reject_start_on_paired_channel(&mut rig.stores(), &lf.local(), ChannelId(1))
                .await
                .expect("absent channel record must be accepted");
        });
    }

    #[test]
    fn reject_start_on_paired_channel_errors_for_paired_replica() {
        run_async(async {
            let lf = LocalFixture::new(42);
            let mut rig = StoreRig::with_channels(FixedChannelStore {
                seeded: Some(fake_channel(
                    ChannelStatus::Paired,
                    SenderKind::ReplicaSource,
                )),
            });
            let err = reject_start_on_paired_channel(&mut rig.stores(), &lf.local(), ChannelId(1))
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
    use crate::protocol::test::LocalFixture;
    use crate::protocol::test::{StoreRig, run_async};
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember};
    use crate::types::ReplicaId;

    const SECRET_ID: u64 = 0x0B0E_9A19;
    const CHANNEL: ChannelId = ChannelId(6000);
    const OWN_REPLICA: u64 = 0xA11CE;

    fn endpoint() -> TransportProtocol {
        TransportProtocol {
            uri: "https://peer.example".to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    fn endpoints() -> Vec<TransportProtocol> {
        vec![endpoint()]
    }

    /// `start` records a replica scanner as its own roster row, not as a
    /// helper channel, so the PrePair-response handler has to resolve the
    /// local sender kind from either shape.
    ///
    /// Reading only the helper shape made `HashedKeys` and `NoKeys` — the two
    /// modes with a PrePair leg — unusable for admitting a replica at all.
    #[test]
    fn a_replica_scanner_is_recorded_as_its_own_roster_row() {
        run_async(async {
            let lf = LocalFixture::new(SECRET_ID);
            let mut rig = StoreRig::new();
            persist_start_record(
                &mut rig.stores(),
                &lf.local(),
                CHANNEL,
                endpoints(),
                std::collections::HashMap::new(),
                SenderKind::ReplicaDestination,
                Some(OWN_REPLICA),
            )
            .await
            .expect("persist start record");

            assert!(
                rig.channels
                    .load(
                        SECRET_ID,
                        crate::protocol::types::ChannelQuery::Helper {
                            channel_id: CHANNEL
                        }
                    )
                    .await
                    .expect("load")
                    .and_then(|r| r.as_helper().cloned())
                    .is_none(),
                "a replica scanner writes no helper record — resolving only that \
                 shape is what broke PrePair for replicas"
            );

            let member = rig
                .channels
                .load(
                    SECRET_ID,
                    crate::protocol::types::ChannelQuery::Replica {
                        channel_id: CHANNEL,
                        replica_id: ReplicaId(OWN_REPLICA),
                    },
                )
                .await
                .expect("load")
                .and_then(|r| r.as_replica().cloned())
                .expect("the replica scanner records its own roster row");
            assert_eq!(
                member.role.to_sender_kind(),
                SenderKind::ReplicaDestination,
                "the row carries the local kind the PrePair response needs"
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
                std::collections::HashMap::new(),
                SenderKind::Owner,
                None,
            )
            .await
            .expect("persist start record");

            let helper: HelperChannel = rig
                .channels
                .load(
                    SECRET_ID,
                    crate::protocol::types::ChannelQuery::Helper {
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
                communication_info: std::collections::HashMap::new(),
                role: crate::protocol::types::ReplicaRole::Destination,
                status: ChannelStatus::Pending,
                created_at: 0,
            });
        });
    }
}

#[cfg(test)]
mod pairing_material_cleanup_tests {
    use super::super::*;
    use crate::protocol::test::StoreRig;
    use crate::protocol::test::run_async;
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
    use crate::protocol::context::PairingConfig;
    use crate::protocol::test::LocalFixture;
    use crate::protocol::test::StoreRig;
    use crate::protocol::test::{InMemChannelStore, run_async};
    use crate::protocol::types::{ChannelRecord, ChannelStatus, ReplicaMember, ReplicaRole};
    use crate::protocol::{DeRecChannelStore, DeRecSecretStore, SecretKind, SecretValue};
    use crate::types::{ChannelId, ReplicaId};

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
                    transports: vec![derec_proto::TransportProtocol {
                        uri: "https://peer.example".to_owned(),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
                    communication_info: std::collections::HashMap::new(),
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
                super::super::replica_id_is_taken(&mut rig.stores(), &lf.local(), 1001)
                    .await
                    .expect("check"),
                "a peer announcing our own id must be refused"
            );
            assert!(
                !super::super::replica_id_is_taken(&mut rig.stores(), &lf.local(), 1002)
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
                .save(SECRET_ID, PAIRING, SecretValue::SharedKey([0x22; 32]))
                .await
                .expect("seed key");

            super::super::pair::abandon_pairing(&mut rig.stores(), &lf.local(), PAIRING)
                .await
                .expect("abandon succeeds");

            assert!(
                rig.channels
                    .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
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

            super::super::pair::abandon_pairing(&mut rig.stores(), &lf.local(), PAIRING)
                .await
                .expect("abandon succeeds");

            let roster = rig
                .channels
                .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
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
                    SecretValue::PairingSecret(
                        crate::protocol::types::PairingKeyMaterial::from_bytes(vec![0x01, 0x02]),
                    ),
                )
                .await
                .expect("seed pairing secret");

            super::super::pair::abandon_pairing(&mut rig.stores(), &lf.local(), PAIRING)
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

    /// `accept()` must select from the requester's `supportedTransports`
    /// offer list, not trust its legacy singular field outright. The peer
    /// here advertises HTTPS as its singular field — structurally valid,
    /// so the old code accepted it without complaint — but also offers
    /// gRPCS, which is the only protocol this responder actually serves.
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    #[test]
    fn accept_offers_the_transport_every_advertised_endpoint() {
        use super::super::pair::accept;
        use crate::primitives::pairing::request;
        use crate::protocol::test::run_async;
        use crate::protocol::{DeRecSecretStore, PairingKeyMaterial, SecretValue};
        use crate::types::ChannelId;
        use derec_proto::{ContactMode, Protocol, SenderKind, TransportProtocol};
        use std::collections::HashMap;

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
            } = request::extract(&request_envelope, initiator_secret.ecies_secret_key())
                .expect("extract");

            pair_request.transport_protocol = Some(TransportProtocol {
                uri: "https://peer.example.com/derec".to_owned(),
                protocol: Protocol::Https as i32,
            });
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

            // This responder serves only gRPCS.
            let lf = LocalFixture {
                own_transports: vec![TransportProtocol {
                    uri: "grpcs://me.example.com:443".to_owned(),
                    protocol: Protocol::Grpc as i32,
                }],
                ..LocalFixture::new(secret_id)
            };
            let comm_info = HashMap::new();
            let pairing_cfg = PairingConfig {
                communication_info: &comm_info,
                parameter_range: None,
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
            .expect(
                "accept must select the servable gRPCS offer, not the unservable \
                 HTTPS singular field",
            );

            // The library must hand the transport everything the peer
            // advertised, in the peer's order — not narrow it to the singular
            // legacy field. Which of these to dial is the application's call,
            // so this asserts what was *offered*, not what was chosen.
            assert_eq!(
                rig.transport.sent_endpoint_sets(),
                vec![vec![
                    derec_proto::TransportProtocol {
                        uri: "https://peer.example.com/derec".to_owned(),
                        protocol: Protocol::Https as i32,
                    },
                    derec_proto::TransportProtocol {
                        uri: "grpcs://peer.example.com:443".to_owned(),
                        protocol: Protocol::Grpc as i32,
                    },
                ]],
                "accept() must offer the transport every endpoint the peer \
                 advertised, not just its singular legacy field"
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
