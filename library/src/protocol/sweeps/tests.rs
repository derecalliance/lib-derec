// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::protocol::DeRecProtocol;
use crate::protocol::events::DeRecEvent;
use crate::protocol::traits::{DeRecChannelStore, DeRecStateStore};
use crate::protocol::types::{StateItem, StateKey};
use crate::types::ChannelId;
use crate::utils::now_secs;

mod sharing_round_outcome {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::tests::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::types::ReplicaId;

    use std::collections::HashSet;

    const SECRET_ID: u64 = 0xF00D;

    // The persisting double: the accumulator reads back what it wrote, so a
    // no-op state store would make every assertion here vacuous.
    type TestProtocol = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        NoopTransport,
    >;

    fn build(threshold: usize) -> TestProtocol {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(threshold)
            .build()
            .expect("test protocol builds")
    }

    async fn seed_round(
        protocol: &mut TestProtocol,
        version: u32,
        helpers: &[u64],
        members: &[u64],
    ) {
        protocol
            .state_store
            .save(
                SECRET_ID,
                StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                    version,
                    pending: helpers.iter().copied().map(ChannelId).collect(),
                    confirmed: HashSet::new(),
                    failed: HashSet::new(),
                    pending_replicas: members.iter().copied().map(ReplicaId).collect(),
                    synced_replicas: HashSet::new(),
                    behind_replicas: HashSet::new(),
                    started_at: now_secs(),
                    keep_version: None,
                    threshold: None,
                })),
            )
            .await
            .expect("seed round");
    }

    /// Two rounds open at once each settle on their own.
    ///
    /// Rounds are not started only by `start(ProtectSecret)`: the
    /// pair-completion hook and the promotion inside `verify_fingerprint` both
    /// publish while handling an *inbound* message, so a second round can open
    /// under an application that never asked for one. When the row was keyed by
    /// `secret_id` alone the newcomer replaced its predecessor and **neither**
    /// finished — responses for the replaced round landed against state that no
    /// longer existed, and no `SharingComplete` was emitted for either. The
    /// application could not defend against it, having no view of round state.
    #[test]
    fn two_open_rounds_settle_independently() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 7, &[9001], &[]).await;
            seed_round(&mut protocol, 8, &[9002], &[]).await;

            // Both rows survive; the second did not displace the first.
            for version in [7u32, 8] {
                assert!(
                    protocol
                        .state_store
                        .load(SECRET_ID, StateKey::SharingRound { version })
                        .await
                        .expect("load")
                        .is_some(),
                    "round v{version} must still be in flight"
                );
            }

            // Answer only v7. Its event carries the version, so v8 must ignore it.
            let mut events = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(9001),
                version: 7,
            }];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 7, .. })),
                "v7 completes once its only helper confirms; got {events:?}"
            );
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 8, .. })),
                "v8 has an outstanding helper and must not complete; got {events:?}"
            );
            assert!(
                protocol
                    .state_store
                    .load(SECRET_ID, StateKey::SharingRound { version: 7 })
                    .await
                    .expect("load")
                    .is_none(),
                "a completed round leaves no row"
            );

            // v8 is untouched and still settles on its own answer.
            let mut events = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(9002),
                version: 8,
            }];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 8, .. })),
                "v8 completes when its own helper answers; got {events:?}"
            );
            assert!(
                protocol
                    .state_store
                    .load(SECRET_ID, StateKey::SharingRound { version: 8 })
                    .await
                    .expect("load")
                    .is_none(),
                "a completed round leaves no row"
            );
        });
    }

    /// A round with no further traffic still reaches a terminal state.
    ///
    /// Timeouts are otherwise only evaluated inside `process`, so a publish
    /// whose helpers all go quiet has nothing left to trigger it. `tick` is
    /// the entry point a scheduler calls, and it must both fail the silent
    /// participants *and* close the round: reporting failures while leaving
    /// the round open would still strand an application waiting on
    /// `SharingComplete`.
    #[test]
    fn a_tick_loads_the_open_rounds_once() {
        run_async(async {
            let mut protocol = build(2);
            protocol.timeouts.sharing_round = std::time::Duration::from_secs(60);
            seed_round(&mut protocol, 3, &[9001], &[]).await;
            seed_round(&mut protocol, 4, &[9002], &[]).await;
            for version in [3u32, 4] {
                let key = StateKey::SharingRound { version };
                let Some(StateItem::SharingRound(mut round)) = protocol
                    .state_store
                    .load(SECRET_ID, key)
                    .await
                    .expect("load")
                else {
                    panic!("round {version} seeded");
                };
                if version == 3 {
                    round.started_at = now_secs().saturating_sub(600);
                }
                protocol
                    .state_store
                    .save(SECRET_ID, StateItem::SharingRound(round))
                    .await
                    .expect("save");
            }

            let events = protocol.tick().await;

            assert_eq!(
                protocol.state_store.load_all_calls.lock().unwrap()
                    [&crate::protocol::types::StateKind::SharingRound],
                1,
                "timeouts and the tally share one load"
            );
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 3, .. })),
                "the expired round times out and closes; got {events:?}"
            );
            assert!(
                protocol
                    .state_store
                    .load(SECRET_ID, StateKey::SharingRound { version: 4 })
                    .await
                    .expect("load")
                    .is_some(),
                "the round inside its window stays open"
            );
        });
    }

    #[test]
    fn tick_closes_a_round_that_no_message_will_ever_finish() {
        run_async(async {
            let mut protocol = build(2);
            protocol.timeouts.sharing_round = std::time::Duration::from_secs(60);

            // A round started well outside the timeout window, with one helper
            // and one member that never answered.
            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: 3,
                        pending: [ChannelId(9001)].into_iter().collect(),
                        confirmed: [ChannelId(9002)].into_iter().collect(),
                        failed: HashSet::new(),
                        pending_replicas: [ReplicaId(1002)].into_iter().collect(),
                        synced_replicas: HashSet::new(),
                        behind_replicas: HashSet::new(),
                        started_at: now_secs().saturating_sub(600),
                        keep_version: None,
                        threshold: None,
                    })),
                )
                .await
                .expect("seed round");

            let events = protocol.tick().await;

            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ShareRejected { channel_id, memo, .. }
                        if *channel_id == ChannelId(9001) && memo == "timeout"
                )),
                "the silent helper is failed; got {events:?}"
            );
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ReplicaSyncFailed { replica_id, reason, .. }
                        if *replica_id == 1002 && reason == "timeout"
                )),
                "the silent member is reported behind; got {events:?}"
            );
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 3, .. })),
                "the round must actually close, not just report failures; got {events:?}"
            );
            assert!(
                protocol
                    .state_store
                    .load(SECRET_ID, StateKey::SharingRound { version: 3 })
                    .await
                    .expect("load")
                    .is_none(),
                "a closed round leaves no state row behind"
            );
        });
    }

    /// The sweep inside `process` saves the failed participants before the
    /// message is even decoded, so a message that then fails must still
    /// hand back the timeouts and the closed round.
    #[test]
    fn a_failing_process_still_reports_the_timeouts_it_settled() {
        run_async(async {
            let mut protocol = build(2);
            protocol.timeouts.sharing_round = std::time::Duration::from_secs(60);
            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: 3,
                        pending: [ChannelId(9001)].into_iter().collect(),
                        confirmed: [ChannelId(9002)].into_iter().collect(),
                        failed: HashSet::new(),
                        pending_replicas: HashSet::new(),
                        synced_replicas: HashSet::new(),
                        behind_replicas: HashSet::new(),
                        started_at: now_secs().saturating_sub(600),
                        keep_version: None,
                        threshold: None,
                    })),
                )
                .await
                .expect("seed round");

            let error = protocol
                .process(&[0xFF, 0xFF, 0xFF])
                .await
                .expect_err("garbage bytes do not decode");

            assert!(error.channel_id.is_none());
            assert!(
                error.events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ShareRejected { channel_id, memo, .. }
                        if *channel_id == ChannelId(9001) && memo == "timeout"
                )),
                "the timeout travels with the error; got {:?}",
                error.events
            );
            assert!(
                error
                    .events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 3, .. })),
                "the round closes on the failing call; got {:?}",
                error.events
            );
            assert!(
                protocol.tick().await.is_empty(),
                "settled deadlines are not reported twice"
            );
        });
    }

    /// Rounds that complete in the same pass close together: one read of
    /// their weights and one removal of their rows. They are reported in
    /// version order, and a departing member both let go is reported once,
    /// by the first.
    #[test]
    fn rounds_completing_together_close_in_one_pass() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 8, &[9002], &[1003]).await;
            seed_round(&mut protocol, 7, &[9001], &[1003]).await;
            protocol
                .channel_store
                .save(
                    SECRET_ID,
                    crate::protocol::types::ChannelRecord::Replica(
                        crate::protocol::types::ReplicaMember {
                            channel_id: ChannelId(5001),
                            replica_id: ReplicaId(1003),
                            transports: vec![derec_proto::TransportProtocol {
                                uri: "https://peer.example".to_owned(),
                                protocol: derec_proto::Protocol::Https as i32,
                            }],
                            communication_info: std::collections::HashMap::new(),
                            role: crate::protocol::types::ReplicaRole::Destination,
                            status: crate::protocol::types::ChannelStatus::Unpairing,
                            created_at: 0,
                        },
                    ),
                )
                .await
                .expect("seed member");

            let mut events = Vec::new();
            for (channel, version) in [(9001u64, 7u32), (9002, 8)] {
                events.push(DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(channel),
                    version,
                });
                events.push(DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1003,
                    secret_id: SECRET_ID,
                    version,
                    status: 0,
                    memo: String::new(),
                });
            }
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            let reported: Vec<String> = events
                .iter()
                .filter_map(|e| match e {
                    DeRecEvent::SharingComplete { version, .. } => {
                        Some(format!("complete v{version}"))
                    }
                    DeRecEvent::ReplicaRemoved { replica_id } => {
                        Some(format!("removed {replica_id}"))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(reported, ["complete v7", "removed 1003", "complete v8"]);
            assert_eq!(*protocol.share_store.load_many_calls.lock().unwrap(), 1);
            assert_eq!(*protocol.state_store.remove_many_calls.lock().unwrap(), 1);
            for version in [7u32, 8] {
                assert!(
                    protocol
                        .state_store
                        .load(SECRET_ID, StateKey::SharingRound { version })
                        .await
                        .expect("load")
                        .is_none(),
                    "v{version} leaves no row"
                );
            }
        });
    }

    /// `tick` runs the unpair sweep too, not only the sharing round.
    ///
    /// An unpair sent under `UnpairAck::Required` keeps local state alive
    /// until the peer acknowledges. A peer that never answers would otherwise
    /// pin that state forever, since nothing else would arrive to trigger the
    /// check.
    #[test]
    fn tick_expires_an_unacknowledged_unpair() {
        run_async(async {
            let mut protocol = build(2);
            protocol.timeouts.unpair_ack = std::time::Duration::from_secs(60);

            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::PendingUnpair {
                        channel_id: ChannelId(4242),
                        started_at: now_secs().saturating_sub(600),
                    },
                )
                .await
                .expect("seed pending unpair");

            let events = protocol.tick().await;

            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::Unpaired { channel_id } if *channel_id == ChannelId(4242)
                )),
                "the unacknowledged unpair completes on the timeout; got {events:?}"
            );
            assert!(
                protocol
                    .state_store
                    .load(
                        SECRET_ID,
                        StateKey::PendingUnpair {
                            channel_id: ChannelId(4242)
                        }
                    )
                    .await
                    .expect("load")
                    .is_none(),
                "the pending row is consumed"
            );
        });
    }

    /// Seed an unpair on `channel` whose acknowledgement window has elapsed.
    async fn seed_expired_unpair(protocol: &mut TestProtocol, channel: ChannelId) {
        protocol.timeouts.unpair_ack = std::time::Duration::from_secs(60);
        protocol
            .state_store
            .save(
                SECRET_ID,
                StateItem::PendingUnpair {
                    channel_id: channel,
                    started_at: now_secs().saturating_sub(600),
                },
            )
            .await
            .expect("seed pending unpair");
    }

    async fn still_pending(protocol: &TestProtocol, channel: ChannelId) -> bool {
        protocol
            .state_store
            .load(
                SECRET_ID,
                StateKey::PendingUnpair {
                    channel_id: channel,
                },
            )
            .await
            .expect("load")
            .is_some()
    }

    fn unpaired(events: &[DeRecEvent], channel: ChannelId) -> usize {
        events
            .iter()
            .filter(|e| matches!(e, DeRecEvent::Unpaired { channel_id } if *channel_id == channel))
            .count()
    }

    /// A timed-out unpair whose channel cannot be dropped keeps its pending
    /// entry and reports nothing; the next sweep drops it and reports it.
    #[test]
    fn a_timed_out_unpair_that_cannot_be_dropped_is_dropped_next_time() {
        run_async(async {
            let mut protocol = build(2);
            let channel = ChannelId(4242);
            seed_expired_unpair(&mut protocol, channel).await;

            *protocol.channel_store.fail_remove_many.lock().unwrap() = true;
            let events = protocol.tick().await;
            assert_eq!(unpaired(&events, channel), 0, "got {events:?}");
            assert!(
                still_pending(&protocol, channel).await,
                "the entry survives"
            );

            *protocol.channel_store.fail_remove_many.lock().unwrap() = false;
            let events = protocol.tick().await;
            assert_eq!(unpaired(&events, channel), 1, "got {events:?}");
            assert!(!still_pending(&protocol, channel).await);
        });
    }

    /// A timed-out unpair dropped but whose entry cannot be removed reports
    /// nothing; the next sweep removes it and reports it, once.
    #[test]
    fn a_timed_out_unpair_whose_entry_stays_is_reported_once() {
        run_async(async {
            let mut protocol = build(2);
            let channel = ChannelId(4242);
            seed_expired_unpair(&mut protocol, channel).await;

            *protocol.state_store.fail_writes.lock().unwrap() = true;
            let events = protocol.tick().await;
            assert_eq!(unpaired(&events, channel), 0, "got {events:?}");
            assert!(
                still_pending(&protocol, channel).await,
                "the entry survives"
            );

            *protocol.state_store.fail_writes.lock().unwrap() = false;
            let events = protocol.tick().await;
            assert_eq!(unpaired(&events, channel), 1, "got {events:?}");
            assert!(!still_pending(&protocol, channel).await);

            let events = protocol.tick().await;
            assert_eq!(
                unpaired(&events, channel),
                0,
                "reported once; got {events:?}"
            );
        });
    }

    /// A pending unpair still inside its window survives a `tick`.
    #[test]
    fn tick_leaves_a_recent_unpair_pending() {
        run_async(async {
            let mut protocol = build(2);
            protocol.timeouts.unpair_ack = std::time::Duration::from_secs(600);

            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::PendingUnpair {
                        channel_id: ChannelId(4242),
                        started_at: now_secs(),
                    },
                )
                .await
                .expect("seed pending unpair");

            let events = protocol.tick().await;

            assert!(events.is_empty(), "got {events:?}");
            assert!(
                protocol
                    .state_store
                    .load(
                        SECRET_ID,
                        StateKey::PendingUnpair {
                            channel_id: ChannelId(4242)
                        }
                    )
                    .await
                    .expect("load")
                    .is_some(),
                "the acknowledgement window has not elapsed"
            );
        });
    }

    /// Expired-channel cleanup is part of `tick`, and follows the same
    /// configuration `process` honours rather than a rule of its own.
    ///
    /// Disabled is the default, so a `tick` on a protocol that never opted in
    /// must leave a stale pending channel alone; `remove_expired_channels`
    /// stays available for callers that want to sweep explicitly.
    #[test]
    fn tick_honours_the_expired_channel_policy() {
        run_async(async {
            for (cleanup, expect_removed) in [
                (crate::protocol::ExpiredChannelCleanup::Disabled, false),
                (
                    crate::protocol::ExpiredChannelCleanup::Enabled { timeout_in_secs: 1 },
                    true,
                ),
            ] {
                let mut protocol = build(2);
                protocol.timeouts.expired_channels = cleanup;
                protocol
                    .channel_store
                    .save(
                        SECRET_ID,
                        crate::protocol::types::ChannelRecord::Helper(
                            crate::protocol::types::HelperChannel {
                                channel_id: ChannelId(77),
                                transports: vec![derec_proto::TransportProtocol {
                                    uri: "https://stale.example".to_owned(),
                                    protocol: derec_proto::Protocol::Https as i32,
                                }],
                                communication_info: std::collections::HashMap::new(),
                                peer_role: derec_proto::SenderKind::Helper,
                                status: crate::protocol::types::ChannelStatus::Pending,
                                created_at: now_secs().saturating_sub(3600),
                                weight: 1,
                            },
                        ),
                    )
                    .await
                    .expect("seed stale pending channel");

                let _ = protocol.tick().await;

                let gone = protocol
                    .channel_store
                    .helpers(SECRET_ID, crate::protocol::types::HelperFilter::default())
                    .await
                    .expect("helpers")
                    .is_empty();
                assert_eq!(
                    gone, expect_removed,
                    "cleanup {cleanup:?}: expected removed={expect_removed}"
                );
            }
        });
    }

    /// `tick` is safe to call on an idle protocol — the common case for a
    /// scheduler firing on a quiet partition.
    #[test]
    fn tick_on_an_idle_protocol_does_nothing() {
        run_async(async {
            let mut protocol = build(2);
            let events = protocol.tick().await;
            assert!(events.is_empty(), "got {events:?}");
        });
    }

    /// A round still inside its window is left alone: `tick` must not cut
    /// short a publish whose helpers are merely slow.
    #[test]
    fn tick_leaves_a_round_inside_its_window_open() {
        run_async(async {
            let mut protocol = build(2);
            protocol.timeouts.sharing_round = std::time::Duration::from_secs(600);
            seed_round(&mut protocol, 4, &[9001], &[1002]).await;

            let events = protocol.tick().await;

            assert!(events.is_empty(), "got {events:?}");
            assert!(
                protocol
                    .state_store
                    .load(SECRET_ID, StateKey::SharingRound { version: 4 })
                    .await
                    .expect("load")
                    .is_some(),
                "the round is still in flight"
            );
        });
    }

    /// The publisher drops a departing member's row once that member has
    /// acknowledged the version excluding it.
    ///
    /// Reconciliation normally runs when a roster *arrives*, but the device
    /// that ran the removal never receives the roster it just sent. Without a
    /// publisher-side pass it would keep the flagged row forever and keep
    /// addressing a member that has already torn itself down — the removal
    /// would converge everywhere except on the device that ordered it.
    #[test]
    fn the_publisher_drops_a_departing_member_once_it_acknowledges() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 7, &[9001], &[1002, 1003]).await;

            for (id, status) in [
                (1002u64, crate::protocol::types::ChannelStatus::Paired),
                (1003, crate::protocol::types::ChannelStatus::Unpairing),
            ] {
                protocol
                    .channel_store
                    .save(
                        SECRET_ID,
                        crate::protocol::types::ChannelRecord::Replica(
                            crate::protocol::types::ReplicaMember {
                                channel_id: ChannelId(5001),
                                replica_id: ReplicaId(id),
                                transports: vec![derec_proto::TransportProtocol {
                                    uri: "https://peer.example".to_owned(),
                                    protocol: derec_proto::Protocol::Https as i32,
                                }],
                                communication_info: std::collections::HashMap::new(),
                                role: crate::protocol::types::ReplicaRole::Destination,
                                status,
                                created_at: 0,
                            },
                        ),
                    )
                    .await
                    .expect("seed member");
            }

            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 7,
                },
                DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1002,
                    secret_id: SECRET_ID,
                    version: 7,
                    status: 0,
                    memo: String::new(),
                },
                DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1003,
                    secret_id: SECRET_ID,
                    version: 7,
                    status: 0,
                    memo: String::new(),
                },
            ];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            let remaining: Vec<u64> = protocol
                .channel_store
                .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
                .await
                .expect("roster")
                .into_iter()
                .map(|m| m.replica_id.0)
                .collect();
            assert_eq!(
                remaining,
                vec![1002],
                "the acknowledged departing member is gone; the other survives"
            );
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ReplicaRemoved { replica_id } if *replica_id == 1003
                )),
                "the removal is reported to the application; got {events:?}"
            );
        });
    }

    /// The departed members' rows go in one call, so a store failure removes
    /// none of them. The round is then kept rather than completed, and the
    /// next call completes it and reports both departures.
    #[test]
    fn a_failed_member_removal_keeps_the_round_for_a_later_call() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 7, &[9001], &[1002, 1003]).await;
            for id in [1002u64, 1003] {
                protocol
                    .channel_store
                    .save(
                        SECRET_ID,
                        crate::protocol::types::ChannelRecord::Replica(
                            crate::protocol::types::ReplicaMember {
                                channel_id: ChannelId(5001),
                                replica_id: ReplicaId(id),
                                transports: vec![derec_proto::TransportProtocol {
                                    uri: "https://peer.example".to_owned(),
                                    protocol: derec_proto::Protocol::Https as i32,
                                }],
                                communication_info: std::collections::HashMap::new(),
                                role: crate::protocol::types::ReplicaRole::Destination,
                                status: crate::protocol::types::ChannelStatus::Unpairing,
                                created_at: 0,
                            },
                        ),
                    )
                    .await
                    .expect("seed member");
            }
            *protocol.channel_store.fail_remove_many.lock().unwrap() = true;

            let mut events = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(9001),
                version: 7,
            }];
            for id in [1002u64, 1003] {
                events.push(DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: id,
                    secret_id: SECRET_ID,
                    version: 7,
                    status: 0,
                    memo: String::new(),
                });
            }
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert!(
                !events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::SharingComplete { .. } | DeRecEvent::ReplicaRemoved { .. }
                )),
                "the round does not complete while its departures cannot be removed; got {events:?}"
            );
            assert_eq!(protocol.channel_store.member_rows.lock().unwrap().len(), 2);

            *protocol.channel_store.fail_remove_many.lock().unwrap() = false;
            let mut events = Vec::new();
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 7, .. })),
                "the kept round completes on the next call; got {events:?}"
            );
            let mut removed: Vec<u64> = events
                .iter()
                .filter_map(|e| match e {
                    DeRecEvent::ReplicaRemoved { replica_id } => Some(*replica_id),
                    _ => None,
                })
                .collect();
            removed.sort_unstable();
            assert_eq!(removed, vec![1002, 1003]);
            assert!(
                protocol
                    .channel_store
                    .member_rows
                    .lock()
                    .unwrap()
                    .is_empty()
            );
        });
    }

    /// A member flagged as leaving that has **not** acknowledged keeps its row.
    ///
    /// Its departure is not complete until it has seen the excluding version,
    /// and dropping it early would stop the publisher addressing the very
    /// member it still needs to reach.
    #[test]
    fn a_departing_member_that_has_not_answered_is_kept() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 7, &[9001], &[1002]).await;

            protocol
                .channel_store
                .save(
                    SECRET_ID,
                    crate::protocol::types::ChannelRecord::Replica(
                        crate::protocol::types::ReplicaMember {
                            channel_id: ChannelId(5001),
                            replica_id: ReplicaId(1003),
                            transports: vec![derec_proto::TransportProtocol {
                                uri: "https://peer.example".to_owned(),
                                protocol: derec_proto::Protocol::Https as i32,
                            }],
                            communication_info: std::collections::HashMap::new(),
                            role: crate::protocol::types::ReplicaRole::Destination,
                            status: crate::protocol::types::ChannelStatus::Unpairing,
                            created_at: 0,
                        },
                    ),
                )
                .await
                .expect("seed member");

            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 7,
                },
                DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1002,
                    secret_id: SECRET_ID,
                    version: 7,
                    status: 0,
                    memo: String::new(),
                },
            ];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            let remaining: Vec<u64> = protocol
                .channel_store
                .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
                .await
                .expect("roster")
                .into_iter()
                .map(|m| m.replica_id.0)
                .collect();
            assert_eq!(
                remaining,
                vec![1003],
                "an unacknowledged departure leaves the row in place"
            );
        });
    }

    /// The regression a shared group channel creates: two members answering on
    /// one channel must settle independently. Keyed on `ChannelId` they would
    /// collapse, and the first ack would complete the round for both.
    #[test]
    fn members_on_one_channel_settle_independently() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 4, &[9001], &[1002, 1003]).await;

            // Only member 1002 answers.
            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 4,
                },
                DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1002,
                    secret_id: SECRET_ID,
                    version: 4,
                    status: 0,
                    memo: String::new(),
                },
            ];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { .. })),
                "the round must stay open while member 1003 has not answered"
            );

            // 1003 answers on the same channel; now the round closes.
            let mut events = vec![DeRecEvent::ReplicaSecretAcked {
                channel_id: ChannelId(5001),
                from_replica_id: 1003,
                secret_id: SECRET_ID,
                version: 4,
                status: 0,
                memo: String::new(),
            }];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            let sync = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::ReplicaSyncComplete { synced, behind, .. } => {
                        Some((synced.clone(), behind.clone()))
                    }
                    _ => None,
                })
                .expect("replica leg must report its own completion");
            assert_eq!(sync, (vec![1002, 1003], vec![]));
        });
    }

    /// F2: a member that never answers is `behind`, and does not fail the
    /// round — the helper leg alone decides `threshold_met`.
    #[test]
    fn an_unreachable_member_leaves_the_round_successful() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 4, &[9001, 9002], &[1003]).await;

            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 4,
                },
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9002),
                    version: 4,
                },
                DeRecEvent::ReplicaSyncFailed {
                    replica_id: 1003,
                    version: 4,
                    reason: "transport unreachable".to_owned(),
                },
            ];
            // A dispatch failure never entered `pending_replicas`, so the round
            // is settled by the helper leg alone; drain the member by hand to
            // mirror what `start` records at dispatch time.
            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: 4,
                        pending: HashSet::from([ChannelId(9001), ChannelId(9002)]),
                        confirmed: HashSet::new(),
                        failed: HashSet::new(),
                        pending_replicas: HashSet::new(),
                        synced_replicas: HashSet::new(),
                        behind_replicas: HashSet::from([ReplicaId(1003)]),
                        started_at: now_secs(),
                        keep_version: None,
                        threshold: None,
                    })),
                )
                .await
                .expect("seed");
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            let complete = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::SharingComplete { threshold_met, .. } => Some(*threshold_met),
                    _ => None,
                })
                .expect("helper leg must complete");
            assert!(
                complete,
                "an unreachable replica must not fail the helper round"
            );

            let sync = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::ReplicaSyncComplete { synced, behind, .. } => {
                        Some((synced.clone(), behind.clone()))
                    }
                    _ => None,
                })
                .expect("replica leg must report its own completion");
            assert_eq!(sync, (vec![], vec![1003]), "the member is reported behind");
        });
    }

    /// F1: a member refusing with a conflict lands in `behind`, reported
    /// separately from the helper leg's own verdict.
    #[test]
    fn a_conflicting_member_is_reported_behind() {
        run_async(async {
            let mut protocol = build(3);
            seed_round(&mut protocol, 4, &[9001, 9002, 9003], &[1002, 1003]).await;

            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 4,
                },
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9002),
                    version: 4,
                },
                DeRecEvent::ShareRejected {
                    channel_id: ChannelId(9003),
                    version: 4,
                    status: derec_proto::StatusEnum::VersionConflict as i32,
                    memo: "conflict".to_owned(),
                },
                DeRecEvent::ReplicaSyncRejected {
                    replica_id: 1002,
                    secret_id: SECRET_ID,
                    version: 4,
                    status: derec_proto::StatusEnum::VersionConflict as i32,
                    memo: "conflict".to_owned(),
                },
                DeRecEvent::ReplicaSecretAcked {
                    channel_id: ChannelId(5001),
                    from_replica_id: 1003,
                    secret_id: SECRET_ID,
                    version: 4,
                    status: 0,
                    memo: String::new(),
                },
            ];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            let (confirmed, failed, threshold_met) = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::SharingComplete {
                        confirmed_count,
                        failed_count,
                        threshold_met,
                        ..
                    } => Some((*confirmed_count, *failed_count, *threshold_met)),
                    _ => None,
                })
                .expect("helper leg must complete");
            assert_eq!((confirmed, failed), (2, 1));
            assert!(!threshold_met, "2 of 3 helpers is under a threshold of 3");

            let sync = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::ReplicaSyncComplete { synced, behind, .. } => {
                        Some((synced.clone(), behind.clone()))
                    }
                    _ => None,
                })
                .expect("replica leg must report its own completion");
            assert_eq!(sync, (vec![1003], vec![1002]));
        });
    }

    /// A publish with no replica group stays silent on the replica leg rather
    /// than reporting an empty one.
    #[test]
    fn a_helpers_only_round_emits_no_replica_summary() {
        run_async(async {
            let mut protocol = build(2);
            seed_round(&mut protocol, 2, &[9001], &[]).await;

            let mut events = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(9001),
                version: 2,
            }];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { .. })),
                "the helper leg still completes"
            );
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ReplicaSyncComplete { .. })),
                "a round with no replica leg must not report one"
            );
        });
    }
}

mod timeout {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::tests::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::protocol::types::Timeouts;
    use derec_proto::DeRecMessage;
    use std::collections::HashSet;
    use std::time::Duration;

    const SECRET_ID: u64 = 0x7180;

    type TestProtocol = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        NoopTransport,
    >;

    fn build_with(timeouts: Timeouts) -> TestProtocol {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .with_timeouts(timeouts)
            .build()
            .expect("test protocol builds")
    }

    /// An envelope whose timestamp is `age_secs` in the past.
    fn envelope_aged(age_secs: u64) -> DeRecMessage {
        DeRecMessage {
            timestamp: Some(prost_types::Timestamp {
                seconds: now_secs().saturating_sub(age_secs) as i64,
                nanos: 0,
            }),
            ..Default::default()
        }
    }

    /// The defaults are load-bearing — every binding omits fields and relies
    /// on these, so a change here changes behaviour for all seven surfaces.
    #[test]
    fn defaults_are_the_documented_values() {
        let d = Timeouts::default();
        assert_eq!(d.inbound_message, Duration::from_secs(300));
        assert_eq!(d.sharing_round, Duration::from_secs(60));
        assert_eq!(d.unpair_ack, Duration::from_secs(60));
        assert_eq!(
            d.expired_channels,
            crate::protocol::ExpiredChannelCleanup::Enabled {
                timeout_in_secs: 300
            }
        );
    }

    /// The staleness boundary had no test at all before the split, despite
    /// being the replay-defence window.
    #[test]
    fn inbound_message_bounds_how_stale_an_envelope_may_be() {
        let protocol = build_with(Timeouts {
            inbound_message: Duration::from_secs(120),
            ..Default::default()
        });

        assert!(
            !protocol.is_message_expired(&envelope_aged(60), ChannelId(1)),
            "an envelope inside the window is accepted"
        );
        assert!(
            !protocol.is_message_expired(&envelope_aged(120), ChannelId(1)),
            "the boundary itself is inclusive"
        );
        assert!(
            protocol.is_message_expired(&envelope_aged(121), ChannelId(1)),
            "an envelope past the window is discarded"
        );
    }

    /// A timestampless envelope is not judged stale — the timestamp
    /// invariant is enforced elsewhere, and treating "absent" as "expired"
    /// here would mask it.
    #[test]
    fn an_envelope_without_a_timestamp_is_not_expired() {
        let protocol = build_with(Timeouts::default());
        let envelope = DeRecMessage {
            timestamp: None,
            ..Default::default()
        };
        assert!(!protocol.is_message_expired(&envelope, ChannelId(1)));
    }

    /// **The point of the split.** Shortening the liveness budgets must not
    /// narrow the security boundary. Under the old single knob, asking for a
    /// 1-second sharing round also meant refusing every message more than a
    /// second old.
    #[test]
    fn shortening_the_liveness_budgets_leaves_the_replay_window_alone() {
        let protocol = build_with(Timeouts {
            sharing_round: Duration::from_secs(1),
            unpair_ack: Duration::from_secs(1),
            ..Default::default()
        });

        assert_eq!(protocol.timeouts.inbound_message, Duration::from_secs(300));
        assert!(
            !protocol.is_message_expired(&envelope_aged(290), ChannelId(1)),
            "a message well inside the default replay window is still accepted \
             even though both liveness budgets are one second"
        );
    }

    /// And the converse: a long replay window does not keep a stalled round
    /// open. Both directions matter — one knob meant either mistake was
    /// reachable by tuning the other concern.
    #[test]
    fn a_long_replay_window_does_not_extend_the_sharing_round() {
        run_async(async {
            let mut protocol = build_with(Timeouts {
                inbound_message: Duration::from_secs(3600),
                sharing_round: Duration::from_secs(1),
                ..Default::default()
            });

            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: 1,
                        pending: [ChannelId(9001)].into_iter().collect(),
                        confirmed: HashSet::new(),
                        failed: HashSet::new(),
                        pending_replicas: HashSet::new(),
                        synced_replicas: HashSet::new(),
                        behind_replicas: HashSet::new(),
                        started_at: now_secs().saturating_sub(30),
                        keep_version: None,
                        threshold: None,
                    })),
                )
                .await
                .expect("seed round");

            let events = protocol.tick().await;
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::SharingComplete { version: 1, .. })),
                "the round times out on its own budget, not the replay window; got {events:?}"
            );
        });
    }
}
