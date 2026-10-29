// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::protocol::DeRecProtocol;
use crate::protocol::events::DeRecEvent;
use crate::protocol::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore,
};
use crate::protocol::types::{StateItem, StateKey};
use crate::types::ChannelId;
use crate::utils::now_secs;
use derec_proto::StatusEnum;

mod proof_cleanup {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::tests::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::protocol::traits::ShareStoreFuture;
    use crate::protocol::types::Share;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    const SECRET_ID: u64 = 0xBEEF;

    /// Wraps [`InMemShareStore`] and counts the `(channel_id, version)`
    /// entries passed to `remove_versions_many`, to catch a cleanup path
    /// invoked more than once for the same channel failure.
    #[derive(Default, Clone)]
    struct CountingShareStore {
        inner: InMemShareStore,
        remove_versions_calls: Arc<Mutex<Vec<(ChannelId, u32)>>>,
    }

    impl CountingShareStore {
        fn remove_versions_call_count(&self, channel_id: ChannelId, version: u32) -> usize {
            self.remove_versions_calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(c, v)| *c == channel_id && *v == version)
                .count()
        }
    }

    impl DeRecShareStore for CountingShareStore {
        fn load(
            &self,
            secret_id: u64,
            channel_id: ChannelId,
            versions: &[u32],
        ) -> ShareStoreFuture<'_, Vec<Share>> {
            self.inner.load(secret_id, channel_id, versions)
        }
        fn load_many(
            &self,
            secret_id: u64,
            channel_ids: &[ChannelId],
            versions: &[u32],
        ) -> ShareStoreFuture<'_, Vec<(ChannelId, Share)>> {
            self.inner.load_many(secret_id, channel_ids, versions)
        }
        fn load_all(
            &self,
            secret_id: u64,
            channel_ids: &[ChannelId],
        ) -> ShareStoreFuture<'_, Vec<Share>> {
            self.inner.load_all(secret_id, channel_ids)
        }
        fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>> {
            self.inner.latest_version(secret_id)
        }
        fn save(
            &mut self,
            secret_id: u64,
            channel_id: ChannelId,
            share: Share,
        ) -> ShareStoreFuture<'_, ()> {
            self.inner.save(secret_id, channel_id, share)
        }
        fn remove_channel(
            &mut self,
            secret_id: u64,
            channel_id: ChannelId,
        ) -> ShareStoreFuture<'_, ()> {
            self.inner.remove_channel(secret_id, channel_id)
        }
        fn remove_versions(
            &mut self,
            secret_id: u64,
            channel_id: ChannelId,
            versions: &[u32],
        ) -> ShareStoreFuture<'_, ()> {
            self.inner.remove_versions(secret_id, channel_id, versions)
        }
        fn remove_versions_many(
            &mut self,
            secret_id: u64,
            entries: &[(ChannelId, Vec<u32>)],
        ) -> ShareStoreFuture<'_, ()> {
            {
                let mut calls = self.remove_versions_calls.lock().unwrap();
                for (channel_id, versions) in entries {
                    calls.extend(versions.iter().map(|v| (*channel_id, *v)));
                }
            }
            self.inner.remove_versions_many(secret_id, entries)
        }
        fn keep_version(&self, secret_id: u64, version: u32) -> ShareStoreFuture<'_, u32> {
            self.inner.keep_version(secret_id, version)
        }
    }

    type CountingTestProtocol = DeRecProtocol<
        InMemChannelStore,
        CountingShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        NoopTransport,
    >;

    fn build_counting(threshold: usize, shares: CountingShareStore) -> CountingTestProtocol {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(shares)
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(threshold)
            .build()
            .expect("test protocol builds")
    }

    type TestProtocol = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        NoopTransport,
    >;

    fn build(threshold: usize, shares: InMemShareStore) -> TestProtocol {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(shares)
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(threshold)
            .build()
            .expect("test protocol builds")
    }

    async fn seed_round(protocol: &mut TestProtocol, version: u32, helpers: &[u64]) {
        protocol
            .state_store
            .save(
                SECRET_ID,
                StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                    version,
                    pending: helpers.iter().copied().map(ChannelId).collect(),
                    confirmed: HashSet::new(),
                    failed: HashSet::new(),
                    pending_replicas: HashSet::new(),
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

    /// Seed the owner's proof for `channel_id` at `version`.
    fn seed_proof(shares: &InMemShareStore, channel_id: u64, version: u32) {
        shares.data.lock().unwrap().insert(
            (SECRET_ID, channel_id, version),
            Share {
                secret_id: SECRET_ID,
                version,
                bytes: vec![0xAB],
                subshares: None,
                threshold: None,
            },
        );
    }

    fn has_proof(shares: &InMemShareStore, channel_id: u64, version: u32) -> bool {
        shares
            .data
            .lock()
            .unwrap()
            .contains_key(&(SECRET_ID, channel_id, version))
    }

    fn stored_round(
        protocol: &TestProtocol,
        version: u32,
    ) -> Option<crate::protocol::types::SharingRoundState> {
        match protocol
            .state_store
            .data
            .lock()
            .unwrap()
            .get(&(SECRET_ID, StateKey::SharingRound { version }))
        {
            Some(StateItem::SharingRound(round)) => Some((**round).clone()),
            _ => None,
        }
    }

    fn rejected(channel_id: u64, version: u32) -> DeRecEvent {
        DeRecEvent::ShareRejected {
            channel_id: ChannelId(channel_id),
            version,
            status: StatusEnum::Fail as i32,
            memo: "rejected".to_owned(),
        }
    }

    fn sharing_complete(events: &[DeRecEvent]) -> Vec<bool> {
        events
            .iter()
            .filter_map(|e| match e {
                DeRecEvent::SharingComplete { threshold_met, .. } => Some(*threshold_met),
                _ => None,
            })
            .collect()
    }

    /// A round whose save fails gives up no proof: the failure it applied is
    /// not recorded, so acting on it would leave a proof missing for a helper
    /// the stored round still waits on. Retrying the answer once the store
    /// recovers settles it.
    #[test]
    fn a_round_that_cannot_be_saved_gives_up_no_proof() {
        run_async(async {
            let shares = InMemShareStore::default();
            seed_proof(&shares, 9001, 4);
            seed_proof(&shares, 9002, 4);
            let mut protocol = build(2, shares.clone());
            seed_round(&mut protocol, 4, &[9001, 9002]).await;

            *protocol.state_store.fail_writes.lock().unwrap() = true;
            protocol
                .update_sharing_round(&mut vec![rejected(9002, 4)])
                .await
                .expect_err("the round cannot be saved");

            assert!(has_proof(&shares, 9002, 4));
            let round = stored_round(&protocol, 4).expect("the round stays stored");
            assert!(round.pending.contains(&ChannelId(9002)));

            *protocol.state_store.fail_writes.lock().unwrap() = false;
            protocol
                .update_sharing_round(&mut vec![rejected(9002, 4)])
                .await
                .expect("the rounds are settled");

            assert!(!has_proof(&shares, 9002, 4));
            let round = stored_round(&protocol, 4).expect("the round stays open");
            assert!(round.failed.contains(&ChannelId(9002)));
        });
    }

    /// A timed-out round whose save fails reports no timeout, so the timeout
    /// is reported once, by the call that records it: the next `tick`.
    #[test]
    fn a_timed_out_round_that_cannot_be_saved_reports_no_timeout() {
        run_async(async {
            let shares = InMemShareStore::default();
            seed_proof(&shares, 9001, 4);
            let mut protocol = build(2, shares.clone());
            protocol.timeouts.sharing_round = std::time::Duration::from_secs(60);
            seed_round(&mut protocol, 4, &[9001]).await;
            if let Some(StateItem::SharingRound(round)) = protocol
                .state_store
                .data
                .lock()
                .unwrap()
                .get_mut(&(SECRET_ID, StateKey::SharingRound { version: 4 }))
            {
                round.started_at = now_secs().saturating_sub(600);
            }

            *protocol.state_store.fail_writes.lock().unwrap() = true;
            let events = protocol.tick().await;

            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ShareRejected { .. })),
                "got {events:?}"
            );
            assert!(has_proof(&shares, 9001, 4));
            assert!(stored_round(&protocol, 4).is_some());

            *protocol.state_store.fail_writes.lock().unwrap() = false;
            let events = protocol.tick().await;

            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ShareRejected { .. })),
                "got {events:?}"
            );
            assert!(!has_proof(&shares, 9001, 4));
        });
    }

    /// A completed round whose removal fails is not reported complete: the
    /// stored round still waits on the helper, and reporting it now would
    /// report it twice.
    #[test]
    fn a_round_that_cannot_be_removed_does_not_complete() {
        run_async(async {
            let shares = InMemShareStore::default();
            seed_proof(&shares, 9001, 4);
            let mut protocol = build(2, shares.clone());
            seed_round(&mut protocol, 4, &[9001]).await;
            let confirmed = || {
                vec![DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 4,
                }]
            };

            *protocol.state_store.fail_writes.lock().unwrap() = true;
            let mut events = confirmed();
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect_err("the round cannot be removed");

            assert!(sharing_complete(&events).is_empty(), "got {events:?}");
            let round = stored_round(&protocol, 4).expect("the round stays stored");
            assert!(round.pending.contains(&ChannelId(9001)));

            *protocol.state_store.fail_writes.lock().unwrap() = false;
            let mut events = confirmed();
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert_eq!(sharing_complete(&events), vec![false]);
            assert!(stored_round(&protocol, 4).is_none());
        });
    }

    /// A round whose helpers' weights cannot be read is kept, answers and
    /// all, and completes on a later call rather than reporting a
    /// `threshold_met` it could not compute.
    #[test]
    fn a_round_whose_weights_cannot_be_read_completes_later() {
        run_async(async {
            let shares = InMemShareStore::default();
            let mut protocol = build(2, shares.clone());
            seed_round(&mut protocol, 4, &[9001, 9002]).await;

            *shares.fail_load_many.lock().unwrap() = true;
            let mut events: Vec<DeRecEvent> = [9001, 9002]
                .into_iter()
                .map(|channel| DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(channel),
                    version: 4,
                })
                .collect();
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert!(sharing_complete(&events).is_empty(), "got {events:?}");
            let round = stored_round(&protocol, 4).expect("the round is kept");
            assert!(round.pending.is_empty());
            assert_eq!(round.confirmed.len(), 2);

            *shares.fail_load_many.lock().unwrap() = false;
            let mut events = Vec::new();
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert_eq!(sharing_complete(&events), vec![true]);
            assert!(stored_round(&protocol, 4).is_none());
        });
    }

    /// An inbound rejection removes the failed channel's proof; the
    /// confirmed channel's proof is untouched.
    #[test]
    fn rejected_channel_proof_is_removed_and_confirmed_kept() {
        run_async(async {
            let shares = InMemShareStore::default();
            seed_proof(&shares, 9001, 4);
            seed_proof(&shares, 9002, 4);
            let mut protocol = build(2, shares.clone());
            seed_round(&mut protocol, 4, &[9001, 9002]).await;

            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 4,
                },
                DeRecEvent::ShareRejected {
                    channel_id: ChannelId(9002),
                    version: 4,
                    status: StatusEnum::Fail as i32,
                    memo: "rejected".to_owned(),
                },
            ];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert!(
                has_proof(&shares, 9001, 4),
                "the confirmed channel's proof survives"
            );
            assert!(
                !has_proof(&shares, 9002, 4),
                "the rejected channel's proof is removed"
            );
        });
    }

    /// A channel that times out loses its proof exactly like an explicit
    /// rejection does.
    #[test]
    fn timed_out_channel_proof_is_removed() {
        run_async(async {
            let shares = InMemShareStore::default();
            seed_proof(&shares, 9001, 4);
            let mut protocol = build(2, shares.clone());
            protocol.timeouts.sharing_round = std::time::Duration::from_secs(60);
            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: 4,
                        pending: [ChannelId(9001)].into_iter().collect(),
                        confirmed: HashSet::new(),
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

            let _events = protocol.tick().await;

            assert!(
                !has_proof(&shares, 9001, 4),
                "the timed-out channel's proof is removed"
            );
        });
    }

    /// Any rejection status removes the proof, not only `Fail` — a store
    /// rate limit (`TooFrequent`) is just as final for the owner's proof
    /// as an explicit failure, and only the round's version is touched.
    #[test]
    fn store_refusal_rejection_removes_the_proof() {
        run_async(async {
            let shares = InMemShareStore::default();
            seed_proof(&shares, 9002, 4);
            seed_proof(&shares, 9002, 3);
            let mut protocol = build(2, shares.clone());
            seed_round(&mut protocol, 4, &[9001, 9002]).await;

            let mut events = vec![DeRecEvent::ShareRejected {
                channel_id: ChannelId(9002),
                version: 4,
                status: StatusEnum::TooFrequent as i32,
                memo: "too frequent".to_owned(),
            }];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert!(
                !has_proof(&shares, 9002, 4),
                "a TooFrequent rejection removes the proof just like Fail does"
            );
            assert!(
                has_proof(&shares, 9002, 3),
                "an older version's proof is untouched by this round settling"
            );
        });
    }

    /// A late `ShareConfirmed` for a channel whose round already settled as
    /// failed must not bring its proof back.
    #[test]
    fn late_confirmation_after_failure_does_not_restore_a_proof() {
        run_async(async {
            let shares = InMemShareStore::default();
            seed_proof(&shares, 9001, 4);
            seed_proof(&shares, 9002, 4);
            let mut protocol = build(2, shares.clone());
            seed_round(&mut protocol, 4, &[9001, 9002]).await;

            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9001),
                    version: 4,
                },
                DeRecEvent::ShareRejected {
                    channel_id: ChannelId(9002),
                    version: 4,
                    status: StatusEnum::Fail as i32,
                    memo: "rejected".to_owned(),
                },
            ];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");
            assert!(
                protocol
                    .state_store
                    .load(SECRET_ID, StateKey::SharingRound { version: 4 })
                    .await
                    .expect("load")
                    .is_none(),
                "the round closed: both channels are settled"
            );
            assert!(!has_proof(&shares, 9002, 4));

            // The round row is gone, so this reply is late: nothing matches
            // it, and it must not resurrect the proof that was just removed.
            let mut late = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(9002),
                version: 4,
            }];
            protocol
                .update_sharing_round(&mut late)
                .await
                .expect("the rounds are settled");

            assert!(
                !has_proof(&shares, 9002, 4),
                "a late confirmation after the failure must not re-create the proof"
            );
        });
    }

    /// A channel rejected and then confirmed in the same batch, while the
    /// round is still open (other channels still pending), must count only
    /// as failed — not in both `failed` and `confirmed`, which would let
    /// `threshold_met` include a channel whose proof was just removed.
    #[test]
    fn rejected_then_confirmed_within_open_round_counts_only_as_failed() {
        run_async(async {
            let shares = InMemShareStore::default();
            seed_proof(&shares, 9002, 4);
            let mut protocol = build(2, shares.clone());
            seed_round(&mut protocol, 4, &[9001, 9002, 9003]).await;

            let mut events = vec![
                DeRecEvent::ShareRejected {
                    channel_id: ChannelId(9002),
                    version: 4,
                    status: StatusEnum::Fail as i32,
                    memo: "rejected".to_owned(),
                },
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(9002),
                    version: 4,
                },
            ];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert!(
                !has_proof(&shares, 9002, 4),
                "the rejection still removes the proof"
            );

            let round = protocol
                .state_store
                .load(SECRET_ID, StateKey::SharingRound { version: 4 })
                .await
                .expect("load")
                .expect("round still open: 9001 and 9003 have not answered");
            let StateItem::SharingRound(round) = round else {
                panic!("expected a SharingRound state item");
            };
            assert!(
                round.failed.contains(&ChannelId(9002)),
                "the channel is recorded as failed"
            );
            assert!(
                !round.confirmed.contains(&ChannelId(9002)),
                "the later confirmation must not also count it as confirmed"
            );
        });
    }

    /// A `tick()` first fails a timed-out channel in the timeout sweep, then
    /// hands the very `ShareRejected` it just produced to round settlement.
    /// The channel must be dropped from the store exactly once, not once by
    /// each stage.
    #[test]
    fn timed_out_channel_proof_is_removed_once() {
        run_async(async {
            let shares = CountingShareStore::default();
            let mut protocol = build_counting(2, shares.clone());
            protocol.timeouts.sharing_round = std::time::Duration::from_secs(60);
            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: 4,
                        pending: [ChannelId(9001)].into_iter().collect(),
                        confirmed: HashSet::new(),
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

            let _events = protocol.tick().await;

            assert_eq!(
                shares.remove_versions_call_count(ChannelId(9001), 4),
                1,
                "the timeout sweep and round settlement must not both drop the same proof"
            );
        });
    }

    /// Two `ShareRejected` events for the same channel and version in one
    /// batch — a genuine duplicate, not a timeout echo — must still only
    /// remove the proof once: the second one finds the channel already out
    /// of `pending`.
    #[test]
    fn duplicate_share_rejected_does_not_double_remove_the_proof() {
        run_async(async {
            let shares = CountingShareStore::default();
            let mut protocol = build_counting(2, shares.clone());
            protocol
                .state_store
                .save(
                    SECRET_ID,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: 4,
                        pending: [ChannelId(9001)].into_iter().collect(),
                        confirmed: HashSet::new(),
                        failed: HashSet::new(),
                        pending_replicas: HashSet::new(),
                        synced_replicas: HashSet::new(),
                        behind_replicas: HashSet::new(),
                        started_at: now_secs(),
                        keep_version: None,
                        threshold: None,
                    })),
                )
                .await
                .expect("seed round");

            let mut events = vec![
                DeRecEvent::ShareRejected {
                    channel_id: ChannelId(9001),
                    version: 4,
                    status: StatusEnum::Fail as i32,
                    memo: "rejected".to_owned(),
                },
                DeRecEvent::ShareRejected {
                    channel_id: ChannelId(9001),
                    version: 4,
                    status: StatusEnum::Fail as i32,
                    memo: "duplicate".to_owned(),
                },
            ];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert_eq!(
                shares.remove_versions_call_count(ChannelId(9001), 4),
                1,
                "a duplicated inbound rejection must not remove the proof twice"
            );
        });
    }
}

mod weighted_tally {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::tests::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::protocol::types::Share;
    use prost::Message as _;
    use std::collections::HashSet;

    const SECRET_ID: u64 = 0x5EED;
    const VERSION: u32 = 3;
    const THRESHOLD: usize = 3;
    const A: u64 = 31;
    const B: u64 = 32;
    const C: u64 = 33;
    const D: u64 = 34;

    type TestProtocol = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        NoopTransport,
    >;

    /// A protocol whose share store holds the owner's tracking share for each
    /// of `A`..`D` at [`VERSION`], split with `A` at weight 2, and an open
    /// round awaiting all four.
    async fn rig() -> (TestProtocol, InMemShareStore) {
        rig_with(THRESHOLD, None).await
    }

    /// [`rig`] with the builder's threshold and the round's recorded one set
    /// separately. The shares are always split at [`THRESHOLD`].
    async fn rig_with(
        builder_threshold: usize,
        round_threshold: Option<u32>,
    ) -> (TestProtocol, InMemShareStore) {
        let channels = [
            (ChannelId(A), 2),
            (ChannelId(B), 1),
            (ChannelId(C), 1),
            (ChannelId(D), 1),
        ];
        let split = crate::primitives::sharing::request::split(
            &channels,
            SECRET_ID,
            VERSION,
            b"weighted tally secret",
            THRESHOLD,
        )
        .expect("weighted split");
        let shares = InMemShareStore::default();
        for (channel_id, committed) in &split.shares {
            shares.data.lock().unwrap().insert(
                (SECRET_ID, channel_id.0, VERSION),
                Share {
                    secret_id: SECRET_ID,
                    version: VERSION,
                    bytes: committed.encode_to_vec(),
                    subshares: crate::protocol::handlers::sharing::subshare_count(committed),
                    threshold: None,
                },
            );
        }

        let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(shares.clone())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(builder_threshold)
            .build()
            .expect("test protocol builds");
        protocol
            .state_store
            .save(
                SECRET_ID,
                StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                    version: VERSION,
                    pending: channels.iter().map(|&(c, _)| c).collect(),
                    confirmed: HashSet::new(),
                    failed: HashSet::new(),
                    pending_replicas: HashSet::new(),
                    synced_replicas: HashSet::new(),
                    behind_replicas: HashSet::new(),
                    started_at: now_secs(),
                    keep_version: None,
                    threshold: round_threshold,
                })),
            )
            .await
            .expect("seed round");
        (protocol, shares)
    }

    fn answers(confirmed: &[u64], rejected: &[u64]) -> Vec<DeRecEvent> {
        let mut events: Vec<DeRecEvent> = confirmed
            .iter()
            .map(|&c| DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(c),
                version: VERSION,
            })
            .collect();
        events.extend(rejected.iter().map(|&c| DeRecEvent::ShareRejected {
            channel_id: ChannelId(c),
            version: VERSION,
            status: StatusEnum::Fail as i32,
            memo: "rejected".to_owned(),
        }));
        events
    }

    fn threshold_met(events: &[DeRecEvent]) -> bool {
        events
            .iter()
            .find_map(|e| match e {
                DeRecEvent::SharingComplete {
                    version: VERSION,
                    threshold_met,
                    ..
                } => Some(*threshold_met),
                _ => None,
            })
            .expect("the round completes once every helper has answered")
    }

    #[test]
    fn threshold_met_counts_confirmed_weight() {
        run_async(async {
            // A (2 subshares) plus B (1 subshare) reach t = 3 with two helpers.
            let (mut protocol, _) = rig().await;
            let mut events = answers(&[A, B], &[C, D]);
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");
            assert!(
                threshold_met(&events),
                "A + B hold 3 subshares; got {events:?}"
            );

            // Three weight-1 helpers reach t = 3 without A.
            let (mut protocol, _) = rig().await;
            let mut events = answers(&[B, C, D], &[A]);
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");
            assert!(
                threshold_met(&events),
                "B + C + D hold 3 subshares; got {events:?}"
            );

            // Two weight-1 helpers hold 2 subshares, below t = 3.
            let (mut protocol, _) = rig().await;
            let mut events = answers(&[B, C], &[A, D]);
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");
            assert!(
                !threshold_met(&events),
                "B + C hold 2 subshares; got {events:?}"
            );
        });
    }

    /// The round is judged against the threshold it split at, whatever the
    /// builder says now.
    #[test]
    fn threshold_met_follows_the_rounds_own_threshold() {
        run_async(async {
            // B + C hold 2 subshares: enough for a builder at 2, not for the
            // round's 3.
            let (mut protocol, _) = rig_with(2, Some(3)).await;
            let mut events = answers(&[B, C], &[A, D]);
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");
            assert!(!threshold_met(&events), "got {events:?}");

            // A + B hold 3 subshares: short of a builder at 4, enough for the
            // round's 3.
            let (mut protocol, _) = rig_with(4, Some(3)).await;
            let mut events = answers(&[A, B], &[C, D]);
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");
            assert!(threshold_met(&events), "got {events:?}");

            // A round with no recorded threshold falls back to the builder's.
            let (mut protocol, _) = rig_with(2, None).await;
            let mut events = answers(&[B, C], &[A, D]);
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");
            assert!(threshold_met(&events), "got {events:?}");
        });
    }

    /// Completing a round reads every confirmed helper's tracking share in a
    /// single call, not one call per helper.
    #[test]
    fn completing_a_round_loads_the_tracking_shares_once() {
        run_async(async {
            let (mut protocol, shares) = rig().await;
            let mut events = answers(&[A, B, C], &[D]);
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert!(threshold_met(&events), "got {events:?}");
            assert_eq!(*shares.load_many_calls.lock().unwrap(), 1);
            assert_eq!(*shares.load_calls.lock().unwrap(), 0);
        });
    }

    #[test]
    fn threshold_met_counts_a_missing_tracking_share_as_one() {
        run_async(async {
            let (mut protocol, shares) = rig().await;
            shares.data.lock().unwrap().remove(&(SECRET_ID, A, VERSION));

            let mut events = answers(&[A, B, C], &[D]);
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");
            assert!(
                threshold_met(&events),
                "A's weight is unknown without its tracking share and counts as 1, so A + B + C hold 3 subshares; got {events:?}"
            );
        });
    }
}

mod keep_version_proof {
    use super::*;
    use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
    use crate::protocol::DeRecFlow;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::events::VerifyFailureReason;
    use crate::protocol::tests::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, RecordingTransport, run_async,
    };
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, HelperChannel, SecretValue, Target, UserSecret,
    };
    use derec_proto::{DeRecResult, MessageBody, StoreShareResponseMessage};
    use prost::Message as _;

    const SECRET_ID: u64 = 0x4EE9;
    const A: u64 = 31;
    const B: u64 = 32;

    type TestProtocol = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        RecordingTransport,
    >;

    fn uri(channel: u64) -> String {
        format!("https://helper-{channel}.example")
    }

    fn key_of(channel: u64) -> crate::types::SharedKey {
        crate::types::SharedKey::new([channel as u8; 32])
    }

    async fn owner(shares: InMemShareStore, transport: RecordingTransport) -> TestProtocol {
        let mut channels = InMemChannelStore::default();
        let mut secrets = InMemSecretStore::default();
        for channel in [A, B] {
            channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id: ChannelId(channel),
                        transports: vec![derec_proto::TransportProtocol {
                            uri: uri(channel),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
                        communication_info: std::collections::HashMap::new(),
                        peer_role: derec_proto::SenderKind::Helper,
                        status: ChannelStatus::Paired,
                        created_at: now_secs(),
                        weight: 1,
                    }),
                )
                .await
                .expect("seed helper");
            secrets
                .save(
                    SECRET_ID,
                    ChannelId(channel),
                    SecretValue::SharedKey(key_of(channel)),
                )
                .await
                .expect("seed key");
        }
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels)
            .with_share_store(shares)
            .with_secret_store(secrets)
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_state_store(InMemPersistedStateStore::default())
            .with_transport(transport)
            .with_own_transports(["https://owner.example"])
            .with_threshold(2)
            .build()
            .expect("test protocol builds")
    }

    /// The channel each envelope sent so far went to, with the request it
    /// carried.
    fn sent_requests(
        transport: &RecordingTransport,
    ) -> Vec<(u64, derec_proto::StoreShareRequestMessage)> {
        transport
            .sent
            .lock()
            .unwrap()
            .iter()
            .map(|(endpoints, envelope)| {
                let channel = [A, B]
                    .into_iter()
                    .find(|c| endpoints[0].uri == uri(*c))
                    .expect("every send goes to a seeded helper");
                let request =
                    crate::primitives::sharing::request::extract(envelope, &key_of(channel))
                        .expect("a store-share request")
                        .request;
                (channel, request)
            })
            .collect()
    }

    fn answer(channel: u64, version: u32, status: derec_proto::StatusEnum) -> Vec<u8> {
        let timestamp = current_timestamp();
        DeRecMessageBuilder::channel()
            .channel_id(ChannelId(channel))
            .timestamp(timestamp)
            .message_body(MessageBody::StoreShareResponse(StoreShareResponseMessage {
                result: Some(DeRecResult {
                    status: status as i32,
                    memo: String::new(),
                }),
                version,
                timestamp: Some(timestamp),
                secret_id: SECRET_ID,
                replica_id: None,
            }))
            .encrypt(&key_of(channel))
            .expect("encrypt")
            .build()
            .expect("build")
            .encode_to_vec()
    }

    /// Publish once and have each Helper answer with the status `status_of`
    /// gives its channel. Returns the version published.
    async fn round(
        protocol: &mut TestProtocol,
        transport: &RecordingTransport,
        status_of: impl Fn(u64) -> derec_proto::StatusEnum,
    ) -> u32 {
        transport.sent.lock().unwrap().clear();
        protocol
            .start(DeRecFlow::ProtectSecret {
                secrets: vec![UserSecret {
                    id: b"id".to_vec(),
                    name: "name".to_owned(),
                    data: b"data".to_vec(),
                }],
                description: None,
                weights: std::collections::HashMap::new(),
                threshold: None,
            })
            .await
            .expect("publish");
        let requests = sent_requests(transport);
        assert_eq!(requests.len(), 2, "one request per helper");
        let version = requests[0].1.version;
        for (channel, request) in requests {
            protocol
                .process(&answer(channel, request.version, status_of(channel)))
                .await
                .expect("the owner reads the answer");
        }
        version
    }

    fn versions_held(shares: &InMemShareStore, channel: u64) -> Vec<u32> {
        let mut versions: Vec<u32> = shares
            .data
            .lock()
            .unwrap()
            .keys()
            .filter(|(s, c, _)| *s == SECRET_ID && *c == channel)
            .map(|(_, _, v)| *v)
            .collect();
        versions.sort_unstable();
        versions
    }

    fn ok(_: u64) -> derec_proto::StatusEnum {
        derec_proto::StatusEnum::Ok
    }

    /// An application keeping no older version: once both Helpers confirm
    /// v3 they hold only v3, and so does the owner. Verifying v1 is then a
    /// local condition, not a question for the Helpers.
    #[test]
    fn confirmed_versions_other_than_the_keep_version_lose_their_proofs() {
        run_async(async {
            let shares = InMemShareStore::default();
            *shares.keep.lock().unwrap() = Some(0);
            let transport = RecordingTransport::default();
            let mut protocol = owner(shares.clone(), transport.clone()).await;

            for expected in 1..=3 {
                assert_eq!(round(&mut protocol, &transport, ok).await, expected);
            }

            assert_eq!(versions_held(&shares, A), vec![3]);
            assert_eq!(versions_held(&shares, B), vec![3]);

            transport.sent.lock().unwrap().clear();
            let events = protocol
                .start(DeRecFlow::VerifyShares {
                    secret_id: SECRET_ID,
                    version: 1,
                    target: Target::All,
                })
                .await
                .expect("verify starts");

            assert_eq!(events.len(), 2, "one verdict per helper; got {events:?}");
            assert!(
                events.iter().all(|e| matches!(
                    e,
                    DeRecEvent::VerifySharesFailed {
                        version: 1,
                        reason: VerifyFailureReason::NoProof,
                        ..
                    }
                )),
                "got {events:?}"
            );
            assert!(
                transport.sent_envelopes().is_empty(),
                "no challenge is sent for a version no helper holds"
            );
        });
    }

    /// A Helper that refuses v3 prunes nothing, so the owner keeps the
    /// proofs of the versions it still holds; the Helper that confirmed
    /// loses them.
    #[test]
    fn a_rejecting_helper_keeps_its_older_proofs() {
        run_async(async {
            let shares = InMemShareStore::default();
            let transport = RecordingTransport::default();
            let mut protocol = owner(shares.clone(), transport.clone()).await;

            round(&mut protocol, &transport, ok).await;
            round(&mut protocol, &transport, ok).await;
            assert_eq!(versions_held(&shares, B), vec![1, 2]);

            *shares.keep.lock().unwrap() = Some(0);
            let version = round(&mut protocol, &transport, |channel| {
                if channel == B {
                    derec_proto::StatusEnum::Fail
                } else {
                    derec_proto::StatusEnum::Ok
                }
            })
            .await;
            assert_eq!(version, 3);

            assert_eq!(versions_held(&shares, A), vec![3]);
            assert_eq!(
                versions_held(&shares, B),
                vec![1, 2],
                "B refused v3: it still holds v1 and v2, and v3's proof is dropped"
            );
        });
    }

    /// The `keepVersion` is still held by the Helper, so its proof stays.
    #[test]
    fn the_keep_version_keeps_its_proof() {
        run_async(async {
            let shares = InMemShareStore::default();
            let transport = RecordingTransport::default();
            let mut protocol = owner(shares.clone(), transport.clone()).await;

            round(&mut protocol, &transport, ok).await;
            *shares.keep.lock().unwrap() = Some(1);
            for _ in 2..=3 {
                round(&mut protocol, &transport, ok).await;
            }

            assert_eq!(versions_held(&shares, A), vec![1, 3]);
            assert_eq!(versions_held(&shares, B), vec![1, 3]);
        });
    }

    fn seed_proof(shares: &InMemShareStore, channel: u64, version: u32) {
        shares.data.lock().unwrap().insert(
            (SECRET_ID, channel, version),
            crate::protocol::types::Share {
                secret_id: SECRET_ID,
                version,
                bytes: vec![0xAB],
                subshares: None,
                threshold: None,
            },
        );
    }

    async fn seed_open_round(protocol: &mut TestProtocol, version: u32, keep_version: Option<u32>) {
        protocol
            .state_store
            .save(
                SECRET_ID,
                StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                    version,
                    pending: [ChannelId(A), ChannelId(B)].into_iter().collect(),
                    confirmed: Default::default(),
                    failed: Default::default(),
                    pending_replicas: Default::default(),
                    synced_replicas: Default::default(),
                    behind_replicas: Default::default(),
                    started_at: now_secs(),
                    keep_version,
                    threshold: None,
                })),
            )
            .await
            .expect("seed round");
    }

    /// A Helper ignores the `keepVersion` of a request older than a version it
    /// already holds. While the owner holds a newer proof for the channel,
    /// confirming the older round removes nothing.
    #[test]
    fn a_confirmation_older_than_a_held_proof_removes_nothing() {
        run_async(async {
            let shares = InMemShareStore::default();
            for version in [3, 4, 5] {
                seed_proof(&shares, A, version);
            }
            let mut protocol = owner(shares.clone(), RecordingTransport::default()).await;
            seed_open_round(&mut protocol, 4, Some(0)).await;

            let mut events = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(A),
                version: 4,
            }];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert_eq!(versions_held(&shares, A), vec![3, 4, 5]);
        });
    }

    /// A version whose round still waits on the Helper may reach it after
    /// the newer one and be stored without pruning, so its proof stays.
    #[test]
    fn a_version_still_awaiting_the_helper_keeps_its_proof() {
        run_async(async {
            let shares = InMemShareStore::default();
            for version in [3, 4, 5] {
                seed_proof(&shares, A, version);
            }
            let mut protocol = owner(shares.clone(), RecordingTransport::default()).await;
            seed_open_round(&mut protocol, 4, Some(0)).await;
            seed_open_round(&mut protocol, 5, Some(0)).await;

            let mut events = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(A),
                version: 5,
            }];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert_eq!(
                versions_held(&shares, A),
                vec![4, 5],
                "v3 is pruned; v4 still awaits this helper"
            );
        });
    }

    /// The proofs every round gives up in one pass, failed and pruned alike,
    /// go to the store in a single call.
    #[test]
    fn a_tick_drops_every_rounds_proofs_in_one_call() {
        run_async(async {
            let shares = InMemShareStore::default();
            for version in [2, 3, 4] {
                seed_proof(&shares, A, version);
            }
            for version in [3, 4] {
                seed_proof(&shares, B, version);
            }
            let mut protocol = owner(shares.clone(), RecordingTransport::default()).await;
            seed_open_round(&mut protocol, 3, Some(0)).await;
            seed_open_round(&mut protocol, 4, Some(0)).await;

            let rejected = |version| DeRecEvent::ShareRejected {
                channel_id: ChannelId(B),
                version,
                status: StatusEnum::Fail as i32,
                memo: "rejected".to_owned(),
            };
            let mut events = vec![
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(A),
                    version: 4,
                },
                rejected(3),
                rejected(4),
            ];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert_eq!(
                versions_held(&shares, A),
                vec![3, 4],
                "v2 is pruned; v3 still awaits this helper"
            );
            assert_eq!(versions_held(&shares, B), Vec::<u32>::new());
            assert_eq!(*shares.remove_versions_many_calls.lock().unwrap(), 1);
        });
    }

    /// A newer round the Helper failed in the same pass does not hold back
    /// the pruning of an older round it confirmed: the failed version's
    /// proof is already on its way out.
    #[test]
    fn a_version_failed_in_the_same_pass_does_not_block_pruning() {
        run_async(async {
            let shares = InMemShareStore::default();
            for version in [5, 6, 7, 8] {
                seed_proof(&shares, A, version);
            }
            let mut protocol = owner(shares.clone(), RecordingTransport::default()).await;
            seed_open_round(&mut protocol, 7, Some(5)).await;
            seed_open_round(&mut protocol, 8, Some(5)).await;

            let mut events = vec![
                DeRecEvent::ShareRejected {
                    channel_id: ChannelId(A),
                    version: 8,
                    status: StatusEnum::Fail as i32,
                    memo: "rejected".to_owned(),
                },
                DeRecEvent::ShareConfirmed {
                    channel_id: ChannelId(A),
                    version: 7,
                },
            ];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert_eq!(versions_held(&shares, A), vec![5, 7]);
        });
    }

    /// Keeping the version before each time leaves the owner the proofs of
    /// the last two versions, as the Helpers hold.
    #[test]
    fn keeping_the_previous_version_keeps_the_last_two_proofs() {
        run_async(async {
            let shares = InMemShareStore::default();
            let transport = RecordingTransport::default();
            let mut protocol = owner(shares.clone(), transport.clone()).await;

            for _ in 1..=3 {
                round(&mut protocol, &transport, ok).await;
            }

            assert_eq!(versions_held(&shares, A), vec![2, 3]);
            assert_eq!(versions_held(&shares, B), vec![2, 3]);
        });
    }

    /// A round with no recorded `keep_version`, such as one persisted before
    /// the field existed, removes no proof when its Helpers confirm.
    #[test]
    fn a_round_without_a_keep_version_removes_no_proof() {
        run_async(async {
            let shares = InMemShareStore::default();
            for version in [1, 2, 3] {
                seed_proof(&shares, A, version);
            }
            let mut protocol = owner(shares.clone(), RecordingTransport::default()).await;
            seed_open_round(&mut protocol, 3, None).await;

            let mut events = vec![DeRecEvent::ShareConfirmed {
                channel_id: ChannelId(A),
                version: 3,
            }];
            protocol
                .update_sharing_round(&mut events)
                .await
                .expect("the rounds are settled");

            assert_eq!(versions_held(&shares, A), vec![1, 2, 3]);
        });
    }
}
