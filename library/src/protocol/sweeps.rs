// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Time-driven work.
//!
//! Nothing in the protocol runs on its own clock: [`DeRecProtocol::tick`] is
//! the application handing over control so deadlines can be checked. A round
//! that never completes, an unpair that is never acknowledged, and a channel
//! that outlives its pairing window are all settled from here.

use super::context::local;
use super::events::DeRecEvent;
use super::stores::borrow_stores;
use super::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use super::types::{SecretKind, StateItem, StateKey, StateKind};
use super::{DeRecProtocol, handlers};
use crate::{Result, types::ChannelId};
use derec_proto::StatusEnum;

use crate::extensions::channel_store::ChannelStoreExt as _;
#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;

impl<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
> DeRecProtocol<Ch, Sh, Ss, Us, St, T>
{
    /// Check if any channels in the active sharing round have timed out.
    ///
    /// Returns `ShareRejected` events for timed-out channels and moves them
    /// from `pending` to `failed` in the round tracker.
    /// Advance every time-driven part of the protocol without an inbound
    /// message, returning whatever that produced.
    ///
    /// # Why this exists
    ///
    /// Timeouts are otherwise only evaluated inside [`Self::process`], so they
    /// advance only when traffic arrives. A publish whose helpers all go quiet
    /// has nothing left to trigger it: the round stays open, no
    /// [`DeRecEvent::SharingComplete`] is ever emitted, and an application
    /// waiting on that event waits forever. The same applies to an
    /// unacknowledged unpair.
    ///
    /// A long-lived embedded application could rely on incidental traffic. A
    /// service that rebuilds the protocol per request has no background loop
    /// at all, so this is the entry point its scheduler calls — a cron tick, a
    /// timer task, a queue heartbeat.
    ///
    /// # What it does
    ///
    /// Exactly what [`Self::process`] does about time, minus the message:
    ///
    /// 1. Expired-channel cleanup, if
    ///    [`Timeouts::expired_channels`](crate::protocol::types::Timeouts::expired_channels)
    ///    enabled it — which it is **by default**
    ///    (`Enabled { timeout_in_secs: 300 }`). Setting it to
    ///    [`crate::protocol::ExpiredChannelCleanup::Disabled`]
    ///    skips this step and leaves [`Self::remove_expired_channels`] for
    ///    explicit control.
    /// 2. Sharing-round timeouts — every helper still pending past the
    ///    configured window is failed with
    ///    [`DeRecEvent::ShareRejected`], every member still pending is
    ///    reported [`DeRecEvent::ReplicaSyncFailed`].
    /// 3. Unpair-acknowledgement timeouts.
    /// 4. The round tally, which is what turns a fully-drained round into
    ///    [`DeRecEvent::SharingComplete`] and clears its state row. Step 2
    ///    only marks the participants; without this the round would report
    ///    failures and still never close.
    ///
    /// # Calling it
    ///
    /// Idempotent and safe to call at any time: with nothing in flight it
    /// touches no state and returns an empty vector. Store failures are
    /// swallowed the same way [`Self::process`] swallows them, so a transient
    /// backend error means work is retried on the next call rather than
    /// surfaced here.
    ///
    /// Cadence should be shorter than
    /// [`Timeouts`](crate::protocol::types::Timeouts), since that bounds how long a
    /// stalled round can sit before this notices it.
    ///
    /// Concurrency is the caller's, as everywhere else: this mutates the same
    /// round state an inbound response does, so it must be serialized against
    /// [`Self::process`] for the same `secret_id`. See
    /// [`DeRecStateStore`].
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn tick(&mut self) -> Vec<DeRecEvent> {
        let mut events = self.run_timeout_sweeps().await;
        self.update_sharing_round(&mut events).await;
        events
    }

    /// Remove `Pending` channels older than `older_than_secs`, along with
    /// their pairing keys. Returns the ids that were removed.
    ///
    /// This is **independent of**
    /// [`Timeouts::expired_channels`](crate::protocol::types::Timeouts::expired_channels): it sweeps at
    /// the threshold it is given even when the policy is
    /// [`crate::protocol::ExpiredChannelCleanup::Disabled`]. That is what
    /// makes `Disabled` mean "the application drives cleanup itself".
    ///
    /// `older_than_secs` is not clamped. The minimum-of-one-second rule
    /// exists to stop the *automatic* sweep from deleting just-started
    /// pairings on every [`process`](Self::process) call; an explicit call
    /// is a deliberate act, so `remove_expired_channels(0)` is permitted
    /// and sweeps the most aggressively the predicate allows.
    ///
    /// The comparison is strict — a channel is removed when its age is
    /// **greater than** `older_than_secs`. Ages are whole seconds, taken
    /// from `created_at`, so `remove_expired_channels(0)` removes every
    /// `Pending` channel created in an earlier second but leaves one
    /// created within the current second.
    ///
    /// Called automatically during [`process`](Self::process) when the
    /// configured policy is
    /// [`crate::protocol::ExpiredChannelCleanup::Enabled`].
    ///
    /// Replica rows are swept on the same clock: a replica pairing that never
    /// completed leaves a `Pending` member row behind. This device's own row is
    /// never a pending pairing, so it is exempt.
    pub async fn remove_expired_channels(
        &mut self,
        older_than_secs: u64,
    ) -> Result<Vec<ChannelId>> {
        let now = now_secs();
        let timeout = older_than_secs;
        let channels = self
            .channel_store
            .helpers_matching(
                self.secret_id,
                crate::protocol::types::HelperFilter {
                    status: vec![crate::protocol::types::ChannelStatus::Pending],
                    ..Default::default()
                },
            )
            .await?;

        let mut removed = Vec::new();
        for channel in channels {
            if now.saturating_sub(channel.created_at) > timeout {
                self.channel_store
                    .remove(
                        self.secret_id,
                        crate::protocol::types::ChannelQuery::Helper {
                            channel_id: channel.channel_id,
                        },
                    )
                    .await?;
                let _ = self
                    .secret_store
                    .remove(
                        self.secret_id,
                        channel.channel_id,
                        SecretKind::PairingSecret,
                    )
                    .await;
                let _ = self
                    .secret_store
                    .remove(
                        self.secret_id,
                        channel.channel_id,
                        SecretKind::PairingContact,
                    )
                    .await;

                #[cfg(feature = "logging")]
                tracing::info!(
                    channel_id = channel.channel_id.0,
                    elapsed_secs = now.saturating_sub(channel.created_at),
                    "expired pending channel removed"
                );

                removed.push(channel.channel_id);
            }
        }

        let expiring = self
            .channel_store
            .replicas_matching(
                self.secret_id,
                crate::protocol::types::ReplicaFilter {
                    status: vec![crate::protocol::types::ChannelStatus::Pending],
                    exclude: self.exclude_self(),
                    ..Default::default()
                },
            )
            .await?;
        for member in expiring {
            if now.saturating_sub(member.created_at) > timeout {
                self.channel_store
                    .remove(
                        self.secret_id,
                        crate::protocol::types::ChannelQuery::Replica {
                            channel_id: member.channel_id,
                            replica_id: member.replica_id,
                        },
                    )
                    .await?;

                #[cfg(feature = "logging")]
                tracing::info!(
                    channel_id = member.channel_id.0,
                    replica_id = member.replica_id.0,
                    elapsed_secs = now.saturating_sub(member.created_at),
                    "expired pending replica member removed"
                );

                if !removed.contains(&member.channel_id) {
                    removed.push(member.channel_id);
                }
            }
        }
        Ok(removed)
    }

    /// The time-driven sweeps, shared by [`Self::tick`] and [`Self::process`]
    /// so the two cannot drift.
    ///
    /// Deliberately does **not** run the round tally: `process` runs it once
    /// at the end, over these events together with the message's own, and
    /// running it here as well would reorder what `process` reports.
    pub(super) async fn run_timeout_sweeps(&mut self) -> Vec<DeRecEvent> {
        if let crate::protocol::ExpiredChannelCleanup::Enabled { timeout_in_secs } =
            self.timeouts.expired_channels
        {
            // Best effort: a cleanup failure must not fail the `process` or
            // `tick` that ran it, or a store hiccup would reject a message
            // that has nothing to do with expiry. Logged rather than dropped
            // silently — a store failing every sweep is worth seeing.
            if let Err(_error) = self.remove_expired_channels(timeout_in_secs).await {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    error = %_error,
                    "expired-channel sweep failed; channels stay until the next one"
                );
            }
        }

        let mut events = self.check_sharing_round_timeouts().await;
        events.append(&mut self.check_unpair_timeouts().await);
        events
    }

    /// Update the active sharing round based on events produced by `process_inner`.
    ///
    /// Moves channels from `pending` to `confirmed` or `failed` as
    /// `ShareConfirmed` / `ShareRejected` events arrive. When no channels
    /// remain pending, appends a [`DeRecEvent::SharingComplete`] summary.
    ///
    /// Every open round is offered the same event list and takes only the
    /// entries carrying its own version. Rounds overlap whenever a publish
    /// fires from an inbound path, so settling just one of them would strand
    /// the rest.
    pub(super) async fn update_sharing_round(&mut self, events: &mut Vec<DeRecEvent>) {
        let Ok(rounds) = self
            .state_store
            .load_all(self.secret_id, StateKind::SharingRound)
            .await
        else {
            return;
        };

        let mut produced: Vec<DeRecEvent> = Vec::new();

        for item in rounds {
            let StateItem::SharingRound(round) = item else {
                continue;
            };
            let crate::protocol::types::SharingRoundState {
                version: round_version,
                mut pending,
                mut confirmed,
                mut failed,
                mut pending_replicas,
                mut synced_replicas,
                mut behind_replicas,
                started_at,
            } = *round;

            self.settle_one_round(
                events,
                &mut produced,
                round_version,
                &mut pending,
                &mut confirmed,
                &mut failed,
                &mut pending_replicas,
                &mut synced_replicas,
                &mut behind_replicas,
                started_at,
            )
            .await;
        }

        events.append(&mut produced);
    }

    /// Settle every sharing round whose window has elapsed.
    ///
    /// More than one round can be open at a time: the pair-completion hook and
    /// the promotion inside [`verify_fingerprint`](Self::verify_fingerprint)
    /// both publish, and either can fire while an application-initiated round
    /// is still in flight. Each is keyed by its version and ages on its own
    /// clock, so they are swept independently rather than as one row.
    ///
    /// Members age on the same clock as helpers. A member that never answered
    /// settles as behind rather than failing the round — see
    /// `ReplicaSyncComplete`.
    async fn check_sharing_round_timeouts(&mut self) -> Vec<DeRecEvent> {
        let Ok(rounds) = self
            .state_store
            .load_all(self.secret_id, StateKind::SharingRound)
            .await
        else {
            return vec![];
        };

        let now = now_secs();
        let mut events = Vec::new();

        for item in rounds {
            let StateItem::SharingRound(round) = item else {
                continue;
            };
            let crate::protocol::types::SharingRoundState {
                version,
                mut pending,
                confirmed,
                mut failed,
                mut pending_replicas,
                synced_replicas,
                mut behind_replicas,
                started_at,
            } = *round;

            if now.saturating_sub(started_at) <= self.timeouts.sharing_round.as_secs() {
                continue;
            }
            let timed_out: Vec<ChannelId> = pending.drain().collect();
            for channel_id in timed_out {
                failed.insert(channel_id);
                events.push(DeRecEvent::ShareRejected {
                    channel_id,
                    version,
                    status: StatusEnum::Fail as i32,
                    memo: "timeout".to_owned(),
                });

                #[cfg(feature = "logging")]
                tracing::warn!(
                    channel_id = channel_id.0,
                    version,
                    "sharing round: helper timed out"
                );
            }
            let timed_out_replicas: Vec<crate::types::ReplicaId> =
                pending_replicas.drain().collect();
            for replica_id in timed_out_replicas {
                behind_replicas.insert(replica_id);
                events.push(DeRecEvent::ReplicaSyncFailed {
                    replica_id: replica_id.0,
                    version,
                    reason: "timeout".to_owned(),
                });

                #[cfg(feature = "logging")]
                tracing::warn!(
                    replica_id = replica_id.0,
                    version,
                    "sharing round: replica timed out"
                );
            }

            let _ = self
                .state_store
                .save(
                    self.secret_id,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version,
                        pending,
                        confirmed,
                        failed,
                        pending_replicas,
                        synced_replicas,
                        behind_replicas,
                        started_at,
                    })),
                )
                .await;
        }
        events
    }

    /// Drop local state for any pending unpair whose acknowledgement window has
    /// elapsed, returning an `Unpaired` event per dropped channel.
    async fn check_unpair_timeouts(&mut self) -> Vec<DeRecEvent> {
        let now = now_secs();
        let all = match self
            .state_store
            .load_all(self.secret_id, StateKind::PendingUnpair)
            .await
        {
            Ok(items) => items,
            Err(_) => return Vec::new(),
        };
        let expired: Vec<ChannelId> = all
            .into_iter()
            .filter_map(|item| match item {
                StateItem::PendingUnpair {
                    channel_id,
                    started_at,
                } if now.saturating_sub(started_at) > self.timeouts.unpair_ack.as_secs() => {
                    Some(channel_id)
                }
                _ => None,
            })
            .collect();

        let mut events = Vec::with_capacity(expired.len());
        for cid in expired {
            let _ = self
                .state_store
                .remove(self.secret_id, StateKey::PendingUnpair { channel_id: cid })
                .await;
            if handlers::unpairing::drop_channel_state(
                &mut borrow_stores!(self),
                &local!(self),
                cid,
            )
            .await
            .is_ok()
            {
                events.push(DeRecEvent::Unpaired { channel_id: cid });
            }
        }
        events
    }

    /// Apply `inbound` to one round and either complete it or persist it.
    ///
    /// Split out of [`Self::update_sharing_round`] so the per-round body stays
    /// readable now that several rounds can be open at once.
    ///
    /// Also carries the publisher-side half of the removal rule: a member told
    /// to leave completes its departure when it acknowledges the version that
    /// excludes it, which is what `synced_replicas` records. Receive-side
    /// reconciliation cannot do this — a publisher never receives the roster it
    /// just sent — so without it the device that ran the removal would keep the
    /// row forever and go on addressing a member that has already torn down.
    ///
    /// The replica leg is reported under its own event: different success rule,
    /// different key, and emitted only when the round had a replica leg at all,
    /// so a helpers-only publish stays silent there.
    #[allow(clippy::too_many_arguments)]
    async fn settle_one_round(
        &mut self,
        inbound: &[DeRecEvent],
        produced: &mut Vec<DeRecEvent>,
        round_version: u32,
        pending: &mut std::collections::HashSet<ChannelId>,
        confirmed: &mut std::collections::HashSet<ChannelId>,
        failed: &mut std::collections::HashSet<ChannelId>,
        pending_replicas: &mut std::collections::HashSet<crate::types::ReplicaId>,
        synced_replicas: &mut std::collections::HashSet<crate::types::ReplicaId>,
        behind_replicas: &mut std::collections::HashSet<crate::types::ReplicaId>,
        started_at: u64,
    ) {
        let events = inbound;
        for event in events.iter() {
            match event {
                DeRecEvent::ShareConfirmed {
                    channel_id,
                    version,
                } if *version == round_version => {
                    pending.remove(channel_id);
                    confirmed.insert(*channel_id);
                }
                DeRecEvent::ShareRejected {
                    channel_id,
                    version,
                    ..
                } if *version == round_version => {
                    pending.remove(channel_id);
                    failed.insert(*channel_id);
                }
                DeRecEvent::ReplicaSecretAcked {
                    from_replica_id,
                    version,
                    ..
                } if *version == round_version => {
                    if let Ok(replica_id) = crate::types::ReplicaId::try_from(*from_replica_id) {
                        pending_replicas.remove(&replica_id);
                        synced_replicas.insert(replica_id);
                    }
                }
                DeRecEvent::ReplicaSyncRejected {
                    replica_id,
                    version,
                    ..
                } if *version == round_version => {
                    if let Ok(replica_id) = crate::types::ReplicaId::try_from(*replica_id) {
                        pending_replicas.remove(&replica_id);
                        behind_replicas.insert(replica_id);
                    }
                }
                _ => {}
            }
        }

        let is_complete = pending.is_empty() && pending_replicas.is_empty();
        let confirmed_count = confirmed.len();
        let failed_count = failed.len();

        if is_complete {
            let threshold_met = confirmed_count >= self.threshold;
            let _ = self
                .state_store
                .remove(
                    self.secret_id,
                    StateKey::SharingRound {
                        version: round_version,
                    },
                )
                .await;
            produced.push(DeRecEvent::SharingComplete {
                version: round_version,
                confirmed_count,
                failed_count,
                threshold_met,
            });

            let mut removed_replicas: Vec<u64> = Vec::new();
            // An empty `ids` is "every member", not "no member", so a round
            // that synced nobody must not reach the store at all.
            let leaving = if synced_replicas.is_empty() {
                Ok(Vec::new())
            } else {
                self.channel_store
                    .replicas_matching(
                        self.secret_id,
                        crate::protocol::types::ReplicaFilter {
                            ids: synced_replicas.iter().copied().collect(),
                            status: vec![crate::protocol::types::ChannelStatus::Unpairing],
                            ..Default::default()
                        },
                    )
                    .await
            };
            if let Ok(roster) = leaving {
                for member in roster {
                    if self
                        .channel_store
                        .remove(
                            self.secret_id,
                            crate::protocol::types::ChannelQuery::Replica {
                                channel_id: member.channel_id,
                                replica_id: member.replica_id,
                            },
                        )
                        .await
                        .is_ok()
                    {
                        removed_replicas.push(member.replica_id.0);
                    }
                }
            }

            if !synced_replicas.is_empty() || !behind_replicas.is_empty() {
                let mut synced: Vec<u64> = synced_replicas.iter().map(|r| r.0).collect();
                let mut behind: Vec<u64> = behind_replicas.iter().map(|r| r.0).collect();
                // Sets are unordered; sort so the event is reproducible.
                synced.sort_unstable();
                behind.sort_unstable();

                #[cfg(feature = "logging")]
                tracing::info!(
                    version = round_version,
                    synced_count = synced.len(),
                    behind_count = behind.len(),
                    "replica sync round complete"
                );

                produced.push(DeRecEvent::ReplicaSyncComplete {
                    version: round_version,
                    synced,
                    behind,
                });
            }

            removed_replicas.sort_unstable();
            for replica_id in removed_replicas {
                produced.push(DeRecEvent::ReplicaRemoved { replica_id });
            }

            #[cfg(feature = "logging")]
            tracing::info!(
                version = round_version,
                confirmed_count,
                failed_count,
                threshold_met,
                "sharing round complete"
            );
        } else {
            let _ = self
                .state_store
                .save(
                    self.secret_id,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version: round_version,
                        pending: std::mem::take(pending),
                        confirmed: std::mem::take(confirmed),
                        failed: std::mem::take(failed),
                        pending_replicas: std::mem::take(pending_replicas),
                        synced_replicas: std::mem::take(synced_replicas),
                        behind_replicas: std::mem::take(behind_replicas),
                        started_at,
                    })),
                )
                .await;
        }
    }
}

#[cfg(test)]
mod expired_channel_sweep_tests {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::test::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, ExpiredChannelCleanup, HelperChannel, ReplicaMember,
        ReplicaRole, SecretValue,
    };

    const SECRET_ID: u64 = 0xC1;

    fn endpoint() -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: "https://peer.example.com".to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    /// Seed one channel whose `created_at` is `age_secs` in the past.
    async fn seed(
        channels: &mut InMemChannelStore,
        cid: u64,
        status: ChannelStatus,
        age_secs: u64,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: ChannelId(cid),
                    transports: vec![endpoint()],
                    communication_info: std::collections::HashMap::new(),
                    status,
                    created_at: now_secs().saturating_sub(age_secs),
                    peer_role: derec_proto::SenderKind::Helper,
                }),
            )
            .await
            .expect("seed channel");
    }

    fn build(
        channels: InMemChannelStore,
        policy: ExpiredChannelCleanup,
        timeout_in_secs: u64,
    ) -> DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
        NoopTransport,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels)
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .with_timeouts(crate::protocol::types::Timeouts {
                sharing_round: std::time::Duration::from_secs(timeout_in_secs),
                unpair_ack: std::time::Duration::from_secs(timeout_in_secs),
                inbound_message: std::time::Duration::from_secs(timeout_in_secs),
                expired_channels: policy,
            })
            .build()
            .expect("test protocol builds")
    }

    /// The manual sweep honours its own argument, not the configured
    /// policy — `Disabled` means "I drive this myself", not "off".
    #[test]
    fn manual_sweep_works_under_disabled_policy() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 600).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
            let removed = protocol
                .remove_expired_channels(60)
                .await
                .expect("sweep succeeds");

            assert_eq!(removed, vec![ChannelId(1)]);
            assert!(channels.helper_rows.lock().unwrap().is_empty());
        });
    }

    /// Seed one replica member on the group channel.
    async fn seed_member(
        channels: &mut InMemChannelStore,
        replica_id: u64,
        status: ChannelStatus,
        age_secs: u64,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: ChannelId(9000),
                    replica_id: crate::types::ReplicaId(replica_id),
                    transports: vec![endpoint()],
                    communication_info: std::collections::HashMap::new(),
                    role: ReplicaRole::Destination,
                    status,
                    created_at: now_secs().saturating_sub(age_secs),
                }),
            )
            .await
            .expect("seed member");
    }

    /// A replica pairing that never completed expires like any other, but
    /// this device's own row is exempt: it is a roster entry, not a pending
    /// handshake, and sweeping it would erase the group's self-reference.
    #[test]
    fn sweep_removes_expired_replica_members_but_never_this_device() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed_member(&mut seeded, 7, ChannelStatus::Pending, 600).await;
            seed_member(&mut seeded, 8, ChannelStatus::Paired, 600).await;
            seed_member(&mut seeded, 9, ChannelStatus::Pending, 600).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
            protocol.replica_id = Some(9);
            let removed = protocol
                .remove_expired_channels(60)
                .await
                .expect("sweep succeeds");

            assert_eq!(
                removed,
                vec![ChannelId(9000)],
                "members share one channel, so the group is reported once"
            );
            let rows = channels.member_rows.lock().unwrap();
            assert!(
                !rows.contains_key(&(SECRET_ID, 7)),
                "expired pending member"
            );
            assert!(rows.contains_key(&(SECRET_ID, 8)), "paired member survives");
            assert!(rows.contains_key(&(SECRET_ID, 9)), "own row is exempt");
        });
    }

    /// `Disabled` suppresses the automatic sweep inside `process()`, so an
    /// over-age channel survives because nothing swept it.
    #[test]
    fn disabled_policy_leaves_channel_for_manual_sweep() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 600).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
            let _ = protocol.process(&[]).await;

            assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
        });
    }

    /// The policy's timeout governs the automatic sweep, not
    /// `timeout_in_secs` — verified by setting them to different values
    /// and choosing an age between the two.
    #[test]
    fn policy_timeout_governs_not_protocol_timeout() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 120).await;

            let mut protocol = build(
                channels.clone(),
                ExpiredChannelCleanup::Enabled {
                    timeout_in_secs: 60,
                },
                3600,
            );
            let _ = protocol.process(&[]).await;

            assert!(channels.helper_rows.lock().unwrap().is_empty());
        });
    }

    /// `Paired` channels are never swept, regardless of age.
    #[test]
    fn paired_channels_are_never_removed() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Paired, 99_999).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::default(), 300);
            let removed = protocol
                .remove_expired_channels(1)
                .await
                .expect("sweep succeeds");

            assert!(removed.is_empty());
            assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
        });
    }

    /// Removing a channel also drops its pairing material, so a stale
    /// handshake leaves nothing behind in the secret store.
    #[test]
    fn removal_drops_pairing_material() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let mut seeded = channels.clone();
            let mut seeded_secrets = secrets.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 600).await;
            seeded_secrets
                .save(
                    SECRET_ID,
                    ChannelId(1),
                    SecretValue::PairingContact(Default::default()),
                )
                .await
                .expect("seed pairing contact");

            let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(channels.clone())
                .with_share_store(InMemShareStore::default())
                .with_secret_store(secrets.clone())
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_transport(NoopTransport)
                .with_state_store(InMemStateStore)
                .with_own_transports(["https://owner.example.com"])
                .with_threshold(2)
                .with_timeouts(crate::protocol::types::Timeouts {
                    expired_channels: ExpiredChannelCleanup::Disabled,
                    ..Default::default()
                })
                .build()
                .expect("test protocol builds");

            let removed = protocol
                .remove_expired_channels(60)
                .await
                .expect("sweep succeeds");

            assert_eq!(removed, vec![ChannelId(1)]);
            assert!(secrets.data.lock().unwrap().is_empty());
        });
    }

    /// An explicit zero is not clamped — the minimum-of-1 rule guards the
    /// automatic sweep only. A `Pending` channel from an earlier second
    /// goes; the `Paired` one stays.
    #[test]
    fn explicit_zero_sweeps_pending_from_earlier_seconds() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 1).await;
            seed(&mut seeded, 2, ChannelStatus::Paired, 1).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
            let removed = protocol
                .remove_expired_channels(0)
                .await
                .expect("sweep succeeds");

            assert_eq!(removed, vec![ChannelId(1)]);
            assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
        });
    }

    /// The comparison is strict, so a channel created within the current
    /// second survives even the most aggressive threshold. This pins the
    /// boundary the automatic sweep relies on to avoid deleting pairings
    /// the instant they start.
    #[test]
    fn zero_age_channel_survives_zero_threshold() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let mut seeded = channels.clone();
            seed(&mut seeded, 1, ChannelStatus::Pending, 0).await;

            let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
            let removed = protocol
                .remove_expired_channels(0)
                .await
                .expect("sweep succeeds");

            assert!(removed.is_empty());
            assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
        });
    }
}

#[cfg(test)]
mod sharing_round_outcome_tests {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::test::{
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
            protocol.update_sharing_round(&mut events).await;

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
            protocol.update_sharing_round(&mut events).await;
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
            protocol.update_sharing_round(&mut events).await;

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
            protocol.update_sharing_round(&mut events).await;

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
            protocol.update_sharing_round(&mut events).await;

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
            protocol.update_sharing_round(&mut events).await;

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
                    })),
                )
                .await
                .expect("seed");
            protocol.update_sharing_round(&mut events).await;

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
            protocol.update_sharing_round(&mut events).await;

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
            protocol.update_sharing_round(&mut events).await;

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

#[cfg(test)]
mod timeout_tests {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::test::{
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
