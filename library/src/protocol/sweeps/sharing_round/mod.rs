// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Settling sharing rounds: timing out silent participants, the tally
//! that closes a round, and the proof cleanup that keeps each stored proof
//! either confirmed or part of an open round.

use crate::Result;
use crate::protocol::DeRecProtocol;
use crate::protocol::events::DeRecEvent;
use crate::protocol::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use crate::protocol::types::{
    ChannelQuery, ChannelStatus, ReplicaFilter, SharingRoundState, StateItem, StateKey, StateKind,
};
use crate::types::{ChannelId, ReplicaId};
use derec_proto::StatusEnum;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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
    /// Settle every open sharing round: time out the participants it has
    /// waited on too long, apply the answers in `events`, persist the round or
    /// report it complete, then drop the proofs no helper can answer anymore.
    ///
    /// Every open round is offered the same event list and takes only the
    /// entries carrying its own version. Rounds overlap whenever a publish
    /// fires from an inbound path, so settling just one of them would strand
    /// the rest. Each is keyed by its version and ages on its own clock.
    ///
    /// Timeouts are applied first, as if they had happened before `events`
    /// arrived: a helper that timed out stays failed even if its confirmation
    /// is in this batch. A member that never answered settles as behind rather
    /// than failing the round — see `ReplicaSyncComplete`. The timeout events
    /// are put at the front of `events`, ahead of what the caller had
    /// collected, and the completion summaries at the end.
    ///
    /// Each round is loaded once and written once per call, and the proofs
    /// every round gave up are dropped together after the rounds are settled,
    /// so a completing round still weighs the proofs it counts.
    ///
    /// A round's new state is written before anything acts on it: only a
    /// round whose save or removal succeeded reports its events and gives up
    /// its proofs. A round whose write fails is left as stored, to be settled
    /// again on the next call. The rounds that close in one call are removed
    /// in one write, so they close or stay open together; each open round is
    /// saved on its own.
    ///
    /// # Errors
    ///
    /// Returns the store error when the rounds cannot be loaded, or the first
    /// one when a round cannot be written; later write failures are logged.
    /// The answers in `events` were then not recorded on that round, and are
    /// recorded only if the message carrying them is processed again. The
    /// rounds that were written still report their events into `events`.
    pub(in crate::protocol) async fn update_sharing_round(
        &mut self,
        events: &mut Vec<DeRecEvent>,
    ) -> Result<()> {
        let rounds = self.open_rounds().await?;

        let passes = self.time_out_expired(rounds);

        let unanswered: Vec<(u32, HashSet<ChannelId>)> = passes
            .iter()
            .map(|(round, _)| (round.version, round.pending.clone()))
            .collect();

        let (answered, open): (Vec<_>, Vec<_>) = passes
            .into_iter()
            .map(|(mut round, mut settled)| {
                settled.apply_answers(&mut round, events);
                (round, settled)
            })
            .partition(|(round, _)| round.pending.is_empty() && round.pending_replicas.is_empty());

        let mut written = Written::default();
        let deferred = self.complete_rounds(answered, &mut written).await;
        for (round, settled) in open.into_iter().chain(deferred) {
            let version = round.version;
            match self.save_round(round).await {
                Ok(()) => written.record(settled, Vec::new()),
                Err(error) => written.fail(&[version], error),
            }
        }

        let Written {
            mut settled,
            produced,
            first_error,
        } = written;
        let timeout_events = std::mem::take(&mut settled.timeout_events);
        self.drop_proofs(settled, &unanswered).await;

        events.splice(0..0, timeout_events);
        events.extend(produced);

        first_error.map_or(Ok(()), Err)
    }

    /// Pair every round in `rounds` with what settling it decides, after
    /// timing out every participant of a round whose window has elapsed.
    fn time_out_expired(
        &self,
        rounds: Vec<SharingRoundState>,
    ) -> Vec<(SharingRoundState, Settled)> {
        let now = now_secs();
        let window = self.timeouts.sharing_round.as_secs();
        rounds
            .into_iter()
            .map(|mut round| {
                let mut settled = Settled::default();
                if now.saturating_sub(round.started_at) > window {
                    let (timed_out, events) = time_out(&mut round);
                    settled.timeout_events = events;
                    settled.failed = timed_out
                        .into_iter()
                        .map(|channel_id| (channel_id, round.version))
                        .collect();
                }
                (round, settled)
            })
            .collect()
    }

    /// Close the rounds in `answered`, every participant of which has
    /// answered, and record what they report in `written`.
    ///
    /// Each closed round emits [`DeRecEvent::SharingComplete`], then
    /// [`DeRecEvent::ReplicaSyncComplete`] when it had a replica leg —
    /// different success rule, different key, so a helpers-only publish stays
    /// silent there — then one [`DeRecEvent::ReplicaRemoved`] per departed
    /// member it let go. Rounds are reported in version order, and a member
    /// several of them let go is reported by the first.
    ///
    /// The rounds close together: one read of the confirmed helpers' weights,
    /// one removal of the departed members and one removal of the rounds.
    /// When the weights cannot be read or the departed members cannot be
    /// removed, no round closes: all of them are returned, to be saved as they
    /// stand and completed on a later call, so `threshold_met` is never
    /// guessed and no departed member is left behind once its round is gone.
    /// The departed members are removed before the rounds, so a failure to
    /// remove the rounds after that reports no [`DeRecEvent::ReplicaRemoved`]
    /// when they complete later.
    async fn complete_rounds(
        &mut self,
        mut answered: Vec<(SharingRoundState, Settled)>,
        written: &mut Written,
    ) -> Vec<(SharingRoundState, Settled)> {
        if answered.is_empty() {
            return answered;
        }
        answered.sort_unstable_by_key(|(round, _)| round.version);
        let versions: Vec<u32> = answered.iter().map(|(round, _)| round.version).collect();

        let (thresholds_met, removed) = match self.prepare_completion(&answered).await {
            Ok(prepared) => prepared,
            Err(_error) => {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    versions = ?versions,
                    error = %_error,
                    "sharing rounds could not complete; they are kept and completed later"
                );
                return answered;
            }
        };

        let keys: Vec<StateKey> = versions
            .iter()
            .map(|&version| StateKey::SharingRound { version })
            .collect();
        if let Err(error) = self.state_store.remove_many(self.secret_id, &keys).await {
            written.fail(&versions, error.into());
            return Vec::new();
        }

        let mut unreported: BTreeSet<u64> = removed.into_iter().collect();
        for ((round, settled), threshold_met) in answered.into_iter().zip(thresholds_met) {
            let mut events = vec![DeRecEvent::SharingComplete {
                version: round.version,
                confirmed_count: round.confirmed.len(),
                failed_count: round.failed.len(),
                threshold_met,
            }];
            events.extend(replica_summary(&round));
            let departed: Vec<u64> = round
                .synced_replicas
                .iter()
                .map(|replica_id| replica_id.0)
                .filter(|replica_id| unreported.contains(replica_id))
                .collect::<BTreeSet<u64>>()
                .into_iter()
                .collect();
            for replica_id in departed {
                unreported.remove(&replica_id);
                events.push(DeRecEvent::ReplicaRemoved { replica_id });
            }

            #[cfg(feature = "logging")]
            tracing::info!(
                version = round.version,
                confirmed_count = round.confirmed.len(),
                failed_count = round.failed.len(),
                threshold_met,
                "sharing round complete"
            );

            written.record(settled, events);
        }
        Vec::new()
    }

    /// What closing `answered` needs before the rounds are removed: whether
    /// each met its threshold, in order, and the departed members removed.
    async fn prepare_completion(
        &mut self,
        answered: &[(SharingRoundState, Settled)],
    ) -> Result<(Vec<bool>, Vec<u64>)> {
        let rounds: Vec<&SharingRoundState> = answered.iter().map(|(round, _)| round).collect();
        let thresholds_met = self.thresholds_met(&rounds).await?;
        let synced: HashSet<ReplicaId> = rounds
            .iter()
            .flat_map(|round| round.synced_replicas.iter().copied())
            .collect();
        let removed = self.remove_departed_members(&synced).await?;
        Ok((thresholds_met, removed))
    }

    /// Whether the confirmed helpers of each of `rounds` hold at least its
    /// threshold of subshares between them, in order.
    async fn thresholds_met(&self, rounds: &[&SharingRoundState]) -> Result<Vec<bool>> {
        let weights = self.tracked_weights(rounds).await?;
        Ok(rounds
            .iter()
            .map(|round| {
                let confirmed_weight: u64 = round
                    .confirmed
                    .iter()
                    .map(|&channel_id| {
                        weights
                            .get(&(channel_id, round.version))
                            .copied()
                            .unwrap_or(1)
                    })
                    .sum();
                // A round written before its threshold was recorded is judged
                // against the builder's.
                let round_threshold = round.threshold.map_or(self.threshold as u64, u64::from);
                confirmed_weight >= round_threshold
            })
            .collect())
    }

    /// Drop the rows of the members in `synced` that were told to leave, and
    /// return their ids, sorted.
    ///
    /// This is the publisher-side half of the removal rule: a member told to
    /// leave completes its departure when it acknowledges the version that
    /// excludes it, which is what `synced` records. Receive-side
    /// reconciliation cannot do this — a publisher never receives the roster it
    /// just sent — so without it the device that ran the removal would keep the
    /// row forever and go on addressing a member that has already torn down.
    ///
    /// The rows go in one call, so either every one is removed or none is.
    async fn remove_departed_members(&mut self, synced: &HashSet<ReplicaId>) -> Result<Vec<u64>> {
        // An empty `ids` is "every member", not "no member", so a round
        // that synced nobody must not reach the store at all.
        if synced.is_empty() {
            return Ok(Vec::new());
        }

        let departed = self
            .channel_store
            .replicas_matching(
                self.secret_id,
                ReplicaFilter {
                    ids: synced.iter().copied().collect(),
                    status: vec![ChannelStatus::Unpairing],
                    ..Default::default()
                },
            )
            .await?;

        if departed.is_empty() {
            return Ok(Vec::new());
        }

        let queries: Vec<ChannelQuery> = departed
            .iter()
            .map(|member| ChannelQuery::Replica {
                channel_id: member.channel_id,
                replica_id: member.replica_id,
            })
            .collect();

        self.channel_store
            .remove_many(self.secret_id, &queries)
            .await?;

        let mut removed: Vec<u64> = departed.iter().map(|member| member.replica_id.0).collect();
        removed.sort_unstable();
        Ok(removed)
    }

    /// Persist an open round.
    async fn save_round(&mut self, round: SharingRoundState) -> Result<()> {
        self.state_store
            .save(self.secret_id, StateItem::SharingRound(Box::new(round)))
            .await?;

        Ok(())
    }

    /// Every sharing round still open.
    async fn open_rounds(&self) -> Result<Vec<SharingRoundState>> {
        let items = self
            .state_store
            .load_all(self.secret_id, StateKind::SharingRound)
            .await?;

        Ok(items
            .into_iter()
            .filter_map(|item| match item {
                StateItem::SharingRound(round) => Some(*round),
                _ => None,
            })
            .collect())
    }

    /// Drop, in one call, the owner's proofs the helpers in `settled` can no
    /// longer answer for.
    ///
    /// Keeps the invariant in
    /// [`dispatch_share_to_helper`](crate::protocol::handlers::sharing): a
    /// stored proof is either confirmed by its helper or belongs to a round
    /// that is still open. Two kinds of proof break it:
    ///
    /// - A failed helper's proof for the round it failed — by an inbound
    ///   rejection of any status, or by timing out — can never be confirmed.
    ///   Replica legs of a round have no proof and are never recorded here.
    /// - A confirming helper's proofs for the versions it removed under the
    ///   round's `keepVersion`; see [`pruned_versions`].
    ///
    /// A store error is logged and swallowed: a cleanup failure must not fail
    /// the sweep that found it. Every proof then stays in the store, and a
    /// straggler is removed the next time its channel fails or confirms a
    /// round.
    async fn drop_proofs(&mut self, settled: Settled, unanswered: &[(u32, HashSet<ChannelId>)]) {
        let mut drops: BTreeMap<ChannelId, BTreeSet<u32>> = BTreeMap::new();
        for &(channel_id, version) in &settled.failed {
            drops.entry(channel_id).or_default().insert(version);
        }

        let stored = self.stored_versions(&settled.confirmed, &drops).await;

        for confirmation in &settled.confirmed {
            let Some(stored) = stored.get(&confirmation.channel_id) else {
                continue;
            };
            let pruned = pruned_versions(confirmation, stored, unanswered);

            drops
                .entry(confirmation.channel_id)
                .or_default()
                .extend(pruned);
        }

        let entries: Vec<(ChannelId, Vec<u32>)> = drops
            .into_iter()
            .filter(|(_, versions)| !versions.is_empty())
            .map(|(channel_id, versions)| (channel_id, versions.into_iter().collect()))
            .collect();

        if entries.is_empty() {
            return;
        }

        if let Err(_error) = self
            .share_store
            .remove_versions_many(self.secret_id, &entries)
            .await
        {
            #[cfg(feature = "logging")]
            tracing::warn!(
                error = %_error,
                "settled-round proof cleanup failed; proofs left in store"
            );
        } else {
            #[cfg(feature = "logging")]
            tracing::debug!(removed = ?entries, "settled-round proofs removed");
        }
    }

    /// The versions of the owner's proofs stored for each channel in
    /// `confirmed` whose round recorded a `keep_version`, read in one call,
    /// leaving out the versions `failed` is about to drop.
    ///
    /// Empty when no confirmation can prune or the proofs cannot be loaded,
    /// so nothing is pruned.
    async fn stored_versions(
        &self,
        confirmed: &[Confirmation],
        failed: &BTreeMap<ChannelId, BTreeSet<u32>>,
    ) -> HashMap<ChannelId, Vec<u32>> {
        let mut channel_ids: Vec<ChannelId> = confirmed
            .iter()
            .filter(|confirmation| confirmation.keep_version.is_some())
            .map(|confirmation| confirmation.channel_id)
            .collect();
        channel_ids.sort_unstable();
        channel_ids.dedup();
        if channel_ids.is_empty() {
            return HashMap::new();
        }
        let shares = match self
            .share_store
            .load_many(self.secret_id, &channel_ids, &[])
            .await
        {
            Ok(shares) => shares,
            Err(_error) => {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    error = %_error,
                    "keep-version proof cleanup could not load the confirmed channels' proofs"
                );
                return HashMap::new();
            }
        };
        let mut stored: HashMap<ChannelId, Vec<u32>> = HashMap::new();
        for (channel_id, share) in shares {
            if failed
                .get(&channel_id)
                .is_some_and(|versions| versions.contains(&share.version))
            {
                continue;
            }
            stored.entry(channel_id).or_default().push(share.version);
        }
        stored
    }

    /// The number of subshares this device dispatched to each confirmed
    /// helper of `rounds`, keyed by channel and version, read in one call from
    /// the [`Share::subshares`](crate::protocol::types::Share::subshares)
    /// recorded on the tracking shares it kept.
    ///
    /// A tracking share that is missing or records no count is left out, and
    /// the caller counts its helper as one subshare, the weight every Helper
    /// holds by default.
    async fn tracked_weights(
        &self,
        rounds: &[&SharingRoundState],
    ) -> Result<HashMap<(ChannelId, u32), u64>> {
        let mut channel_ids: Vec<ChannelId> = rounds
            .iter()
            .flat_map(|round| round.confirmed.iter().copied())
            .collect();
        channel_ids.sort_unstable();
        channel_ids.dedup();
        if channel_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let versions: Vec<u32> = rounds.iter().map(|round| round.version).collect();
        let shares = self
            .share_store
            .load_many(self.secret_id, &channel_ids, &versions)
            .await?;
        Ok(shares
            .into_iter()
            .filter_map(|(channel_id, share)| {
                share
                    .subshares
                    .map(|count| ((channel_id, share.version), u64::from(count)))
            })
            .collect())
    }
}

/// Settle every participant `round` is still waiting on as timed out: each
/// pending helper as failed, each pending member as behind. Returns the
/// helpers that failed, whose proofs the caller drops, and the events to
/// report.
fn time_out(round: &mut SharingRoundState) -> (Vec<ChannelId>, Vec<DeRecEvent>) {
    let mut events = Vec::new();
    let timed_out: Vec<ChannelId> = round.pending.drain().collect();
    for &channel_id in &timed_out {
        round.failed.insert(channel_id);
        events.push(DeRecEvent::ShareRejected {
            channel_id,
            version: round.version,
            status: StatusEnum::Fail as i32,
            memo: "timeout".to_owned(),
        });

        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = channel_id.0,
            version = round.version,
            "sharing round: helper timed out"
        );
    }
    for replica_id in round.pending_replicas.drain().collect::<Vec<_>>() {
        round.behind_replicas.insert(replica_id);
        events.push(DeRecEvent::ReplicaSyncFailed {
            replica_id: replica_id.0,
            version: round.version,
            reason: "timeout".to_owned(),
        });

        #[cfg(feature = "logging")]
        tracing::warn!(
            replica_id = replica_id.0,
            version = round.version,
            "sharing round: replica timed out"
        );
    }
    (timed_out, events)
}

/// What settling a round decided: the proofs it gives up and the timeouts it
/// reports. Gathered across every round whose write succeeded, so
/// [`DeRecProtocol::drop_proofs`] drops the proofs in one call.
#[derive(Default)]
struct Settled {
    /// Each helper channel that failed a round, with that round's version.
    failed: Vec<(ChannelId, u32)>,
    /// Each helper channel that confirmed a round.
    confirmed: Vec<Confirmation>,
    /// The events reporting the participants a round timed out.
    timeout_events: Vec<DeRecEvent>,
}

/// What the rounds written in one pass report, and the first write that
/// failed.
#[derive(Default)]
struct Written {
    /// What the written rounds settled.
    settled: Settled,
    /// The completion events of the rounds that closed.
    produced: Vec<DeRecEvent>,
    /// The first write that failed; later ones are only logged.
    first_error: Option<crate::Error>,
}

impl Written {
    /// Record a round whose write succeeded.
    fn record(&mut self, mut settled: Settled, events: Vec<DeRecEvent>) {
        self.settled.failed.append(&mut settled.failed);
        self.settled.confirmed.append(&mut settled.confirmed);
        self.settled
            .timeout_events
            .append(&mut settled.timeout_events);
        self.produced.extend(events);
    }

    /// Record that the rounds at `versions` could not be written.
    fn fail(&mut self, _versions: &[u32], error: crate::Error) {
        #[cfg(feature = "logging")]
        tracing::warn!(
            versions = ?_versions,
            error = %error,
            "sharing rounds could not be written; they are settled again next time"
        );
        self.first_error.get_or_insert(error);
    }
}

/// A helper channel that confirmed round `version`, sent with
/// `keep_version`.
struct Confirmation {
    channel_id: ChannelId,
    version: u32,
    keep_version: Option<u32>,
}

impl Settled {
    /// Apply the answers in `inbound` that carry `round`'s version, recording
    /// the helpers newly confirmed and newly failed.
    ///
    /// Only a channel still `pending` moves. A channel already settled as
    /// `failed` — rejected or timed out, its proof already dropped — must not
    /// also land in `confirmed`, or `threshold_met` could count a channel whose
    /// proof no longer exists; and a repeated `ShareRejected`, timeout-born or
    /// a genuine duplicate, must not drop its proof a second time.
    fn apply_answers(&mut self, round: &mut SharingRoundState, inbound: &[DeRecEvent]) {
        for event in inbound {
            match event {
                DeRecEvent::ShareConfirmed {
                    channel_id,
                    version,
                } if *version == round.version => {
                    if round.pending.remove(channel_id) {
                        round.confirmed.insert(*channel_id);
                        self.confirmed.push(Confirmation {
                            channel_id: *channel_id,
                            version: round.version,
                            keep_version: round.keep_version,
                        });
                    }
                }
                DeRecEvent::ShareRejected {
                    channel_id,
                    version,
                    ..
                } if *version == round.version => {
                    if round.pending.remove(channel_id) {
                        round.failed.insert(*channel_id);
                        self.failed.push((*channel_id, round.version));
                    }
                }
                DeRecEvent::ReplicaSecretAcked {
                    from_replica_id,
                    version,
                    ..
                } if *version == round.version => {
                    if let Ok(replica_id) = ReplicaId::try_from(*from_replica_id) {
                        round.pending_replicas.remove(&replica_id);
                        round.synced_replicas.insert(replica_id);
                    }
                }
                DeRecEvent::ReplicaSyncRejected {
                    replica_id,
                    version,
                    ..
                } if *version == round.version => {
                    if let Ok(replica_id) = ReplicaId::try_from(*replica_id) {
                        round.pending_replicas.remove(&replica_id);
                        round.behind_replicas.insert(replica_id);
                    }
                }
                _ => {}
            }
        }
    }
}

/// The versions among `stored` whose proofs `confirmation`'s helper removed
/// when it confirmed.
///
/// A Helper that accepts a share applies the request's `keepVersion`: it
/// removes every version it holds on the channel other than the accepted one
/// and `keepVersion`, so the owner's proofs of those versions can no longer be
/// answered. This mirrors that rule on the owner, and errs only towards
/// keeping a proof:
///
/// - A round with no recorded `keep_version` removes nothing.
/// - A Helper ignores the `keepVersion` of a request older than a version it
///   already holds. When the owner holds a proof newer than the confirmed
///   version for this channel the Helper may have accepted that one first, so
///   nothing is removed.
/// - A version whose round is still waiting on this Helper may reach it after
///   the confirmed version and be stored without pruning, so its proof stays.
///
/// A proof left behind this way is removed by a later confirmation whose
/// `keepVersion` is not that version. A confirmation arriving after its round
/// has closed carries no `keepVersion` to apply and removes nothing.
fn pruned_versions(
    confirmation: &Confirmation,
    stored: &[u32],
    unanswered: &[(u32, HashSet<ChannelId>)],
) -> Vec<u32> {
    let Some(keep_version) = confirmation.keep_version else {
        return Vec::new();
    };
    let version = confirmation.version;
    if stored.iter().any(|&v| v > version) {
        return Vec::new();
    }
    stored
        .iter()
        .copied()
        .filter(|&v| v != version && v != keep_version)
        .filter(|v| {
            !unanswered
                .iter()
                .any(|(round, pending)| round == v && pending.contains(&confirmation.channel_id))
        })
        .collect()
}

/// The [`DeRecEvent::ReplicaSyncComplete`] that reports `round`'s replica leg,
/// or `None` when the round had none.
fn replica_summary(round: &SharingRoundState) -> Option<DeRecEvent> {
    if round.synced_replicas.is_empty() && round.behind_replicas.is_empty() {
        return None;
    }
    let mut synced: Vec<u64> = round.synced_replicas.iter().map(|r| r.0).collect();
    let mut behind: Vec<u64> = round.behind_replicas.iter().map(|r| r.0).collect();
    // Sets are unordered; sort so the event is reproducible.
    synced.sort_unstable();
    behind.sort_unstable();

    #[cfg(feature = "logging")]
    tracing::info!(
        version = round.version,
        synced_count = synced.len(),
        behind_count = behind.len(),
        "replica sync round complete"
    );

    Some(DeRecEvent::ReplicaSyncComplete {
        version: round.version,
        synced,
        behind,
    })
}

#[cfg(test)]
mod tests;
