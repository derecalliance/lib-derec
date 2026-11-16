// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Post-recovery rebuild handler.
//!
//! Takes a [`Secret`] handed up by a
//! [`DeRecEvent::SecretRecovered`](super::super::DeRecEvent::SecretRecovered)
//! event and reseats the protocol's `secret_id` namespace from it:
//! writes canonical helper channel records (or keeps the recovery channels
//! the application names in their place), commits the user-secret snapshot
//! with the roster's threshold, then unpairs every other recovery-mode
//! channel under the `secret_id` (the channels minted to drive
//! `start(RecoverSecret)` — scrap after restore commits). The recovered
//! replica group is never written: restoring means the owner lost its
//! devices, and any it still has join again by pairing.
//!
//! Two preconditions are reported as [`RestoreError`] (wrapped in
//! [`crate::Error::Restore`]) **before any store mutation** — a
//! precondition error is exactly equivalent to never having called
//! restore:
//!
//! - [`RestoreError::AlreadyRestored`] — a user-secret snapshot
//!   already exists for this `secret_id`.
//! - [`RestoreError::Conflict`] — a channel already lives at one of
//!   the canonical helper ids restore is about to write.
//!
//! A roster entry with no transport endpoint is not an error: a channel to
//! it would have nothing to send to, so restore writes none and reports the
//! entry as [`DeRecEvent::PeerNotRestored`] instead. Every other entry is
//! restored as usual.
//!
//! Store I/O failures mid-restore propagate as their underlying
//! [`crate::Error`] variant (`ChannelStore`, `SecretStore`, and
//! `ShareStore` — which the user-secret store reuses for the snapshot
//! write, restore having no share writes of its own). The snapshot
//! write is the commit point — nothing
//! is removed before it succeeds, so any mid-flight failure leaves
//! state the next `restore` call can detect as one of the
//! preconditions above.
//!
//! Restore writes no owner-side tracking shares, so the recovered
//! version is not verifiable on this device; publishing once restores
//! that. See [`restore`] for why.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecStateStore, DeRecUserSecretStore, StateItem, StateKey,
    UnpairAck,
    types::{
        ChannelRecord, ChannelStatus, HelperChannel, KeepRecoveryChannel, Secret, UserSecrets,
    },
};
use crate::extensions::secret_store::SecretStoreExt as _;
use crate::protocol::context::{Local, Round};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::{ChannelKey, KeyRing};
use crate::{Error, Result, types::ChannelId};
use std::collections::HashSet;

use super::unpairing::{self, drop_channels_state};
use crate::derec_message::fresh_trace_id;
use crate::extensions::channel_store::ChannelStoreExt as _;
#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
use crate::protocol::types::HelperFilter;
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;
use derec_proto::SenderKind;
pub use error::RestoreError;
use restore_plan::RestorePlan;

mod error;
mod restore_plan;

/// Run the restore flow. On success: canonical helper channels are
/// persisted with their key, except those `keep_recovery_channels` replaces
/// with a recovery channel; the user-secret snapshot is committed at
/// `newest_version`; every other recovery-mode channel under `secret_id`
/// is unpaired under the configured `unpair_ack`, exactly as
/// `start(Unpair)` would. The returned events are one
/// [`DeRecEvent::PeerNotRestored`] per roster entry that got no channel —
/// every replica group member among them — followed by those of the
/// recovery-channel wipe, and should be drained into the protocol's
/// `pending_start_events`.
///
/// # Verification after a restore
///
/// No owner-side tracking [`crate::protocol::types::Share`] is written,
/// so `start(VerifyShares)` at `recovered_version` sends no challenge and
/// reports each channel as `VerifySharesFailed` with
/// [`crate::protocol::VerifyFailureReason::NoProof`] — this device holds no
/// reference bytes
/// for that version and cannot check a proof against it. That is a
/// property of recovery, not a defect: a `VerifyShare` proof is
/// `SHA-384(share ‖ nonce)` over the *exact* bytes a Helper holds, and
/// recovery cannot attribute a collected share to a canonical Helper
/// channel — the VSS x-coordinate is a random field element and
/// `GetShareResponseMessage` carries no channel id.
///
/// The way back to a verifiable state is to publish:
/// `start(ProtectSecret)` derives `recovered_version + 1` from the
/// snapshot committed here, writes real tracking shares as it
/// distributes, and `start(VerifyShares)` at that version behaves
/// exactly as it does for an owner that never recovered.
///
/// # The replica group is dropped
///
/// Restore is for an owner that lost access to its other devices; one that
/// still has them adds a device by pairing it as a replica, not by
/// restoring. So the recovered group is not carried forward: no member
/// record and no group key are written, and each member is reported as
/// [`DeRecEvent::PeerNotRestored`] with
/// [`NotRestoredReason::ReplicaGroupDropped`](crate::protocol::NotRestoredReason::ReplicaGroupDropped), in roster order. The
/// restored device publishes as a lone owner, and devices the owner still
/// has join it again by pairing. The recovered `Secret`'s `replicas` still
/// names each member, with the `communication_info` it advertised, for the
/// application to show. No message is sent to the old members: they are
/// cut off from the helpers when the old helper channels are retired with a
/// linked `start(Unpair)`, since they share those channels.
///
/// # Peers without an endpoint
///
/// A helper whose `transports` is empty gets no channel:
/// it would be a channel with nothing to send to. Restore skips it, reports
/// it as [`DeRecEvent::PeerNotRestored`] with
/// [`NotRestoredReason::NoTransports`](crate::protocol::NotRestoredReason::NoTransports), and restores the rest of the roster.
/// A legacy roster whose single URI had a scheme this library does not serve
/// decodes to exactly such an entry.
///
/// A skipped entry is still validated — its key length, and a group
/// member's `replica_id` and role, are part of the recovered `Secret`, and
/// an inconsistent `Secret` is refused whole whether or not every entry is
/// written. What the skip changes is which ids restore claims. A skipped
/// helper's `channel_id` is not written, so a channel already sitting there
/// is not a conflict; it is a roster id, so it is not a recovery channel
/// either, and the wipe leaves it alone rather than send an unpair to a
/// peer that holds a share. The dropped group's channel id is treated the
/// same way.
///
/// # Sequence
///
/// 1. **Preconditions.** Validate the protocol can restore and plan
///    every write the rest of the flow makes. [`crate::Error::InvalidInput`]
///    when `newest_version` is below `recovered_version`.
///    [`RestoreError::AlreadyRestored`] when a snapshot is already
///    committed, [`RestoreError::Invariant`] when a key is mis-sized, a
///    member's role is unknown or the threshold is below `2`, [`crate::Error::InvalidInput`] when a
///    member's `replica_id` is the reserved `0`, and
///    [`RestoreError::Conflict`] when an existing channel sits at an id
///    restore is about to write. All are reported before any store
///    mutation. Channels at no roster id whose peer is a Helper are
///    recovery channels — wiped in step 4, never flagged as collisions.
/// 2. **Helper channels.** Persist each reachable helper's key ring — the
///    roster's key at its `key_epoch`, with `recovered_version` pinned to
///    that epoch — in one call, then every channel record in one call: each
///    reachable helper's canonical record, and each recovery channel named
///    in `keep_recovery_channels` with its roster entry's weight, keeping
///    its own endpoint and key in place of its roster helper. No tracking
///    share — see *Verification after a restore* above. The device's own
///    `replica_id` is never adopted from the recovered `Secret`, and no
///    replica group is written.
/// 3. **Commit.** Write the user-secret snapshot at `newest_version`,
///    carrying the recovered secrets and the roster's threshold, so the next
///    publish is `newest_version + 1` and splits at the `t` the secret was
///    shared under. A Helper refuses a version older than the newest it
///    stores ([`IgnoreReason::Superseded`](crate::protocol::IgnoreReason::Superseded)),
///    so a publish numbered from an older `recovered_version` would reach
///    none of them. To change the threshold, pass `threshold` on
///    `start(ProtectSecret)`. This write is the commit point — nothing is
///    removed before it succeeds, so any earlier failure is fully
///    retryable.
/// 4. **Wipe.** Unpair every channel at no roster id whose peer is a
///    Helper — the recovery-mode channels minted to drive
///    `start(RecoverSecret)` — under the configured `unpair_ack`. A channel
///    whose peer is an Owner is this device helping someone else: it holds
///    that owner's share and is never touched. Each recovery channel is
///    sent its own unpair request; the rest happens all at once. Under
///    `UnpairAck::Required` every one is marked
///    [`ChannelStatus::Unpairing`](crate::protocol::types::ChannelStatus::Unpairing)
///    in a single write, so no flow selects it while its helper's answer is
///    awaited: the follow-up `ProtectSecret` reaches only the restored
///    helpers, and the answer lands on a channel that still exists. Unlike
///    `start(Unpair)`, the outcome does not depend on the answer: an
///    acceptance, the acknowledgement timeout and a refusal all drop the
///    channel and report [`DeRecEvent::Unpaired`], a refusal preceded by
///    [`DeRecEvent::UnpairRejected`]. The answer only tells the application
///    whether the helper confirmed. Under `UnpairAck::NotRequired` the
///    recovery channels are dropped together as the requests go out.
///
///    For the same reason the wipe cannot fail the restore. An old
///    helper that has gone away is the expected condition during
///    recovery, and the commit in step 3 has already happened —
///    returning `Err` here would strand the caller with committed
///    canonical state, un-torn-down ephemeral channels, and
///    [`RestoreError::AlreadyRestored`] blocking any retry. Instead each
///    undeliverable teardown surfaces as
///    [`DeRecEvent::UnpairFailed`] and local state is dropped anyway, so
///    every wiped channel yields exactly one [`DeRecEvent::Unpaired`]:
///    in the returned events when the request could not be sent or no
///    acknowledgement is required, later from `process` or the timeout
///    sweep otherwise. Only a failure to drop the local state itself
///    leaves channels behind, reported as `UnpairFailed` with no
///    `Unpaired`.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
pub(in crate::protocol) async fn restore<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    secret: &Secret,
    recovered_version: u32,
    newest_version: u32,
    keep_recovery_channels: &[KeepRecoveryChannel],
    unpair_ack: UnpairAck,
) -> Result<Vec<DeRecEvent>> {
    if newest_version < recovered_version {
        return Err(Error::InvalidInput(
            "newest_version is below recovered_version",
        ));
    }
    let plan = RestorePlan::new(secret, keep_recovery_channels)?;
    let existing_channels = check_preconditions(stores, local, &plan).await?;
    let kept = plan.kept_channels(&existing_channels)?;

    write_channels(stores, local, &plan.helpers, kept, recovered_version).await?;
    save_secret(stores, local, secret, newest_version).await?;

    let kept_ids = plan.kept_recovery_ids();
    let mut events = plan.not_restored;
    events.extend(
        unpair_recovery_channels(
            stores,
            local,
            &existing_channels,
            &plan.roster_ids,
            &kept_ids,
            unpair_ack,
        )
        .await,
    );

    #[cfg(feature = "logging")]
    tracing::info!(
        local.secret_id,
        helpers_restored = plan.helpers.len(),
        user_secrets_restored = secret.secrets.len(),
        "DeRecProtocol restored from recovered Secret"
    );

    Ok(events)
}

async fn check_preconditions<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    plan: &RestorePlan,
) -> Result<Vec<HelperChannel>> {
    if stores
        .user_secrets
        .load_latest(local.secret_id)
        .await?
        .is_some()
    {
        return Err(RestoreError::AlreadyRestored.into());
    }

    // Unfiltered deliberately: a channel of either role at an id restore
    // writes is a conflict, and the caller picks the recovery channels out
    // of the same rows.
    let existing_channels = stores
        .channels
        .helpers_matching(local.secret_id, HelperFilter::default())
        .await?;
    let collisions: Vec<ChannelId> = existing_channels
        .iter()
        .filter(|c| plan.written_ids.contains(&c.channel_id.0))
        .map(|c| c.channel_id)
        .collect();

    if !collisions.is_empty() {
        return Err(RestoreError::Conflict(collisions).into());
    }

    Ok(existing_channels)
}

/// Write the restored channels: the key rings of the roster helpers in one
/// secret-store call, then every channel record, roster helpers and kept
/// recovery channels alike, in one channel-store call. A kept channel keeps
/// its own key, so it has no ring to write.
///
/// The rings go first so a failure between the two calls leaves no channel
/// record behind: a retried restore finds no conflict and rewrites them.
async fn write_channels<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    helpers: &[(HelperChannel, ChannelKey)],
    kept: Vec<HelperChannel>,
    version: u32,
) -> Result<()> {
    let secret_id = local.secret_id;
    let rings: Vec<(ChannelId, KeyRing)> = helpers
        .iter()
        .map(|(channel, key)| (channel.channel_id, KeyRing::restored(key, version)))
        .collect();
    stores.secrets.save_key_rings(secret_id, &rings).await?;

    let records: Vec<ChannelRecord> = helpers
        .iter()
        .map(|(channel, _)| ChannelRecord::Helper(channel.clone()))
        .chain(kept.into_iter().map(ChannelRecord::Helper))
        .collect();
    if !records.is_empty() {
        stores.channels.save_many(secret_id, records).await?;
    }
    Ok(())
}

async fn save_secret<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    secret: &Secret,
    version: u32,
) -> Result<()> {
    stores
        .user_secrets
        .save_latest(
            local.secret_id,
            UserSecrets {
                version,
                secrets: secret.secrets.clone(),
                description: None,
                author_replica_id: None,
                threshold: secret.threshold,
            },
        )
        .await?;
    Ok(())
}

/// Tear down the recovery channels: every channel at no roster id whose peer
/// is a Helper and that is not kept.
///
/// Each one is sent an unpair request, which needs its own key and endpoint.
/// The rest happens all at once:
///
/// - Under `UnpairAck::Required`, one state-store write saves a pending
///   entry for every channel that was sent its request, marked to drop the
///   channel whatever the Helper answers, and then one channel-store write
///   marks all of them `Unpairing`, so no flow selects them while the answers are awaited. A
///   Helper's acceptance, its refusal and the acknowledgement timeout each
///   end in [`DeRecEvent::Unpaired`]; a refusal is reported first as
///   [`DeRecEvent::UnpairRejected`].
/// - Every other channel is dropped in one call: all of them under
///   `UnpairAck::NotRequired`, and under `Required` those whose request could
///   not be sent, or every channel if the pending entries could not be saved.
///   If the `Unpairing` write fails, the channels awaiting an answer are dropped
///   here too, so none is left selectable.
///
/// Nothing here fails the restore, which has already committed. A request
/// that could not be sent, or pending entries that could not be saved, are
/// reported as [`DeRecEvent::UnpairFailed`] before the channel's
/// [`DeRecEvent::Unpaired`]. A drop that fails reports `UnpairFailed` for
/// each channel it covered and no `Unpaired`: the channels stay, and the
/// application can unpair them one by one.
async fn unpair_recovery_channels<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    existing_channels: &[HelperChannel],
    roster_ids: &HashSet<u64>,
    kept_ids: &HashSet<u64>,
    unpair_ack: UnpairAck,
) -> Vec<DeRecEvent> {
    let recovery = recovery_channels(existing_channels, roster_ids, kept_ids);
    if recovery.is_empty() {
        return Vec::new();
    }

    let mut teardown = Teardown::default();
    let sent = send_unpair_requests(stores, local, recovery, &mut teardown).await;
    match unpair_ack {
        UnpairAck::NotRequired => teardown.drop_now.extend(sent.iter().map(|c| c.channel_id)),
        UnpairAck::Required => {
            let awaiting = save_pending_unpairs(stores, local.secret_id, sent, &mut teardown).await;
            mark_unpairing(stores, local.secret_id, &awaiting, &mut teardown).await;
        }
    }
    teardown.drop_channels(stores, local).await
}

/// The events of a recovery-channel teardown, and the channels it drops in
/// one call at the end instead of awaiting a Helper's answer.
#[derive(Default)]
struct Teardown {
    events: Vec<DeRecEvent>,
    drop_now: Vec<ChannelId>,
}

impl Teardown {
    /// Report a step that failed for `channel_id` and drop the channel
    /// instead of awaiting its Helper's answer.
    fn failed(&mut self, channel_id: ChannelId, error: impl ToString) {
        self.events.push(DeRecEvent::UnpairFailed {
            channel_id,
            error: error.to_string(),
        });
        self.drop_now.push(channel_id);
    }

    /// Drop every channel not awaiting an answer, in one call, and report
    /// each as `Unpaired`, or as `UnpairFailed` if the drop fails.
    async fn drop_channels<S: StoreSet>(
        mut self,
        stores: &mut Stores<'_, S>,
        local: &Local<'_>,
    ) -> Vec<DeRecEvent> {
        if self.drop_now.is_empty() {
            return self.events;
        }
        match drop_channels_state(stores, local, &self.drop_now).await {
            Ok(()) => self
                .events
                .extend(
                    self.drop_now
                        .into_iter()
                        .map(|channel_id| DeRecEvent::Unpaired {
                            channel_id,
                            acknowledged: false,
                        }),
                ),
            Err(e) => self
                .events
                .extend(
                    self.drop_now
                        .into_iter()
                        .map(|channel_id| DeRecEvent::UnpairFailed {
                            channel_id,
                            error: e.to_string(),
                        }),
                ),
        }
        self.events
    }
}

/// The recovery channels among `existing_channels`: those whose peer is a
/// Helper, at no roster id and not kept.
fn recovery_channels<'a>(
    existing_channels: &'a [HelperChannel],
    roster_ids: &HashSet<u64>,
    kept_ids: &HashSet<u64>,
) -> Vec<&'a HelperChannel> {
    existing_channels
        .iter()
        .filter(|c| {
            c.peer_role == SenderKind::Helper
                && !roster_ids.contains(&c.channel_id.0)
                && !kept_ids.contains(&c.channel_id.0)
        })
        .collect()
}

/// Send each channel its unpair request, all under one trace id, and return
/// the channels it was sent to. A channel whose request could not be sent is
/// reported and dropped.
async fn send_unpair_requests<'a, S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channels: Vec<&'a HelperChannel>,
    teardown: &mut Teardown,
) -> Vec<&'a HelperChannel> {
    let round = &Round {
        reply_to: &[],
        trace_id: fresh_trace_id(),
    };
    let mut sent = Vec::new();
    for channel in channels {
        let channel_id = channel.channel_id;
        teardown.events.push(DeRecEvent::UnpairStarted {
            channel_id,
            trace_id: round.trace_id,
        });
        match unpairing::send_request(stores, local, channel_id, channel_id, None, round).await {
            Ok(()) => sent.push(channel),
            Err(e) => teardown.failed(channel_id, e),
        }
    }
    sent
}

/// Save every channel's pending entry in one call, each marked to drop the
/// channel whatever its Helper answers, and return the channels now awaiting
/// an answer. If the entries could not be saved, every channel is reported
/// and dropped instead.
async fn save_pending_unpairs<'a, S: StoreSet>(
    stores: &mut Stores<'_, S>,
    secret_id: u64,
    channels: Vec<&'a HelperChannel>,
    teardown: &mut Teardown,
) -> Vec<&'a HelperChannel> {
    if channels.is_empty() {
        return channels;
    }
    let now = now_secs();
    let pending: Vec<StateItem> = channels
        .iter()
        .map(|c| StateItem::PendingUnpair {
            channel_id: c.channel_id,
            started_at: now,
            drop_on_rejection: true,
        })
        .collect();
    match stores.state.save_many(secret_id, pending).await {
        Ok(()) => channels,
        Err(e) => {
            for channel in channels {
                teardown.failed(channel.channel_id, &e);
            }
            Vec::new()
        }
    }
}

/// Mark every awaiting channel `Unpairing` in one channel-store write.
///
/// Written after the pending entries, so an `Unpairing` channel always has
/// one and the acknowledgement timeout always reaches it. Only a `Paired`
/// channel becomes `Unpairing`, as in `start(Unpair)`. If the write fails,
/// the pending entries are removed and the channels are dropped instead.
async fn mark_unpairing<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    secret_id: u64,
    awaiting: &[&HelperChannel],
    teardown: &mut Teardown,
) {
    let unpairing: Vec<ChannelRecord> = awaiting
        .iter()
        .filter(|c| c.status == ChannelStatus::Paired)
        .map(|&c| {
            ChannelRecord::Helper(HelperChannel {
                status: ChannelStatus::Unpairing,
                ..c.clone()
            })
        })
        .collect();
    if unpairing.is_empty()
        || stores
            .channels
            .save_many(secret_id, unpairing)
            .await
            .is_ok()
    {
        return;
    }
    let ids: Vec<ChannelId> = awaiting.iter().map(|c| c.channel_id).collect();
    let entries: Vec<StateKey> = ids
        .iter()
        .map(|&channel_id| StateKey::PendingUnpair { channel_id })
        .collect();
    // Best effort: an entry left behind is completed by the timeout sweep,
    // whose drop is idempotent.
    let _ = stores.state.remove_many(secret_id, &entries).await;
    teardown.drop_now.extend(ids);
}

#[cfg(test)]
mod tests;
