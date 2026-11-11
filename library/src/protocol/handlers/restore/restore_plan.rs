// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The writes a restore makes, planned from the recovered [`Secret`].

use super::RestoreError;
use crate::Result;
#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
use crate::protocol::types::{
    ChannelStatus, HelperChannel, HelperInfo, KeepRecoveryChannel, ReplicaRole, Replicas, Secret,
};
use crate::protocol::{ChannelKey, DeRecEvent, NotRestoredReason};
use crate::types::{ChannelId, ReplicaId, SharedKey};
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;
use derec_proto::SenderKind;
use std::collections::HashSet;

/// Every write restore makes, derived from the recovered [`Secret`] and the
/// application's [`KeepRecoveryChannel`] pairs, and fully validated before
/// any store is touched.
pub(super) struct RestorePlan {
    /// Canonical helper channels to write, each with its key.
    pub(super) helpers: Vec<(HelperChannel, ChannelKey)>,
    /// One [`DeRecEvent::PeerNotRestored`] per roster entry that gets no
    /// channel, in roster order.
    pub(super) not_restored: Vec<DeRecEvent>,
    /// Ids restore writes. A pre-existing channel at one of these is a
    /// conflict.
    pub(super) written_ids: HashSet<u64>,
    /// Every id the roster names, written or not. A channel at none of them
    /// is a recovery channel.
    pub(super) roster_ids: HashSet<u64>,
    /// Recovery channels kept in place of a roster helper, each with the
    /// weight its roster entry carries.
    kept: Vec<(ChannelId, u32)>,
}

impl RestorePlan {
    /// Plan the restore of `secret`, keeping the recovery channels `keep`
    /// names in place of their roster helpers. The recovery channels
    /// themselves are checked against the store in [`Self::kept_channels`].
    pub(super) fn new(secret: &Secret, keep: &[KeepRecoveryChannel]) -> Result<Self> {
        if secret.threshold.is_some_and(|t| t < 2) {
            return Err(RestoreError::Invariant("threshold must be at least 2").into());
        }
        let mut plan = Self {
            helpers: Vec::new(),
            not_restored: Vec::new(),
            written_ids: HashSet::new(),
            roster_ids: HashSet::new(),
            kept: Vec::new(),
        };

        for helper in &secret.helpers {
            plan.add_helper(helper)?;
        }
        if let Some(group) = &secret.replicas {
            plan.drop_replica_group(group)?;
        }
        plan.keep(secret, keep)?;
        Ok(plan)
    }

    /// Plan a roster helper's canonical channel, or report it as not
    /// restored when it has no endpoint to send to.
    fn add_helper(&mut self, h: &HelperInfo) -> Result<()> {
        let shared_key: SharedKey = h
            .shared_key
            .as_slice()
            .try_into()
            .map_err(|_| RestoreError::Invariant("helper.shared_key must be 32 bytes"))?;

        let channel_id = ChannelId(h.channel_id);
        self.roster_ids.insert(h.channel_id);
        if h.transports.is_empty() {
            self.not_restored.push(DeRecEvent::PeerNotRestored {
                channel_id,
                replica_id: None,
                reason: NotRestoredReason::NoTransports,
            });
            return Ok(());
        }
        self.written_ids.insert(h.channel_id);
        self.helpers.push((
            HelperChannel {
                channel_id,
                transports: h.transports.clone(),
                communication_info: h.communication_info.clone(),
                status: ChannelStatus::Paired,
                created_at: now_secs(),
                peer_role: SenderKind::Helper,
                weight: h.effective_weight(),
            },
            ChannelKey {
                epoch: h.key_epoch,
                key: shared_key,
            },
        ));
        Ok(())
    }

    /// Validate the recovered replica group like every other roster entry,
    /// so an inconsistent `Secret` is still refused whole, but never write
    /// it: each member is reported as dropped with it.
    fn drop_replica_group(&mut self, group: &Replicas) -> Result<()> {
        self.roster_ids.insert(group.channel_id);
        if !group.members.is_empty() {
            let _: SharedKey = group.shared_key.as_slice().try_into().map_err(|_| {
                RestoreError::Invariant(
                    "recovered Secret carries replicas but replicas.shared_key is missing or wrong size",
                )
            })?;
        }
        for r in &group.members {
            ReplicaId::try_from(r.replica_id)?;
            ReplicaRole::from_i32(r.role).ok_or(RestoreError::Invariant(
                "roster member carries an unknown role",
            ))?;
            self.not_restored.push(DeRecEvent::PeerNotRestored {
                channel_id: ChannelId(group.channel_id),
                replica_id: Some(r.replica_id),
                reason: NotRestoredReason::ReplicaGroupDropped,
            });
        }
        Ok(())
    }

    /// Apply the application's [`KeepRecoveryChannel`] pairs: each named
    /// roster helper is no longer written, and its recovery channel is kept
    /// with the roster weight. A pure check of the pairs against the roster.
    fn keep(&mut self, secret: &Secret, pairs: &[KeepRecoveryChannel]) -> Result<()> {
        let mut rosters = HashSet::new();
        let mut recoveries = HashSet::new();
        for pair in pairs {
            let roster = pair.roster_channel_id;
            let recovery = pair.recovery_channel_id;
            let Some(entry) = secret.helpers.iter().find(|h| h.channel_id == roster.0) else {
                return Err(RestoreError::InvalidKeptChannel(roster).into());
            };
            if !rosters.insert(roster.0) {
                return Err(RestoreError::InvalidKeptChannel(roster).into());
            }
            if self.roster_ids.contains(&recovery.0) || !recoveries.insert(recovery.0) {
                return Err(RestoreError::InvalidKeptChannel(recovery).into());
            }
            self.helpers.retain(|(h, _)| h.channel_id != roster);
            self.written_ids.remove(&roster.0);
            self.not_restored.retain(|event| {
                !matches!(event, DeRecEvent::PeerNotRestored { channel_id, replica_id: None, .. } if *channel_id == roster)
            });
            self.kept.push((recovery, entry.effective_weight()));
        }
        Ok(())
    }

    /// The kept recovery channels as they will be saved: each must already be
    /// a `Paired` channel to a Helper, and takes its roster entry's weight.
    pub(super) fn kept_channels(
        &self,
        existing_channels: &[HelperChannel],
    ) -> Result<Vec<HelperChannel>> {
        self.kept
            .iter()
            .map(|&(recovery, weight)| {
                existing_channels
                    .iter()
                    .find(|c| {
                        c.channel_id == recovery
                            && c.peer_role == SenderKind::Helper
                            && c.status == ChannelStatus::Paired
                    })
                    .map(|c| HelperChannel {
                        weight,
                        ..c.clone()
                    })
                    .ok_or_else(|| RestoreError::InvalidKeptChannel(recovery).into())
            })
            .collect()
    }

    pub(super) fn kept_recovery_ids(&self) -> HashSet<u64> {
        self.kept.iter().map(|(id, _)| id.0).collect()
    }
}
