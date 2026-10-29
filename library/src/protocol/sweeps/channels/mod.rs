// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Expired-channel cleanup, and releasing a channel's key and pairing
//! material once nothing uses them.

use crate::protocol::DeRecProtocol;
use crate::protocol::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use crate::protocol::types::{
    ChannelQuery, ChannelStatus, HelperChannel, HelperFilter, ReplicaFilter, ReplicaMember,
    SecretKind, StateKey,
};
use crate::{Result, types::ChannelId};

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
    /// Remove `Pending` channels older than `older_than_secs`, along with
    /// their channel key, their pairing material, and any unpair or
    /// verification state started on them. Returns the ids that were
    /// removed.
    ///
    /// No key outlives the pairing it was agreed for: without the record, the
    /// key would decrypt the peer's messages again.
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
    /// completed leaves a `Pending` member row behind. Members of a group share
    /// one channel and one key, so the key goes only once no peer is recorded
    /// on the channel. This device's own row is swept only when it is `Pending`
    /// and no peer remains on its channel — the remainder of a pairing that
    /// never completed; a `Paired` own row is its place in the group and is
    /// never swept.
    pub async fn remove_expired_channels(
        &mut self,
        older_than_secs: u64,
    ) -> Result<Vec<ChannelId>> {
        let now = now_secs();
        let mut removed = self.remove_expired_helpers(now, older_than_secs).await?;
        for channel_id in self.remove_expired_members(now, older_than_secs).await? {
            if !removed.contains(&channel_id) {
                removed.push(channel_id);
            }
        }
        Ok(removed)
    }

    /// Drop what is left of a channel no peer is recorded on any more.
    ///
    /// A channel's key outlives no pairing: once no helper and no other member
    /// is recorded on `channel_id`, a `Pending` own row there is the remainder
    /// of an unconfirmed pairing and goes, and so do the channel key and the
    /// pairing material. A `Paired` own row is the device's place in a group
    /// and keeps the channel. Returns whether the channel was released.
    pub(in crate::protocol) async fn release_if_unused(
        &mut self,
        channel_id: ChannelId,
    ) -> Result<bool> {
        if self
            .channel_store
            .load_helper(self.secret_id, channel_id)
            .await?
            .is_some()
        {
            return Ok(false);
        }

        let on_channel = self
            .channel_store
            .replicas_on_channel(self.secret_id, channel_id, ReplicaFilter::default())
            .await?;

        let own = self.replica_id.map(crate::types::ReplicaId);
        if on_channel
            .iter()
            .any(|m| Some(m.replica_id) != own || m.status == ChannelStatus::Paired)
        {
            return Ok(false);
        }

        self.remove_channel_secrets(&[channel_id]).await?;
        self.remove_members(&on_channel).await?;

        Ok(true)
    }

    /// Remove every `Pending` helper channel older than `older_than_secs`,
    /// with everything stored under it.
    ///
    /// A `Pending` channel never received a share, so what it can hold is its
    /// channel key, its pairing material, and the state of an unpair or a
    /// verification started on it. The records go last and in one call: a
    /// failure before then leaves them in place for the next sweep to retry,
    /// rather than leaving a key with no record to find it by.
    async fn remove_expired_helpers(
        &mut self,
        now: u64,
        older_than_secs: u64,
    ) -> Result<Vec<ChannelId>> {
        let expired = self.expired_helpers(now, older_than_secs).await?;
        if expired.is_empty() {
            return Ok(Vec::new());
        }

        let channel_ids: Vec<ChannelId> =
            expired.iter().map(|channel| channel.channel_id).collect();

        self.remove_channel_states(&channel_ids).await?;
        self.remove_channel_secrets(&channel_ids).await?;
        self.remove_helper_channels(&channel_ids).await?;

        #[cfg(feature = "logging")]
        for channel in &expired {
            tracing::info!(
                channel_id = channel.channel_id.0,
                elapsed_secs = now.saturating_sub(channel.created_at),
                "expired pending channel removed"
            );
        }
        Ok(channel_ids)
    }

    /// Remove every `Pending` member row older than `older_than_secs`, then
    /// release the channels nothing is recorded on any more.
    ///
    /// Members of a group share one channel and one key, so removing a row
    /// removes that member only; the key goes through
    /// [`release_if_unused`](Self::release_if_unused), once no peer remains on
    /// the channel. This device's own row is never removed here: it goes
    /// through the same release, and only while it is `Pending`.
    async fn remove_expired_members(
        &mut self,
        now: u64,
        older_than_secs: u64,
    ) -> Result<Vec<ChannelId>> {
        let expired = self.expired_members(now, older_than_secs).await?;
        let mut removed = self.remove_members(&expired).await?;
        #[cfg(feature = "logging")]
        for member in &expired {
            tracing::info!(
                channel_id = member.channel_id.0,
                replica_id = member.replica_id.0,
                elapsed_secs = now.saturating_sub(member.created_at),
                "expired pending replica member removed"
            );
        }

        if let Some(own) = self.own_member().await?
            && own.status == ChannelStatus::Pending
            && now.saturating_sub(own.created_at) > older_than_secs
            && self.release_if_unused(own.channel_id).await?
            && !removed.contains(&own.channel_id)
        {
            removed.push(own.channel_id);
        }
        for &channel_id in &removed {
            self.release_if_unused(channel_id).await?;
        }
        Ok(removed)
    }

    /// This device's own member row, whichever channel it is on.
    async fn own_member(&self) -> Result<Option<crate::protocol::types::ReplicaMember>> {
        let Some(own) = self.replica_id else {
            return Ok(None);
        };

        Ok(self
            .channel_store
            .replicas_matching(
                self.secret_id,
                crate::protocol::types::ReplicaFilter {
                    ids: vec![crate::types::ReplicaId(own)],
                    ..Default::default()
                },
            )
            .await?
            .into_iter()
            .next())
    }

    /// The `Pending` helper channels older than `older_than_secs`.
    async fn expired_helpers(&self, now: u64, older_than_secs: u64) -> Result<Vec<HelperChannel>> {
        Ok(self
            .channel_store
            .helpers_matching(
                self.secret_id,
                HelperFilter {
                    status: vec![ChannelStatus::Pending],
                    ..Default::default()
                },
            )
            .await?
            .into_iter()
            .filter(|channel| now.saturating_sub(channel.created_at) > older_than_secs)
            .collect())
    }

    /// The `Pending` member rows older than `older_than_secs`, never this
    /// device's own.
    async fn expired_members(&self, now: u64, older_than_secs: u64) -> Result<Vec<ReplicaMember>> {
        Ok(self
            .channel_store
            .replicas_matching(
                self.secret_id,
                ReplicaFilter {
                    status: vec![ChannelStatus::Pending],
                    exclude: self.exclude_self(),
                    ..Default::default()
                },
            )
            .await?
            .into_iter()
            .filter(|member| now.saturating_sub(member.created_at) > older_than_secs)
            .collect())
    }

    /// Remove the unpair and verification state started on every channel in
    /// `channel_ids`, in one call. These are the only state rows keyed by a
    /// channel.
    async fn remove_channel_states(&mut self, channel_ids: &[ChannelId]) -> Result<()> {
        let keys: Vec<StateKey> = channel_ids
            .iter()
            .flat_map(|&channel_id| {
                [
                    StateKey::PendingUnpair { channel_id },
                    StateKey::PendingVerification { channel_id },
                ]
            })
            .collect();
        self.state_store.remove_many(self.secret_id, &keys).await?;
        Ok(())
    }

    /// Remove the channel key and the pairing material held for every channel
    /// in `channel_ids`, in one call.
    ///
    /// Absence is not an error: a pairing that never completed holds no key,
    /// and one that completed holds no pairing material.
    ///
    /// A store failure is returned, so the caller stops before removing the
    /// records and the next sweep retries, rather than leaving a key with no
    /// record to find it by.
    async fn remove_channel_secrets(&mut self, channel_ids: &[ChannelId]) -> Result<()> {
        let entries: Vec<(ChannelId, SecretKind)> = channel_ids
            .iter()
            .flat_map(|&channel_id| {
                [
                    SecretKind::SharedKey,
                    SecretKind::PairingSecret,
                    SecretKind::PairingContact,
                ]
                .map(|kind| (channel_id, kind))
            })
            .collect();
        self.secret_store
            .remove_many(self.secret_id, &entries)
            .await?;
        Ok(())
    }

    /// Remove the helper channel record of every channel in `channel_ids`, in
    /// one call.
    async fn remove_helper_channels(&mut self, channel_ids: &[ChannelId]) -> Result<()> {
        let queries: Vec<ChannelQuery> = channel_ids
            .iter()
            .map(|&channel_id| ChannelQuery::Helper { channel_id })
            .collect();
        self.channel_store
            .remove_many(self.secret_id, &queries)
            .await?;
        Ok(())
    }

    /// Remove the row of every member in `members`, in one call, and return
    /// the channels they were on, each once. Each row goes alone: the group
    /// channel and its key stay.
    async fn remove_members(&mut self, members: &[ReplicaMember]) -> Result<Vec<ChannelId>> {
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let queries: Vec<ChannelQuery> = members
            .iter()
            .map(|member| ChannelQuery::Replica {
                channel_id: member.channel_id,
                replica_id: member.replica_id,
            })
            .collect();
        self.channel_store
            .remove_many(self.secret_id, &queries)
            .await?;
        let mut channels: Vec<ChannelId> = Vec::new();
        for member in members {
            if !channels.contains(&member.channel_id) {
                channels.push(member.channel_id);
            }
        }
        Ok(channels)
    }
}

#[cfg(test)]
mod tests;
