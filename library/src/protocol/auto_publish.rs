// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The `ProtectSecret` rounds the library starts on its own.
//!
//! A pairing that completes, an unpair that removes a Helper holding a
//! share, and a replica removal each change who must hold the secret, so the
//! library publishes the latest snapshot itself rather than waiting for the
//! application's next `start(ProtectSecret)`.

use crate::Result;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::protocol::DeRecProtocol;
use crate::protocol::context::Round;
use crate::protocol::events::DeRecEvent;
use crate::protocol::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use crate::types::ChannelId;
use std::collections::HashSet;

impl<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
> DeRecProtocol<Ch, Sh, Ss, Us, St, T>
{
    /// Publish the cached secret when `events` call for it: a helper-side
    /// `PairingCompleted` (the freshly-paired Helper needs shares), or an
    /// [`DeRecEvent::Unpaired`] for a channel in `share_holders` (the Helpers
    /// that remain need a fresh split the removed one has no share of). The
    /// replica-side pairing equivalent fires from `verify_fingerprint` once the
    /// channel leaves `Pending`.
    ///
    /// The completion event is not on its own enough: a `NoKeys` pairing
    /// completes into `ChannelStatus::Pending` and is not a publish target
    /// until its fingerprint is confirmed. Publishing then would bump the
    /// version for every *other* helper while reaching the new one with
    /// nothing, and `verify_fingerprint` would publish again the moment the
    /// gate opened — two rounds where the flow calls for one. So the hook
    /// fires only for a helper that is already usable, and the gated case is
    /// left to `verify_fingerprint`.
    ///
    /// `share_holders` names the channels on which this device held a share
    /// it distributed, read before the channel was dropped; a caller that
    /// settles no unpair passes an empty set. Only those removals republish:
    /// a channel that never received a share — the recovery-mode channels
    /// `restore` unpairs among them — changes nothing a new split would fix.
    ///
    /// The payload comes from `user_secret_store.load_latest()` when one
    /// has been cached by an earlier `start(ProtectSecret)`. When no
    /// snapshot exists yet, a pairing still publishes an empty payload if at
    /// least one Replica Destination is already paired, so the roster
    /// snapshot reaches every Destination — that's how a multi-device sync
    /// stays consistent before the application has added any user secrets.
    /// Without a snapshot an unpair publishes nothing.
    ///
    /// Either way the round runs only when it reaches someone (see
    /// [`auto_round_reaches_anyone`](Self::auto_round_reaches_anyone)):
    /// pairing a Helper that leaves the Helpers below the threshold, with no
    /// replica member to sync, publishes nothing and consumes no version.
    /// One message can both complete a pairing and settle an unpair; either
    /// way it starts at most one round.
    ///
    /// The publish reuses every Helper's stored weight, and a new Helper
    /// starts at `1`. A stored weight that is invalid under the round's
    /// threshold fails the publish with
    /// [`SharingError::InvalidWeight`](crate::primitives::sharing::SharingError::InvalidWeight)
    /// before anything is sent; `process` returns it as a `ProcessError`
    /// carrying the message's events, and `accept` returns it as its error.
    pub(super) async fn maybe_auto_publish(
        &mut self,
        events: &[DeRecEvent],
        share_holders: &HashSet<ChannelId>,
    ) -> Result<Vec<DeRecEvent>> {
        let a_share_holder_was_removed = events.iter().any(|event| {
            matches!(event, DeRecEvent::Unpaired { channel_id } if share_holders.contains(channel_id))
        });
        let a_usable_helper_just_paired = self.a_usable_helper_just_paired(events).await?;
        if !a_usable_helper_just_paired && !a_share_holder_was_removed {
            return Ok(Vec::new());
        }
        let snapshot = self.user_secret_store.load_latest(self.secret_id).await?;
        let (secrets, description, threshold) = match snapshot {
            Some(s) => (s.secrets, s.description, s.threshold),
            None if a_usable_helper_just_paired
                && self.has_paired_replica_destination().await? =>
            {
                (Vec::new(), None, None)
            }
            None => return Ok(Vec::new()),
        };
        if !self.auto_round_reaches_anyone(threshold).await? {
            return Ok(Vec::new());
        }
        self.start_auto_protect_secret(secrets, description).await
    }

    /// Publish the roster that completes a replica removal, right after
    /// `start(UnpairReplica)` flagged the member.
    ///
    /// The flag keeps the member out of the roster while leaving it on the
    /// distribution list, so this round is what lets it tear down and what
    /// makes every other member drop it. The latest snapshot is published, or
    /// an empty payload when there is none: the roster is what the removal
    /// needs, not the secrets.
    pub(super) async fn auto_publish_after_replica_removal(&mut self) -> Result<Vec<DeRecEvent>> {
        let snapshot = self.user_secret_store.load_latest(self.secret_id).await?;
        let (secrets, description, threshold) = match snapshot {
            Some(s) => (s.secrets, s.description, s.threshold),
            None => (Vec::new(), None, None),
        };
        if !self.auto_round_reaches_anyone(threshold).await? {
            return Ok(Vec::new());
        }
        self.start_auto_protect_secret(secrets, description).await
    }

    /// Whether a round the library starts on its own reaches anyone: a
    /// replica member to sync, or paired Helpers whose stored weights sum to
    /// at least the round's threshold — `threshold` when the snapshot records
    /// one, otherwise the builder's.
    ///
    /// Below the threshold a round splits nothing, so with no member to sync
    /// it would consume a version and send nothing at all.
    pub(super) async fn auto_round_reaches_anyone(&self, threshold: Option<u32>) -> Result<bool> {
        use crate::protocol::types::ChannelStatus;
        let members = self
            .channel_store
            .replicas_matching(
                self.secret_id,
                crate::protocol::types::ReplicaFilter {
                    status: vec![ChannelStatus::Paired, ChannelStatus::Unpairing],
                    exclude: self.exclude_self(),
                    ..Default::default()
                },
            )
            .await?;
        if !members.is_empty() {
            return Ok(true);
        }
        let helpers = self
            .channel_store
            .helpers_matching(
                self.secret_id,
                crate::protocol::types::HelperFilter {
                    status: vec![ChannelStatus::Paired],
                    role: Some(derec_proto::SenderKind::Helper),
                    ..Default::default()
                },
            )
            .await?;
        let subshares: u64 = helpers.iter().map(|h| u64::from(h.weight)).sum();
        let threshold = threshold.map_or(self.threshold as u64, u64::from);
        Ok(subshares >= threshold)
    }

    /// The channels among `channels` on which this device holds a share it
    /// distributed. Read before an unpair drops a channel, since the drop
    /// removes those shares.
    pub(super) async fn share_holders(
        &self,
        channels: impl IntoIterator<Item = ChannelId>,
    ) -> Result<HashSet<ChannelId>> {
        let mut holders = HashSet::new();
        for channel_id in channels {
            if !self
                .share_store
                .load(self.secret_id, channel_id, &[])
                .await?
                .is_empty()
            {
                holders.insert(channel_id);
            }
        }
        Ok(holders)
    }

    /// [`Self::share_holders`] over every channel awaiting an unpair
    /// acknowledgement — the ones an inbound response or the timeout sweep
    /// can drop. Best effort, like the sweep itself: a store failure leaves
    /// the set empty and the removal republishes nothing.
    pub(super) async fn pending_unpair_share_holders(&self) -> HashSet<ChannelId> {
        let Ok(items) = self
            .state_store
            .load_all(self.secret_id, crate::protocol::StateKind::PendingUnpair)
            .await
        else {
            return HashSet::new();
        };
        let channels = items.into_iter().filter_map(|item| match item {
            crate::protocol::StateItem::PendingUnpair { channel_id, .. } => Some(channel_id),
            _ => None,
        });
        self.share_holders(channels).await.unwrap_or_default()
    }

    /// Start a `ProtectSecret` round the library decided on itself: stored
    /// weights, stored threshold, and the configured `reply_to` policy.
    pub(super) async fn start_auto_protect_secret(
        &mut self,
        secrets: Vec<crate::protocol::types::UserSecret>,
        description: Option<String>,
    ) -> Result<Vec<DeRecEvent>> {
        let reply_to: Vec<derec_proto::TransportProtocol> = if self.auto_reply_to {
            self.own_transports.clone()
        } else {
            Vec::new()
        };
        self.start_protect_secret(
            secrets,
            description,
            None,
            None,
            &Round {
                reply_to: &reply_to,
                trace_id: crate::derec_message::fresh_trace_id(),
            },
        )
        .await
    }

    // TODO: revisit this name
    async fn a_usable_helper_just_paired(&self, events: &[DeRecEvent]) -> Result<bool> {
        for event in events {
            let DeRecEvent::PairingCompleted {
                kind: derec_proto::SenderKind::Owner,
                channel_id,
                ..
            } = event
            else {
                continue;
            };
            if self
                .channel_store
                .load(
                    self.secret_id,
                    crate::protocol::types::ChannelQuery::Helper {
                        channel_id: *channel_id,
                    },
                )
                .await?
                .is_some_and(|record| {
                    record.status() == crate::protocol::types::ChannelStatus::Paired
                })
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns `true` when at least one channel records a
    /// `ReplicaDestination` peer in `Paired` status — i.e. a Destination
    /// that is fully verified and eligible for secret sync.
    pub(super) async fn has_paired_replica_destination(&self) -> Result<bool> {
        let members = self
            .channel_store
            .replicas_matching(
                self.secret_id,
                crate::protocol::types::ReplicaFilter {
                    status: vec![crate::protocol::types::ChannelStatus::Paired],
                    role: Some(crate::protocol::types::ReplicaRole::Destination),
                    exclude: self.exclude_self(),
                    ..Default::default()
                },
            )
            .await?;
        Ok(!members.is_empty())
    }
}
