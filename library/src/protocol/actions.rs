// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Resolving a [`PendingAction`].
//!
//! A flow that needs the application's decision surfaces
//! [`DeRecEvent::ActionRequired`](crate::protocol::DeRecEvent::ActionRequired) and stops. [`DeRecProtocol::accept`] and
//! [`DeRecProtocol::reject`] are how that decision comes back, and each
//! dispatches on the action to the handler that raised it.

use super::context::{Exchange, Round, local, pairing_config};
use super::events::{DeRecEvent, PendingAction};
use super::obligation::{Obligation, respond_to_failure, settle};
use super::stores::borrow_stores;
use super::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use super::{DeRecProtocol, handlers};
use crate::Result;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::types::ChannelId;
use derec_proto::StatusEnum;
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
    /// Accept a pending action from an [`DeRecEvent::ActionRequired`] event.
    ///
    /// Executes the "do work + send response" path for the given action,
    /// returning the same events that auto-respond would have produced.
    ///
    /// # Failures
    ///
    /// A failure of the request the action answers is **not** an `Err`. It is
    /// reported as [`DeRecEvent::RequestFailed`] in the returned events, and
    /// the request is answered exactly once: by the library under
    /// [`with_auto_respond_on_failure`](crate::protocol::DeRecProtocolBuilder::with_auto_respond_on_failure),
    /// or by passing the event's [`PendingAction::RespondToFailure`] to
    /// [`reject`](Self::reject).
    ///
    /// Before acting, a persisted action is checked against its channel. A
    /// channel that is gone or no longer `Paired` has nothing to answer on,
    /// so that is an `Err` ([`crate::Error::InvalidInput`]) and nothing is
    /// stored or sent. A channel whose peer no longer holds the role the flow
    /// requires is answered `REJECTED`, like any other answerable failure.
    ///
    /// `Err` is left for what cannot be answered: the checks above, a
    /// [`PendingAction::RespondToFailure`] (which only `reject` resolves),
    /// failures of the pairing handshake, and a failure of the publish that
    /// follows a completed pairing.
    ///
    /// That publish runs after the pairing is complete and its response has
    /// been sent. It reuses every Helper's stored weight, and a stored weight
    /// the round's threshold no longer allows fails it with
    /// [`SharingError::InvalidWeight`](crate::primitives::sharing::SharingError::InvalidWeight)
    /// before anything is sent. `accept` then returns that `Err`: the channel
    /// is `Paired` on both sides, but the [`DeRecEvent::PairingCompleted`]
    /// event is not returned. Call
    /// `start(`[`DeRecFlow::ProtectSecret`](crate::protocol::DeRecFlow::ProtectSecret)`)`
    /// with valid weights to publish to every Helper, the new one included.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = action.trace_id())))]
    pub async fn accept(&mut self, action: PendingAction) -> Result<Vec<DeRecEvent>> {
        let obligation = Obligation::for_action(&action, local!(self).policy);
        let mut events = match &obligation {
            Some(obligation) => {
                let outcome = match self.still_answerable(&action).await? {
                    Ok(()) => self.accept_inner(action, Some(obligation)).await,
                    Err(failure) => Err(failure),
                };
                settle(
                    &mut borrow_stores!(self),
                    &local!(self),
                    obligation,
                    self.auto_respond_on_failure,
                    outcome,
                )
                .await
            }
            None => self.accept_inner(action, None).await?,
        };
        let auto_publish_events = self.maybe_auto_publish(&events, &HashSet::new()).await?;
        events.extend(auto_publish_events);
        Ok(events)
    }

    /// Re-check a persisted action against the channel it answers on.
    ///
    /// `Err` when the channel is gone or no longer `Paired`: there is nothing
    /// to answer on. `Ok(Err(..))` is an answerable failure — the peer no
    /// longer holds the role the flow requires, or the channel could not be
    /// read — for the router to answer.
    async fn still_answerable(&self, action: &PendingAction) -> Result<Result<()>> {
        use crate::protocol::types::{ChannelQuery, ChannelStatus};
        use derec_proto::SenderKind;

        let (channel_id, required) = match action {
            PendingAction::StoreShare { channel_id, .. }
            | PendingAction::VerifyShare { channel_id, .. }
            | PendingAction::Discovery { channel_id, .. }
            | PendingAction::GetShare { channel_id, .. }
            | PendingAction::Unpair { channel_id, .. } => (*channel_id, Some(SenderKind::Owner)),
            PendingAction::UpdateChannelInfo { channel_id, .. } => (*channel_id, None),
            PendingAction::Pairing { .. }
            | PendingAction::PrePair { .. }
            | PendingAction::RespondToFailure { .. } => return Ok(Ok(())),
        };
        let record = match self
            .channel_store
            .load(self.secret_id, ChannelQuery::Helper { channel_id })
            .await
        {
            Ok(record) => record,
            Err(error) => return Ok(Err(error.into())),
        };
        let Some(channel) = record
            .as_ref()
            .and_then(|r| r.as_helper())
            .filter(|c| c.status == ChannelStatus::Paired)
        else {
            return Err(crate::Error::InvalidInput(
                "the action's channel is no longer paired",
            ));
        };
        Ok(match required {
            Some(expected) if channel.peer_role != expected => Err(crate::Error::RoleMismatch {
                channel_id,
                expected,
                actual: channel.peer_role,
            }),
            _ => Ok(()),
        })
    }

    /// Reject a pending action from an [`DeRecEvent::ActionRequired`] event.
    ///
    /// Builds and sends a rejection response to the peer with the given status
    /// and memo. The `status` parameter allows the caller to specify the exact
    /// failure reason (e.g. [`StatusEnum::Rejected`], [`StatusEnum::Fail`],
    /// [`StatusEnum::TooFrequent`], etc.).
    ///
    /// # Helper-side admission control
    ///
    /// This is where a helper enforces limits on inbound shares beyond
    /// what the library already checks. This device's own configured
    /// `minShareSize`/`maxShareSize` from [`derec_proto::ParameterRange`]
    /// (see [`DeRecProtocolBuilder::with_parameter_range`](crate::protocol::DeRecProtocolBuilder::with_parameter_range))
    /// is enforced by the library itself against every inbound share's
    /// actual length, before `ActionRequired` is ever raised — a share
    /// outside that range never reaches this gate at all. The protocol
    /// still imposes no bound of its own on storage per sharer or update
    /// frequency; an app with a *tighter or per-user* size limit, or any
    /// other reason to decline a share, uses this gate for that.
    ///
    /// [`PendingAction::StoreShare`] carries the already-decrypted,
    /// already-parsed [`derec_proto::StoreShareRequestMessage`], so the
    /// application inspects the share without touching wire bytes,
    /// envelopes or key material:
    ///
    /// The application context (`my_app`, its per-user limits) is yours, so
    /// this is illustrative rather than a compiled example:
    ///
    /// ```text
    /// for event in protocol.process(&wire_bytes).await? {
    ///     let DeRecEvent::ActionRequired { action, channel_id } = event else { continue };
    ///     match &action {
    ///         PendingAction::StoreShare { request, .. } => {
    ///             // `channel_id` maps to a user in the application's own
    ///             // store, so the limit can be per-user, per-plan, or
    ///             // whatever the deployment needs.
    ///             let limit = my_app.share_limit_for(channel_id);
    ///             if request.share.len() > limit {
    ///                 protocol
    ///                     .reject(
    ///                         action,
    ///                         StatusEnum::SizeLimitExceeded,
    ///                         &format!("share exceeds the {limit}-byte limit"),
    ///                     )
    ///                     .await?;
    ///             } else {
    ///                 protocol.accept(action).await?;
    ///             }
    ///         }
    ///         _ => { protocol.accept(action).await?; }
    ///     }
    /// }
    /// ```
    ///
    /// The owner receives a `StoreShareResponse` carrying that status and
    /// memo, surfacing as [`DeRecEvent::ShareRejected`] on its side — so
    /// the failure is attributable rather than a silent timeout.
    ///
    /// [`StatusEnum::SizeLimitExceeded`] is the protocol's designated code
    /// for this case; [`StatusEnum::TooFrequent`] covers rate limiting and
    /// [`StatusEnum::Rejected`] a user-declined request.
    ///
    /// This gate exists only while
    /// [`AutoAcceptPolicy::store_share`](crate::protocol::AutoAcceptPolicy::store_share)
    /// is `false`. Enabling it makes `process()` accept and store every
    /// inbound share internally, and no `ActionRequired` is emitted to
    /// reject.
    ///
    /// # Answering a failed request
    ///
    /// [`PendingAction::RespondToFailure`], carried by
    /// [`DeRecEvent::RequestFailed`], is resolved here: the request is sent
    /// its own response type with `status` and `memo`, encrypted under the
    /// key of the token's reply channel and delivered to its endpoints. A
    /// body that could not be decoded or a request the channel cannot carry
    /// names no request type the channel answers, so its token is answered
    /// with an `ErrorResponseMessage`. Passing the event's own `status` and
    /// `memo` sends the response `auto_respond_on_failure` would have sent.
    ///
    /// The library is stateless and never expires an action, so it cannot
    /// tell an action it has already resolved from a fresh one: rejecting the
    /// same token twice, or rejecting a copy of an action already accepted,
    /// sends a second response. Resolving each action once is the
    /// application's part.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = action.trace_id())))]
    pub async fn reject(
        &mut self,
        action: PendingAction,
        status: StatusEnum,
        memo: &str,
    ) -> Result<()> {
        let obligation = Obligation::for_action(&action, local!(self).policy);
        let obligation = obligation.as_ref();
        match action {
            PendingAction::Pairing {
                channel_id,
                request,
                trace_id,
                ..
            } => {
                handlers::pairing::pair::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    channel_id,
                    &request,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
            PendingAction::StoreShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::sharing::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                    status,
                    memo,
                )
                .await
            }
            PendingAction::VerifyShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::verification::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                    status,
                    memo,
                )
                .await
            }
            PendingAction::Discovery {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::discovery::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                    status,
                    memo,
                )
                .await
            }
            PendingAction::GetShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::recovery::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                    status,
                    memo,
                )
                .await
            }
            PendingAction::Unpair {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::unpairing::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                    status,
                    memo,
                )
                .await
            }
            PendingAction::UpdateChannelInfo {
                channel_id,
                shared_key,
                trace_id,
                ..
            } => {
                handlers::update_channel_info::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    status,
                    memo,
                )
                .await
            }
            PendingAction::PrePair {
                channel_id,
                request,
                trace_id,
            } => {
                handlers::pairing::pre_pair::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    channel_id,
                    &request,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
            PendingAction::RespondToFailure {
                channel_id,
                trace_id,
                reply,
                request,
            } => {
                let obligation = Obligation::for_failure(
                    channel_id,
                    trace_id,
                    &reply,
                    request,
                    local!(self).policy,
                );
                respond_to_failure(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &obligation,
                    status,
                    memo,
                )
                .await
            }
        }
    }

    /// Walk the post-`process_inner` event list and apply the
    /// [`AutoAcceptPolicy`]: each `ActionRequired` whose action kind
    /// the policy opts into is replaced with `AutoAccepted` plus the
    /// flow events `accept_inner(action)` produces. Other events pass
    /// through unchanged.
    ///
    /// An answerable failure of the accepted request is settled in place —
    /// answered or tokenized as [`DeRecEvent::RequestFailed`] — so
    /// `AutoAccepted` and the rest of the batch are kept. Only a pairing
    /// failure, which has no channel request to answer, is an `Err`.
    pub(super) async fn apply_auto_accept(
        &mut self,
        events: Vec<DeRecEvent>,
    ) -> Result<Vec<DeRecEvent>> {
        let mut out = Vec::with_capacity(events.len());
        for event in events {
            match event {
                DeRecEvent::ActionRequired { channel_id, action }
                    if self.auto_accept.allows(&action) =>
                {
                    let action_kind = action.kind();
                    out.push(DeRecEvent::AutoAccepted {
                        channel_id,
                        action_kind,
                    });
                    match Obligation::for_action(&action, local!(self).policy) {
                        Some(obligation) => {
                            let outcome = self.accept_inner(action, Some(&obligation)).await;
                            out.extend(
                                settle(
                                    &mut borrow_stores!(self),
                                    &local!(self),
                                    &obligation,
                                    self.auto_respond_on_failure,
                                    outcome,
                                )
                                .await,
                            );
                        }
                        None => out.extend(self.accept_inner(action, None).await?),
                    }
                }
                other => out.push(other),
            }
        }
        Ok(out)
    }

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
            .load_all(self.secret_id, super::StateKind::PendingUnpair)
            .await
        else {
            return HashSet::new();
        };
        let channels = items.into_iter().filter_map(|item| match item {
            super::StateItem::PendingUnpair { channel_id, .. } => Some(channel_id),
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

    /// This device's own row, as a
    /// [`ReplicaFilter::exclude`](crate::protocol::types::ChannelFilter::exclude)
    /// list. See [`Local::exclude_self`](crate::protocol::context::Local::exclude_self).
    pub(super) fn exclude_self(&self) -> Vec<crate::types::ReplicaId> {
        self.replica_id
            .map(crate::types::ReplicaId)
            .into_iter()
            .collect()
    }

    async fn accept_inner(
        &mut self,
        action: PendingAction,
        obligation: Option<&Obligation>,
    ) -> Result<Vec<DeRecEvent>> {
        match action {
            PendingAction::Pairing {
                channel_id,
                request,
                kind,
                trace_id,
                ..
            } => {
                handlers::pairing::pair::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &pairing_config!(self),
                    channel_id,
                    &request,
                    kind,
                    trace_id,
                )
                .await
            }
            PendingAction::StoreShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::sharing::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                )
                .await
            }
            PendingAction::VerifyShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::verification::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                )
                .await
            }
            PendingAction::Discovery {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::discovery::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                )
                .await
            }
            PendingAction::GetShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::recovery::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                )
                .await
            }
            PendingAction::Unpair {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::unpairing::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                )
                .await
            }
            PendingAction::UpdateChannelInfo {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::update_channel_info::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                        obligation,
                    },
                    &request,
                )
                .await
            }
            PendingAction::PrePair {
                channel_id,
                request,
                trace_id,
            } => {
                handlers::pairing::pre_pair::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    channel_id,
                    &request,
                    trace_id,
                )
                .await
            }
            PendingAction::RespondToFailure { .. } => Err(crate::Error::InvalidInput(
                "a failed request can only be rejected",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::tests::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::protocol::types::SecretValue;
    use crate::types::ChannelId;

    const SECRET_ID: u64 = 0xF2;
    const CHANNEL: ChannelId = ChannelId(4242);
    const NONCE: u64 = 0xABCD;

    /// A NoKeys contact is the cheapest way into `pre_pair::accept`: it needs
    /// only a stored `PairingContact` whose nonce the request echoes.
    async fn seed_no_keys_contact(secrets: &mut InMemSecretStore) {
        secrets
            .save(
                SECRET_ID,
                CHANNEL,
                SecretValue::PairingContact(derec_proto::ContactMessage {
                    channel_id: CHANNEL.0,
                    contact_mode: derec_proto::ContactMode::NoKeys as i32,
                    nonce: NONCE,
                    ..Default::default()
                }),
            )
            .await
            .expect("seed NoKeys pairing contact");
    }

    fn request_answering_on(uri: &str, protocol: derec_proto::Protocol) -> PendingAction {
        PendingAction::PrePair {
            channel_id: CHANNEL,
            request: derec_proto::PrePairRequestMessage {
                nonce: NONCE,
                supported_transports: vec![derec_proto::TransportProtocol {
                    uri: uri.to_owned(),
                    protocol: protocol as i32,
                }],
                timestamp: None,
            },
            trace_id: 0,
        }
    }

    fn build(
        secrets: InMemSecretStore,
        unsafe_connection: bool,
    ) -> DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
        NoopTransport,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets)
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .with_unsafe_connection(unsafe_connection)
            .build()
            .expect("test protocol builds")
    }

    /// The gap this guards: a peer asking to be answered over LAN plaintext
    /// was dialled regardless of `unsafe_connection`, because this path
    /// validated the endpoint's *structure* and never applied the policy.
    #[test]
    fn lan_plaintext_reply_endpoint_is_refused() {
        run_async(async {
            let secrets = InMemSecretStore::default();
            let mut seeded = secrets.clone();
            seed_no_keys_contact(&mut seeded).await;

            let mut protocol = build(secrets, false);
            let err = protocol
                .accept(request_answering_on(
                    "http://192.168.1.42:8080",
                    derec_proto::Protocol::Https,
                ))
                .await
                .expect_err("LAN plaintext must not be dialled without the flag");

            // Endpoints are filtered rather than fail-fasted, so a request
            // whose *every* endpoint is refused reports that none was usable.
            // The guarantee is unchanged: plaintext is not dialled.
            assert!(
                matches!(err, crate::Error::NoUsableEndpoint { offered: 1 }),
                "expected a no-usable-endpoint refusal, got {err:?}"
            );
        });
    }

    /// Same request succeeds once plaintext is opted into, proving the
    /// refusal above comes from the policy rather than from the fixture.
    #[test]
    fn lan_plaintext_reply_endpoint_is_accepted_with_the_flag() {
        run_async(async {
            let secrets = InMemSecretStore::default();
            let mut seeded = secrets.clone();
            seed_no_keys_contact(&mut seeded).await;

            let mut protocol = build(secrets, true);
            protocol
                .accept(request_answering_on(
                    "http://192.168.1.42:8080",
                    derec_proto::Protocol::Https,
                ))
                .await
                .expect("plaintext is dialled once unsafe_connection is set");
        });
    }

    /// A requester offering both is answered over the secure one rather than
    /// refused outright — one bad endpoint does not sink the request.
    #[test]
    fn a_plaintext_entry_is_skipped_when_a_secure_one_is_offered() {
        run_async(async {
            let secrets = InMemSecretStore::default();
            let mut seeded = secrets.clone();
            seed_no_keys_contact(&mut seeded).await;

            let mut protocol = build(secrets, false);
            protocol
                .accept(PendingAction::PrePair {
                    channel_id: CHANNEL,
                    request: derec_proto::PrePairRequestMessage {
                        nonce: NONCE,
                        supported_transports: vec![
                            derec_proto::TransportProtocol {
                                uri: "http://192.168.1.42:8080".to_owned(),
                                protocol: derec_proto::Protocol::Https as i32,
                            },
                            derec_proto::TransportProtocol {
                                uri: "https://helper.example.com".to_owned(),
                                protocol: derec_proto::Protocol::Https as i32,
                            },
                        ],
                        timestamp: None,
                    },
                    trace_id: 0,
                })
                .await
                .expect("the secure entry survives the plaintext one");
        });
    }

    /// A failed request has no success to send, so the token can only be
    /// rejected.
    #[test]
    fn accepting_a_failed_request_is_refused() {
        run_async(async {
            let mut protocol = build(InMemSecretStore::default(), false);
            let err = protocol
                .accept(PendingAction::RespondToFailure {
                    channel_id: CHANNEL,
                    trace_id: 1,
                    reply: crate::protocol::ReplyTarget {
                        channel_id: CHANNEL,
                        endpoints: Vec::new(),
                    },
                    request: crate::protocol::FailedRequest::Undecodable,
                })
                .await
                .expect_err("a failed request cannot be accepted");
            assert!(
                matches!(
                    err,
                    crate::Error::InvalidInput("a failed request can only be rejected")
                ),
                "expected InvalidInput, got {err:?}"
            );
        });
    }

    /// The ordinary case stays working: a secure endpoint needs no flag.
    #[test]
    fn secure_reply_endpoint_needs_no_flag() {
        run_async(async {
            let secrets = InMemSecretStore::default();
            let mut seeded = secrets.clone();
            seed_no_keys_contact(&mut seeded).await;

            let mut protocol = build(secrets, false);
            protocol
                .accept(request_answering_on(
                    "https://helper.example.com",
                    derec_proto::Protocol::Https,
                ))
                .await
                .expect("a secure reply endpoint is dialled by default");
        });
    }
}
