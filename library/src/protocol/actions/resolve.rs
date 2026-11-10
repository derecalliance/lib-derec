// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The dispatch from a [`PendingAction`] to the handler that resolves it.
//!
//! A request on a paired channel is resolved in one place for every request
//! type: the channel's shared key is loaded and the [`Exchange`] built once,
//! then the request goes to its handler.

use crate::Result;
use crate::extensions::secret_store::SecretStoreExt as _;
use crate::protocol::context::{Exchange, local, pairing_config};
use crate::protocol::events::{Action, ChannelRequest, DeRecEvent, PendingAction};
use crate::protocol::handlers;
use crate::protocol::obligation::{Obligation, respond_to_failure};
use crate::protocol::stores::borrow_stores;
use crate::protocol::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use crate::protocol::{ChannelKey, DeRecProtocol};
use crate::types::ChannelId;
use derec_proto::StatusEnum;

/// An action answered under a channel key reached its handler without one.
const NO_KEY: crate::Error =
    crate::Error::InvalidInput("the action's channel key was not resolved");

impl<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
> DeRecProtocol<Ch, Sh, Ss, Us, St, T>
{
    /// Refuse an action that is not the one `process` raised: its seal must
    /// verify under the key of the channel that answers it, at the action's
    /// epoch.
    ///
    /// An action whose channel has no stored key cannot be checked, or
    /// answered, so that is an `Err` too, and so is one whose epoch's key can
    /// no longer be obtained: it is too late. The pairing actions carry no
    /// seal and pass.
    ///
    /// Returns the key the action is answered under, `None` for the pairing
    /// actions.
    pub(super) async fn check_seal(&self, action: &PendingAction) -> Result<Option<ChannelKey>> {
        let Some(key) = self.answering_key(action).await? else {
            return Ok(None);
        };
        if action.seal_verifies(&key) {
            Ok(Some(key))
        } else {
            Err(crate::Error::InvalidInput(
                "the action was altered, or was not raised on this channel",
            ))
        }
    }

    /// The key `action` is answered under: the key of its
    /// [`sealing_channel`](PendingAction::sealing_channel) at its epoch, held
    /// by the channel's key ring or derived from an older key it holds.
    /// `None` for the pairing actions, which no channel key answers.
    ///
    /// `Err` when the channel has no stored key, or when the ring can no
    /// longer give that epoch's key because no pin keeps it or a key below
    /// it: the action is too late to answer. That includes an epoch the
    /// ring never reached, such as one above the newest.
    pub(super) async fn answering_key(&self, action: &PendingAction) -> Result<Option<ChannelKey>> {
        let Some(channel_id) = action.sealing_channel() else {
            return Ok(None);
        };
        self.secret_store
            .key_ring(self.secret_id, channel_id)
            .await?
            .ok_or(crate::Error::InvalidInput(
                "channel has no shared key — not yet paired",
            ))?
            .key_at(action.epoch())
            .map(Some)
            .ok_or(crate::Error::InvalidInput(
                "the action can no longer be answered: its channel key is no longer held",
            ))
    }

    /// Re-check a persisted action against the channel it answers on.
    ///
    /// `Err` when the channel is gone or no longer `Paired`: there is nothing
    /// to answer on. `Ok(Err(..))` is an answerable failure — the peer no
    /// longer holds the role the flow requires, or the channel could not be
    /// read — for the router to answer.
    pub(super) async fn still_answerable(&self, action: &PendingAction) -> Result<Result<()>> {
        use crate::protocol::types::{ChannelQuery, ChannelStatus};
        use derec_proto::SenderKind;

        let channel_id = action.channel_id();
        let required = match action.action() {
            Action::Request(ChannelRequest::UpdateChannelInfo(_)) => None,
            Action::Request(_) => Some(SenderKind::Owner),
            Action::Pairing { .. } | Action::PrePair(_) | Action::RespondToFailure { .. } => {
                return Ok(Ok(()));
            }
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

    /// Dispatch `action` to the handler that accepts it. `key` is the key
    /// the action is answered under, from [`Self::answering_key`].
    pub(super) async fn accept_inner(
        &mut self,
        action: PendingAction,
        key: Option<ChannelKey>,
        obligation: Option<&Obligation>,
    ) -> Result<Vec<DeRecEvent>> {
        let (channel_id, trace_id, action) = action.into_parts();
        match action {
            Action::Pairing { request, kind, .. } => {
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
            Action::PrePair(request) => {
                handlers::pairing::pre_pair::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &pairing_config!(self),
                    channel_id,
                    &request,
                    trace_id,
                )
                .await
            }
            Action::Request(request) => {
                let key = key.ok_or(NO_KEY)?;
                self.accept_request(channel_id, &key, trace_id, request, obligation)
                    .await
            }
            Action::RespondToFailure { .. } => Err(crate::Error::InvalidInput(
                "a failed request can only be rejected",
            )),
        }
    }

    /// Accept a request that arrived on `channel_id` under `key`, answering
    /// it under that key.
    async fn accept_request(
        &mut self,
        channel_id: ChannelId,
        key: &ChannelKey,
        trace_id: u64,
        request: ChannelRequest,
        obligation: Option<&Obligation>,
    ) -> Result<Vec<DeRecEvent>> {
        let exchange = Exchange {
            channel_id,
            key,
            trace_id,
            obligation,
        };
        let (stores, local) = (&mut borrow_stores!(self), &local!(self));
        match request {
            ChannelRequest::StoreShare(request) => {
                handlers::sharing::accept(stores, local, &exchange, &request).await
            }
            ChannelRequest::VerifyShare(request) => {
                handlers::verification::accept(stores, local, &exchange, &request).await
            }
            ChannelRequest::Discovery(request) => {
                handlers::discovery::accept(stores, local, &exchange, &request).await
            }
            ChannelRequest::GetShare(request) => {
                handlers::recovery::accept(stores, local, &exchange, &request).await
            }
            ChannelRequest::Unpair(request) => {
                handlers::unpairing::accept(stores, local, &exchange, &request).await
            }
            ChannelRequest::UpdateChannelInfo(request) => {
                handlers::update_channel_info::accept(stores, local, &exchange, &request).await
            }
        }
    }

    /// Dispatch `action` to the handler that rejects it. `key` is the key
    /// the action is answered under, from [`Self::answering_key`].
    pub(super) async fn reject_inner(
        &mut self,
        action: PendingAction,
        key: Option<ChannelKey>,
        obligation: Option<&Obligation>,
        status: StatusEnum,
        memo: &str,
    ) -> Result<()> {
        let (channel_id, trace_id, action) = action.into_parts();
        match action {
            Action::Pairing { request, .. } => {
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
            Action::PrePair(request) => {
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
            Action::Request(request) => {
                let key = key.ok_or(NO_KEY)?;
                let exchange = Exchange {
                    channel_id,
                    key: &key,
                    trace_id,
                    obligation,
                };
                self.reject_request(&exchange, request, status, memo).await
            }
            Action::RespondToFailure { reply, request } => {
                let key = key.ok_or(NO_KEY)?;
                let obligation = Obligation::for_failure(
                    channel_id,
                    trace_id,
                    &reply,
                    request,
                    local!(self).policy,
                );
                obligation.answer_under(key);
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

    /// Reject the request `exchange` answers, under the key it arrived
    /// under.
    async fn reject_request(
        &mut self,
        exchange: &Exchange<'_>,
        request: ChannelRequest,
        status: StatusEnum,
        memo: &str,
    ) -> Result<()> {
        let (stores, local) = (&mut borrow_stores!(self), &local!(self));
        match request {
            ChannelRequest::StoreShare(request) => {
                handlers::sharing::reject(stores, local, exchange, &request, status, memo).await
            }
            ChannelRequest::VerifyShare(request) => {
                handlers::verification::reject(stores, local, exchange, &request, status, memo)
                    .await
            }
            ChannelRequest::Discovery(request) => {
                handlers::discovery::reject(stores, local, exchange, &request, status, memo).await
            }
            ChannelRequest::GetShare(request) => {
                handlers::recovery::reject(stores, local, exchange, &request, status, memo).await
            }
            ChannelRequest::Unpair(request) => {
                handlers::unpairing::reject(stores, local, exchange, &request, status, memo).await
            }
            ChannelRequest::UpdateChannelInfo(_) => {
                handlers::update_channel_info::reject(stores, local, exchange, status, memo).await
            }
        }
    }
}
