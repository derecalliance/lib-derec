// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The dispatch from a [`PendingAction`] to the handler that resolves it.
//!
//! A request on a paired channel is resolved in one place for every request
//! type: the channel's shared key is loaded and the [`Exchange`] built once,
//! then the request goes to its handler.

use crate::Result;
use crate::extensions::secret_store::SecretStoreExt as _;
use crate::protocol::DeRecProtocol;
use crate::protocol::context::{Exchange, local, pairing_config};
use crate::protocol::events::{Action, ChannelRequest, DeRecEvent, PendingAction};
use crate::protocol::handlers;
use crate::protocol::obligation::{Obligation, respond_to_failure};
use crate::protocol::stores::borrow_stores;
use crate::protocol::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use crate::types::ChannelId;
use derec_proto::StatusEnum;

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
    /// verify under the shared key of the channel that answers it.
    ///
    /// An action whose channel has no stored key cannot be checked, or
    /// answered, so that is an `Err` too. The pairing actions carry no seal
    /// and pass.
    pub(super) async fn check_seal(&self, action: &PendingAction) -> Result<()> {
        let Some(channel_id) = action.sealing_channel() else {
            return Ok(());
        };
        let key = self
            .secret_store
            .paired_key(self.secret_id, channel_id)
            .await?;
        if action.seal_verifies(&key) {
            Ok(())
        } else {
            Err(crate::Error::InvalidInput(
                "the action was altered, or was not raised on this channel",
            ))
        }
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

    /// Dispatch `action` to the handler that accepts it.
    pub(super) async fn accept_inner(
        &mut self,
        action: PendingAction,
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
                    channel_id,
                    &request,
                    trace_id,
                )
                .await
            }
            Action::Request(request) => {
                self.accept_request(channel_id, trace_id, request, obligation)
                    .await
            }
            Action::RespondToFailure { .. } => Err(crate::Error::InvalidInput(
                "a failed request can only be rejected",
            )),
        }
    }

    /// Accept a request that arrived on `channel_id`, answering it under the
    /// channel's shared key.
    async fn accept_request(
        &mut self,
        channel_id: ChannelId,
        trace_id: u64,
        request: ChannelRequest,
        obligation: Option<&Obligation>,
    ) -> Result<Vec<DeRecEvent>> {
        let shared_key = self
            .secret_store
            .paired_key(self.secret_id, channel_id)
            .await?;
        let exchange = Exchange {
            channel_id,
            shared_key: &shared_key,
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

    /// Dispatch `action` to the handler that rejects it.
    pub(super) async fn reject_inner(
        &mut self,
        action: PendingAction,
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
                self.reject_request(channel_id, trace_id, request, obligation, status, memo)
                    .await
            }
            Action::RespondToFailure { reply, request } => {
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

    /// Reject a request that arrived on `channel_id`, answering it under the
    /// channel's shared key.
    async fn reject_request(
        &mut self,
        channel_id: ChannelId,
        trace_id: u64,
        request: ChannelRequest,
        obligation: Option<&Obligation>,
        status: StatusEnum,
        memo: &str,
    ) -> Result<()> {
        let shared_key = self
            .secret_store
            .paired_key(self.secret_id, channel_id)
            .await?;
        let exchange = Exchange {
            channel_id,
            shared_key: &shared_key,
            trace_id,
            obligation,
        };
        let (stores, local) = (&mut borrow_stores!(self), &local!(self));
        match request {
            ChannelRequest::StoreShare(request) => {
                handlers::sharing::reject(stores, local, &exchange, &request, status, memo).await
            }
            ChannelRequest::VerifyShare(request) => {
                handlers::verification::reject(stores, local, &exchange, &request, status, memo)
                    .await
            }
            ChannelRequest::Discovery(request) => {
                handlers::discovery::reject(stores, local, &exchange, &request, status, memo).await
            }
            ChannelRequest::GetShare(request) => {
                handlers::recovery::reject(stores, local, &exchange, &request, status, memo).await
            }
            ChannelRequest::Unpair(request) => {
                handlers::unpairing::reject(stores, local, &exchange, &request, status, memo).await
            }
            ChannelRequest::UpdateChannelInfo(_) => {
                handlers::update_channel_info::reject(stores, local, &exchange, status, memo).await
            }
        }
    }
}
