// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Resolving a [`PendingAction`].
//!
//! A flow that needs the application's decision surfaces
//! [`DeRecEvent::ActionRequired`] and stops. [`DeRecProtocol::accept`] and
//! [`DeRecProtocol::reject`] are how that decision comes back, and each
//! dispatches on the action to the handler that raised it.
//!
//! - [`resolve`]: the dispatch from an action to its handler.
//! - [`auto_accept`]: resolving the actions the configured
//!   [`AutoAcceptPolicy`](crate::protocol::AutoAcceptPolicy) opts into, inside `process`.

mod auto_accept;
mod resolve;

use super::DeRecProtocol;
use super::context::local;
use super::events::{DeRecEvent, PendingAction};
use super::obligation::{Obligation, settle};
use super::stores::borrow_stores;
use super::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use crate::Result;
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
    /// or by passing the event's [`Action::RespondToFailure`](crate::protocol::Action::RespondToFailure) to
    /// [`reject`](Self::reject).
    ///
    /// Before acting, a persisted action is checked against its channel. A
    /// channel that is gone or no longer `Paired` has nothing to answer on,
    /// so that is an `Err` ([`crate::Error::InvalidInput`]) and nothing is
    /// stored or sent. A channel whose peer no longer holds the role the flow
    /// requires is answered `REJECTED`, like any other answerable failure.
    ///
    /// The action carries no key: the response is encrypted under the shared
    /// key stored for the action's channel, loaded when `accept` runs. Under
    /// that key `accept` first checks the action's seal, so an action that
    /// was altered, built by hand or moved to another channel is an `Err`
    /// ([`crate::Error::InvalidInput`]) and nothing is stored or sent. So is
    /// one whose channel has no stored key, which can be neither checked nor
    /// answered.
    ///
    /// `Err` is left for what cannot be answered: the checks above, a
    /// [`Action::RespondToFailure`](crate::protocol::Action::RespondToFailure) (which only `reject` resolves),
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
        self.check_seal(&action).await?;
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
    /// [`ChannelRequest::StoreShare`](crate::protocol::ChannelRequest::StoreShare) carries the already-decrypted,
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
    ///     match action.action() {
    ///         Action::Request(ChannelRequest::StoreShare(request)) => {
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
    /// [`Action::RespondToFailure`](crate::protocol::Action::RespondToFailure), carried by
    /// [`DeRecEvent::RequestFailed`], is resolved here: the request is sent
    /// its own response type with `status` and `memo`, encrypted under the
    /// key of the token's reply channel and delivered to its endpoints. A
    /// body that could not be decoded or a request the channel cannot carry
    /// names no request type the channel answers, so its token is answered
    /// with an `ErrorResponseMessage`. Passing the event's own `status` and
    /// `memo` sends the response `auto_respond_on_failure` would have sent.
    ///
    /// The response is encrypted under the shared key stored for the
    /// action's channel, loaded when `reject` runs. An action whose seal does
    /// not verify under that key, or whose channel has no stored key, fails
    /// with [`crate::Error::InvalidInput`] and nothing is sent.
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
        self.check_seal(&action).await?;
        let obligation = Obligation::for_action(&action, local!(self).policy);
        let obligation = obligation.as_ref();
        self.reject_inner(action, obligation, status, memo).await
    }
}

#[cfg(test)]
mod tests;
