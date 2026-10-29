// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Time-driven work.
//!
//! Nothing in the protocol runs on its own clock: [`DeRecProtocol::tick`] is
//! the application handing over control so deadlines can be checked. A round
//! that never completes, an unpair that is never acknowledged, and a channel
//! that outlives its pairing window are all settled from here.

mod channels;
mod sharing_round;
mod unpair;

use super::DeRecProtocol;
use super::events::DeRecEvent;
use super::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};

impl<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
> DeRecProtocol<Ch, Sh, Ss, Us, St, T>
{
    /// Settle every deadline that has passed, without an inbound message.
    ///
    /// The library keeps no clock of its own. A deadline is checked only when
    /// the application calls in, and [`Self::process`] checks them only when
    /// a message arrives. But a deadline matters exactly when a peer has gone
    /// quiet, so waiting for traffic is not enough: call `tick` on a timer so
    /// that silence still resolves.
    ///
    /// # What gets stuck without it
    ///
    /// On a device that receives nothing:
    ///
    /// - A sharing round whose helpers never answer stays open. No
    ///   [`DeRecEvent::SharingComplete`] or
    ///   [`DeRecEvent::ReplicaSyncComplete`] is ever emitted, and an
    ///   application waiting on either waits forever.
    /// - An unpair under [`UnpairAck::Required`](crate::protocol::UnpairAck::Required)
    ///   whose helper never answers is never dropped: no
    ///   [`DeRecEvent::Unpaired`], and no republish to the helpers that
    ///   remain.
    /// - A `Pending` channel outlives its pairing window together with its
    ///   channel key and pairing material.
    ///
    /// # What it does
    ///
    /// The same time-driven steps [`Self::process`] runs, in the same order;
    /// `process` handles its message between steps 2 and 3:
    ///
    /// 1. Expired-channel cleanup, when
    ///    [`Timeouts::expired_channels`](crate::protocol::types::Timeouts::expired_channels)
    ///    is enabled (the default, at 300 seconds): every `Pending` channel
    ///    older than the window is removed with its key. With
    ///    [`ExpiredChannelCleanup::Disabled`](crate::protocol::ExpiredChannelCleanup::Disabled)
    ///    this step is skipped and [`Self::remove_expired_channels`] is the
    ///    application's to call.
    /// 2. Unpair-acknowledgement timeouts: every unpair older than
    ///    [`Timeouts::unpair_ack`](crate::protocol::types::Timeouts::unpair_ack)
    ///    drops its channel and emits [`DeRecEvent::Unpaired`].
    /// 3. The sharing rounds, each loaded and written once. A round older
    ///    than [`Timeouts::sharing_round`](crate::protocol::types::Timeouts::sharing_round)
    ///    first fails every helper still pending, with
    ///    [`DeRecEvent::ShareRejected`], and reports every member still pending
    ///    [`DeRecEvent::ReplicaSyncFailed`]; those events come first in the
    ///    result. Then the tally closes a round whose participants have all
    ///    settled, emitting [`DeRecEvent::SharingComplete`] (and
    ///    [`DeRecEvent::ReplicaSyncComplete`] for a round with a replica leg).
    /// 4. The republish after an unpair dropped in step 2, when that helper
    ///    held a share (see [`DeRecFlow::Unpair`](crate::protocol::DeRecFlow::Unpair)).
    ///
    /// Nothing else has a deadline: an outstanding
    /// [`DeRecFlow::VerifyShares`](crate::protocol::DeRecFlow::VerifyShares)
    /// challenge, a [`DeRecFlow::RecoverSecret`](crate::protocol::DeRecFlow::RecoverSecret)
    /// collection and a [`DeRecFlow::ReplicaDiscovery`](crate::protocol::DeRecFlow::ReplicaDiscovery)
    /// check stay open until answered, and `tick` does not touch them.
    ///
    /// # Errors
    ///
    /// `tick` never fails. Store failures are swallowed as in
    /// [`Self::process`], so the work is retried on the next call, and a
    /// failed republish in step 4 is logged: the remaining helpers keep the
    /// previous version until the next
    /// [`DeRecFlow::ProtectSecret`](crate::protocol::DeRecFlow::ProtectSecret).
    ///
    /// # Calling it
    ///
    /// Idempotent: with nothing past its deadline it changes no state and
    /// returns an empty vector, so calling it often is cheap. Call it more
    /// often than the shortest configured timeout, since the interval adds
    /// to how late a deadline is noticed. A long-lived process can run it
    /// from a timer task; a service that builds the protocol per request
    /// runs it from its scheduler (a cron job, a queue heartbeat).
    ///
    /// It mutates the same round state an inbound response does, so it must
    /// be serialized against [`Self::process`] for the same `secret_id`. See
    /// [`DeRecStateStore`].
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn tick(&mut self) -> Vec<DeRecEvent> {
        let share_holders = self.pending_unpair_share_holders().await;
        let mut events = self.run_timeout_sweeps().await;
        if let Err(_error) = self.update_sharing_round(&mut events).await {
            #[cfg(feature = "logging")]
            tracing::warn!(
                error = %_error,
                "sharing rounds could not be settled; the next tick settles them again"
            );
        }
        match self.maybe_auto_publish(&events, &share_holders).await {
            Ok(auto_publish_events) => events.extend(auto_publish_events),
            Err(_error) => {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    error = %_error,
                    "publish after an unpair timeout failed; the remaining helpers keep the previous version"
                );
            }
        }
        events
    }

    /// The time-driven sweeps, shared by [`Self::tick`] and [`Self::process`]
    /// so the two cannot drift.
    ///
    /// Sharing-round timeouts are **not** here: they are applied by
    /// [`Self::update_sharing_round`], which `process` and `tick` run at the
    /// end over every event, so each round is loaded and written once per
    /// call.
    pub(in crate::protocol) async fn run_timeout_sweeps(&mut self) -> Vec<DeRecEvent> {
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

        self.check_unpair_timeouts().await
    }
}

#[cfg(test)]
mod tests;
