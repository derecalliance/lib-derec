// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Recovery and replica version-check timeouts.

use crate::protocol::DeRecProtocol;
use crate::protocol::context::local;
use crate::protocol::events::DeRecEvent;
use crate::protocol::handlers::recovery;
use crate::protocol::handlers::replicas::discovery;
use crate::protocol::stores::borrow_stores;
use crate::protocol::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use crate::protocol::types::{StateItem, StateKey, StateKind};
use crate::types::ChannelId;

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
    /// Conclude a replica version check whose members have stayed silent
    /// longer than
    /// [`Timeouts::get_share_response`](crate::protocol::types::Timeouts::get_share_response),
    /// on the versions already reported.
    pub(super) async fn check_replica_discovery_timeout(&mut self) -> Vec<DeRecEvent> {
        let timeout = self.timeouts.get_share_response;
        let concluded =
            discovery::conclude_if_expired(&mut borrow_stores!(self), &local!(self), timeout).await;
        #[cfg(feature = "logging")]
        if let Err(error) = &concluded {
            tracing::warn!(
                error = %error,
                "replica discovery: concluding the timed-out check failed"
            );
        }
        concluded.unwrap_or_default()
    }

    /// Close every recovery whose share requests have waited longer than
    /// [`Timeouts::get_share_response`](crate::protocol::types::Timeouts::get_share_response),
    /// deciding it on the shares it holds.
    ///
    /// Each Helper still silent is reported as
    /// [`DeRecEvent::RecoverSecretFailed`] with error `"timeout"`, followed by
    /// the recovery's decision. The row is removed before the decision is
    /// reported, so a store failure leaves the recovery open for the next
    /// sweep rather than deciding it twice.
    pub(super) async fn check_recovery_timeouts(&mut self) -> Vec<DeRecEvent> {
        let Ok(recoveries) = self
            .state_store
            .load_all(self.secret_id, StateKind::PendingRecovery)
            .await
        else {
            return vec![];
        };

        let now = now_secs();
        let mut events = Vec::new();
        for item in recoveries {
            let StateItem::PendingRecovery {
                secret_id,
                version,
                shares,
                pending,
                started_at,
            } = item
            else {
                continue;
            };
            if now.saturating_sub(started_at) <= self.timeouts.get_share_response.as_secs() {
                continue;
            }
            let Ok(helpers) =
                recovery::describe_helpers(&self.channel_store, self.secret_id, &shares).await
            else {
                continue;
            };
            if self
                .state_store
                .remove(
                    self.secret_id,
                    StateKey::PendingRecovery { secret_id, version },
                )
                .await
                .is_err()
            {
                continue;
            }

            let mut silent: Vec<ChannelId> = pending.into_iter().collect();
            silent.sort_unstable_by_key(|c| c.0);
            for channel_id in silent {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    channel_id = channel_id.0,
                    secret_id,
                    version,
                    "recovery: helper timed out"
                );
                events.push(DeRecEvent::RecoverSecretFailed {
                    channel_id,
                    version,
                    error: "timeout".to_owned(),
                });
            }
            events.extend(recovery::settle(secret_id, version, &shares, &helpers));
        }
        events
    }
}
