// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Unpair-acknowledgement timeouts.

use crate::protocol::context::local;
use crate::protocol::events::DeRecEvent;
use crate::protocol::stores::borrow_stores;
use crate::protocol::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use crate::protocol::types::{StateItem, StateKey, StateKind};
use crate::protocol::{DeRecProtocol, handlers};
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
    /// Drop local state for any pending unpair whose acknowledgement window has
    /// elapsed, returning an `Unpaired` event per dropped channel.
    ///
    /// The expired channels are dropped together, and their pending entries
    /// removed only after that, in one write: an entry is the only record that
    /// a channel still has to go, so it outlives the drop. The `Unpaired`
    /// events are reported once both have succeeded. A failure of either is
    /// logged and reports nothing; the next sweep finds the same entries and
    /// repeats the drop, which is idempotent, so it completes there.
    ///
    /// A drop that succeeds followed by an entry removal that fails is
    /// reported by the next sweep, which no longer finds the dropped shares,
    /// so the republish that follows an unpair does not run for it.
    pub(super) async fn check_unpair_timeouts(&mut self) -> Vec<DeRecEvent> {
        let now = now_secs();
        let all = match self
            .state_store
            .load_all(self.secret_id, StateKind::PendingUnpair)
            .await
        {
            Ok(items) => items,
            Err(_error) => {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    error = %_error,
                    "pending unpairs could not be loaded; none times out this time"
                );
                return Vec::new();
            }
        };

        let expired: Vec<ChannelId> = all
            .into_iter()
            .filter_map(|item| match item {
                StateItem::PendingUnpair {
                    channel_id,
                    started_at,
                } if now.saturating_sub(started_at) > self.timeouts.unpair_ack.as_secs() => {
                    Some(channel_id)
                }
                _ => None,
            })
            .collect();
        if expired.is_empty() {
            return Vec::new();
        }

        if let Err(_error) = handlers::unpairing::drop_channels_state(
            &mut borrow_stores!(self),
            &local!(self),
            &expired,
        )
        .await
        {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channels = ?expired,
                error = %_error,
                "timed-out unpairs could not be dropped; they are dropped again next time"
            );
            return Vec::new();
        }

        let entries: Vec<StateKey> = expired
            .iter()
            .map(|&channel_id| StateKey::PendingUnpair { channel_id })
            .collect();
        if let Err(_error) = self.state_store.remove_many(self.secret_id, &entries).await {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channels = ?expired,
                error = %_error,
                "timed-out unpairs were dropped but are still pending; they are reported next time"
            );
            return Vec::new();
        }

        expired
            .into_iter()
            .map(|channel_id| DeRecEvent::Unpaired { channel_id })
            .collect()
    }
}
