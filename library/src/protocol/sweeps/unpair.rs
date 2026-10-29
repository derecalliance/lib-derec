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
    pub(super) async fn check_unpair_timeouts(&mut self) -> Vec<DeRecEvent> {
        let now = now_secs();
        let all = match self
            .state_store
            .load_all(self.secret_id, StateKind::PendingUnpair)
            .await
        {
            Ok(items) => items,
            Err(_) => return Vec::new(),
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

        let mut events = Vec::with_capacity(expired.len());
        for cid in expired {
            let _ = self
                .state_store
                .remove(self.secret_id, StateKey::PendingUnpair { channel_id: cid })
                .await;
            if handlers::unpairing::drop_channel_state(
                &mut borrow_stores!(self),
                &local!(self),
                cid,
            )
            .await
            .is_ok()
            {
                events.push(DeRecEvent::Unpaired { channel_id: cid });
            }
        }
        events
    }
}
