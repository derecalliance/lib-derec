// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Resolving, inside `process`, the actions the configured
//! [`AutoAcceptPolicy`](crate::protocol::AutoAcceptPolicy) opts into.

use crate::Result;
use crate::protocol::DeRecProtocol;
use crate::protocol::context::local;
use crate::protocol::events::DeRecEvent;
use crate::protocol::obligation::{Obligation, settle};
use crate::protocol::stores::borrow_stores;
use crate::protocol::traits::{
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
    /// Walk the post-`process_inner` event list and apply the
    /// [`AutoAcceptPolicy`](crate::protocol::AutoAcceptPolicy): each `ActionRequired` whose action kind
    /// the policy opts into is replaced with `AutoAccepted` plus the
    /// flow events `accept_inner(action)` produces. Other events pass
    /// through unchanged.
    ///
    /// An answerable failure of the accepted request is settled in place —
    /// answered or tokenized as [`DeRecEvent::RequestFailed`] — so
    /// `AutoAccepted` and the rest of the batch are kept. Only a pairing
    /// failure, which has no channel request to answer, is an `Err`.
    pub(in crate::protocol) async fn apply_auto_accept(
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
}
