// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The replica-group side of each flow.
//!
//! Several message families serve both the owner↔helper and the replica-group
//! relationships and mean different things on each. The flow handlers in
//! [`handlers`](super) own the owner↔helper reading and delegate here once
//! [`MessageBodyExt::route`](crate::extensions::message_body::MessageBodyExt::route) has said the
//! payload names an author. Each file is named for the flow it mirrors, so
//! the replica half of discovery is [`discovery`], not something else — the
//! catch-up round a member starts travels as `GetSecretIdsVersions`, so it
//! belongs to discovery however differently the application names it — and
//! removing a member travels as `UnpairRequest`, so it belongs to
//! [`unpairing`] however differently [`DeRecFlow`](crate::protocol::DeRecFlow)
//! names it.
//!
//! A file here holds both directions of its flow, because a member drives the
//! replica half itself rather than only answering: [`unpairing::start`] sends
//! the removal its peers answer in [`unpairing::handle_request`].

pub(in crate::protocol) mod discovery;
pub(in crate::protocol) mod recovery;
pub(in crate::protocol) mod sharing;
pub(in crate::protocol) mod unpairing;

use crate::Result;
use crate::protocol::DeRecChannelStore;
use crate::protocol::context::Local;
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::types::{ChannelRecord, ChannelStatus, ReplicaMember};

/// Mark a member as told-to-leave, preserving everything else about the row.
async fn flag_unpairing<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    member: &ReplicaMember,
) -> Result<()> {
    stores
        .channels
        .save(
            local.secret_id,
            ChannelRecord::Replica(ReplicaMember {
                status: ChannelStatus::Unpairing,
                ..member.clone()
            }),
        )
        .await?;
    Ok(())
}
