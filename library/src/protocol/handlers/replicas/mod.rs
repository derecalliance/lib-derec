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

use crate::Error;
use crate::Result;
use crate::extensions::secret_store::SecretStoreExt as _;
use crate::protocol::DeRecChannelStore;
use crate::protocol::context::Local;
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::types::{ChannelRecord, ChannelStatus, ReplicaMember};
use crate::protocol::{ChannelKey, MissingPolicy};
use crate::types::ChannelId;
use std::collections::HashMap;

/// The current key, with its epoch, of every channel `members` are recorded
/// on.
///
/// Members of a group converge on one channel and one key, but a member that
/// has just joined still talks on its pairing channel until it is handed the
/// group channel, so a message to each member is sealed under the key of that
/// member's own channel.
async fn load_member_keys<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    members: &[ReplicaMember],
) -> Result<HashMap<ChannelId, ChannelKey>> {
    let mut channel_ids: Vec<ChannelId> = Vec::new();
    for member in members {
        if !channel_ids.contains(&member.channel_id) {
            channel_ids.push(member.channel_id);
        }
    }
    stores
        .secrets
        .key_rings_many(local.secret_id, &channel_ids, MissingPolicy::Fail)
        .await?
        .into_iter()
        .map(|(channel_id, ring)| {
            ring.map(|ring| (channel_id, ring.current()))
                .ok_or(Error::Invariant(
                    "the secret store holds no usable key for a member's channel",
                ))
        })
        .collect()
}

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
