// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::UserSecret;
use derec_library::protocol::DeRecFlow;
use derec_library::types::ChannelId;
use derec_proto::{ContactMode, SenderKind};
use std::collections::HashMap;

use crate::peer::{Peer, pump_many};

/// Drive a full Owner↔Helper InlineKeys pair handshake. Returns the
/// `ChannelId` both sides converge on (which may differ from the
/// initial `channel_id` the contact was minted with).
pub async fn pair_owner_helper(
    owner: &mut Peer,
    helper: &mut Peer,
    channel_id: ChannelId,
) -> ChannelId {
    let contact = owner
        .protocol
        .create_contact(Some(channel_id), ContactMode::InlineKeys, None)
        .await
        .expect("owner.create_contact failed");

    helper
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact,
            peer_communication_info: HashMap::from([(
                "name".to_owned(),
                helper.label.to_owned(),
            )]),
        })
        .await
        .expect("helper.start(Pairing) failed");

    let events = pump_many(&mut [owner, helper]).await;

    events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::PairingCompleted { channel_id, .. } => Some(*channel_id),
            _ => None,
        })
        .expect("expected PairingCompleted while pumping pair handshake")
}

/// Start a `ProtectSecret` round on the owner with a single
/// `UserSecret` payload, then pump until quiescent.
pub async fn protect_secret(
    owner: &mut Peer,
    helpers: &mut [&mut Peer],
    user_secret: UserSecret,
    description: &str,
) -> Vec<DeRecEvent> {
    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![user_secret],
            description: Some(description.to_owned()),
        })
        .await
        .expect("owner.start(ProtectSecret) failed");

    let mut all: Vec<&mut Peer> = Vec::with_capacity(1 + helpers.len());
    all.push(owner);
    for h in helpers.iter_mut() {
        all.push(&mut **h);
    }
    pump_many(&mut all).await
}
