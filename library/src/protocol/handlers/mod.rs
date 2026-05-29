// SPDX-License-Identifier: Apache-2.0

pub(super) mod discovery;
pub(super) mod pairing;
pub(super) mod recovery;
pub(super) mod sharing;
pub(super) mod unpairing;
pub(super) mod verification;

use super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    PendingRecovery,
};
use crate::{
    Error, Result,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    types::{ChannelId, SharedKey, Target},
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{DeRecMessage, MessageBody, TransportProtocol};
use prost::Message;
use std::collections::HashMap;

pub(super) async fn resolve_target<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    target: Target,
) -> Result<Vec<ChannelId>> {
    // TODO: this filtering logic should be moved to channels()
    let all_channels = channel_store.channels().await?;
    let all_channel_ids: Vec<ChannelId> = all_channels.iter().map(|c| c.id).collect();

    Ok(match target {
        Target::All => all_channel_ids,
        Target::Single(id) => {
            if all_channel_ids.contains(&id) {
                vec![id]
            } else {
                vec![]
            }
        }
        Target::Many(ids) => ids
            .into_iter()
            .filter(|id| all_channel_ids.contains(id))
            .collect(),
    })
}

pub(super) async fn peer_endpoint<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    channel_id: ChannelId,
) -> Result<TransportProtocol> {
    let channel = channel_store.load(channel_id).await?;
    channel
        .map(|ch| ch.transport)
        .ok_or(Error::InvalidInput("no transport endpoint for channel"))
}

pub(super) async fn send_channel_message<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    body: MessageBody,
    shared_key: &SharedKey,
) -> Result<()> {
    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(current_timestamp())
        .message_body(body)
        .encrypt(shared_key)?
        .build()?;

    let wire_bytes = envelope.encode_to_vec();
    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, wire_bytes).await?;
    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle<Ch: DeRecChannelStore, Sh: DeRecShareStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    pending_recovery: &mut PendingRecovery,
    pending_unpair: &mut HashMap<ChannelId, u64>,
    message: &DeRecMessage,
    channel_id: ChannelId,
    shared_key: &SharedKey,
) -> Result<Vec<DeRecEvent>> {
    let inner = crate::derec_message::extract_inner_message(&message.message, shared_key)?;

    match &inner {
        MessageBody::StoreShareRequest(_) | MessageBody::StoreShareResponse(_) => {
            sharing::handle(channel_id, inner, *shared_key)
        }
        MessageBody::VerifyShareRequest(_) | MessageBody::VerifyShareResponse(_) => {
            verification::handle(share_store, channel_id, inner, *shared_key).await
        }
        MessageBody::GetSecretIdsVersionsRequest(_)
        | MessageBody::GetSecretIdsVersionsResponse(_) => {
            discovery::handle(channel_id, inner, *shared_key)
        }
        MessageBody::GetShareRequest(_) | MessageBody::GetShareResponse(_) => {
            recovery::handle(pending_recovery, channel_id, inner, *shared_key)
        }
        MessageBody::UnpairRequest(_) | MessageBody::UnpairResponse(_) => {
            unpairing::handle(
                channel_store,
                share_store,
                secret_store,
                pending_unpair,
                channel_id,
                inner,
                *shared_key,
            )
            .await
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in channel message",
        )),
    }
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn handle_pairing<Ch: DeRecChannelStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    message: &DeRecMessage,
    channel_id: ChannelId,
    pairing_secret: &PairingSecretKeyMaterial,
) -> Result<Vec<DeRecEvent>> {
    let inner =
        crate::derec_message::extract_inner_pairing_message(&message.message, pairing_secret)?;

    pairing::handle(
        channel_store,
        secret_store,
        &inner,
        channel_id,
        pairing_secret,
    )
    .await
}
