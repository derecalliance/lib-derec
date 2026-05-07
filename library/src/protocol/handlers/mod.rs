// SPDX-License-Identifier: Apache-2.0

pub(super) mod discovery;
pub(super) mod pairing;
pub(super) mod recovery;
pub(super) mod sharing;
pub(super) mod verification;

use super::{
    DeRecChannelStore, DeRecEvent, DeRecShareStore, DeRecTransport, PendingRecovery,
};
use crate::{
    Error, Result,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    types::{ChannelId, SharedKey},
};
use derec_proto::{DeRecMessage, MessageBody, TransportProtocol};
use prost::Message;

/// Look up the transport endpoint for a paired channel.
pub(super) async fn peer_endpoint<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    channel_id: ChannelId,
) -> Result<TransportProtocol> {
    let channel = channel_store.load(channel_id).await?;
    channel
        .map(|ch| ch.transport)
        .ok_or(Error::InvalidInput("no transport endpoint for channel"))
}

/// Build an encrypted channel message and send it to the peer.
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

/// Decrypt the channel envelope and dispatch to the appropriate flow handler.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(super) async fn handle<Sh: DeRecShareStore>(
    share_store: &mut Sh,
    pending_recovery: &mut PendingRecovery,
    message: &[u8],
    channel_id: ChannelId,
    shared_key: &SharedKey,
) -> Result<Vec<DeRecEvent>> {
    let envelope = DeRecMessage::decode(message).map_err(Error::ProtobufDecode)?;
    let inner = crate::derec_message::extract_inner_message(&envelope.message, shared_key)?;

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
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in channel message",
        )),
    }
}
