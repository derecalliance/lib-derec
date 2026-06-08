// SPDX-License-Identifier: Apache-2.0

pub(super) mod discovery;
pub(super) mod pairing;
pub(super) mod recovery;
pub(super) mod sharing;
pub(super) mod unpairing;
pub(super) mod update_channel_info;
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
use derec_proto::{DeRecMessage, MessageBody, SenderKind, TransportProtocol};
use prost::Message;
use std::collections::HashMap;

/// Assert that every channel in `channel_ids` carries `expected` as its local
/// role. The protocol's flow directionality (Owner initiates protect/verify/
/// discovery/recovery, Helper accepts) is enforced through this gate.
///
/// Returns the first mismatch as [`crate::Error::RoleMismatch`]; missing
/// channels are also reported as a mismatch against `SenderKind::Owner` of
/// the unknown peer (treated as a programming error — the caller asked the
/// protocol to operate on a channel it doesn't have).
pub(super) async fn require_role<Ch: DeRecChannelStore>(
    channel_store: &Ch,
    channel_ids: &[ChannelId],
    expected: SenderKind,
) -> Result<()> {
    for channel_id in channel_ids {
        let channel = channel_store
            .load(*channel_id)
            .await?
            .ok_or(Error::InvalidInput(
                "channel id not present in channel store",
            ))?;
        if channel.role != expected {
            return Err(Error::RoleMismatch {
                channel_id: *channel_id,
                expected,
                actual: channel.role,
            });
        }
    }
    Ok(())
}

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

/// Re-stamp a primitive-produced wire envelope with `trace_id`.
///
/// The pairing/sharing/verification/discovery/recovery/unpairing primitives
/// build their response envelopes via [`DeRecMessageBuilder`] but don't echo
/// the inbound `traceId` — that's the orchestrator's job (see the field doc
/// on `DeRecMessage.traceId`). This helper decodes the outer envelope (which
/// is plaintext), overwrites `trace_id`, and re-encodes. The encrypted inner
/// `message` field is left untouched, so the cost is one extra proto
/// round-trip with no crypto work.
pub(super) fn apply_trace_id(envelope_bytes: Vec<u8>, trace_id: u64) -> Result<Vec<u8>> {
    let mut envelope = DeRecMessage::decode(envelope_bytes.as_slice()).map_err(|_| {
        Error::Invariant("primitive produced un-decodable response envelope")
    })?;
    envelope.trace_id = trace_id;
    Ok(envelope.encode_to_vec())
}

/// Build and dispatch an encrypted channel-mode response envelope.
///
/// `inbound_trace_id` is the `trace_id` read off the request envelope that
/// triggered this response. Echoed verbatim on the outbound envelope so the
/// requester can correlate (see the field doc on `DeRecMessage.traceId`). Pass
/// `0` when there is no inbound to echo from (e.g. unsolicited messages that
/// don't carry a meaningful correlation handle).
pub(super) async fn send_channel_message<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    body: MessageBody,
    shared_key: &SharedKey,
    inbound_trace_id: u64,
) -> Result<()> {
    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(current_timestamp())
        .message_body(body)
        .trace_id(inbound_trace_id)
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

    if let Some(expected) = expected_role_for_inbound(&inner) {
        require_role(channel_store, &[channel_id], expected).await?;
    }

    let inbound_trace_id = message.trace_id;

    match &inner {
        MessageBody::StoreShareRequest(_) | MessageBody::StoreShareResponse(_) => {
            sharing::handle(channel_id, inner, *shared_key, inbound_trace_id)
        }
        MessageBody::VerifyShareRequest(_) | MessageBody::VerifyShareResponse(_) => {
            verification::handle(share_store, channel_id, inner, *shared_key, inbound_trace_id)
                .await
        }
        MessageBody::GetSecretIdsVersionsRequest(_)
        | MessageBody::GetSecretIdsVersionsResponse(_) => {
            discovery::handle(channel_id, inner, *shared_key, inbound_trace_id)
        }
        MessageBody::GetShareRequest(_) | MessageBody::GetShareResponse(_) => {
            recovery::handle(pending_recovery, channel_id, inner, *shared_key, inbound_trace_id)
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
                inbound_trace_id,
            )
            .await
        }
        MessageBody::UpdateChannelInfoRequest(_) | MessageBody::UpdateChannelInfoResponse(_) => {
            update_channel_info::handle(channel_id, inner, *shared_key, inbound_trace_id).await
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

/// Inbound role-gate table — the local role required on `channel_id` for the
/// orchestrator to honor a given inbound [`MessageBody`].
///
/// Returns `None` for messages that are role-blind (currently only the
/// `UpdateChannelInfo` request/response pair — either side may initiate it).
fn expected_role_for_inbound(body: &MessageBody) -> Option<SenderKind> {
    match body {
        // Helper accepts these; Owner sends them.
        MessageBody::StoreShareRequest(_)
        | MessageBody::VerifyShareRequest(_)
        | MessageBody::GetSecretIdsVersionsRequest(_)
        | MessageBody::GetShareRequest(_)
        | MessageBody::UnpairRequest(_) => Some(SenderKind::Helper),
        // Owner consumes these; Helper sends them.
        MessageBody::StoreShareResponse(_)
        | MessageBody::VerifyShareResponse(_)
        | MessageBody::GetSecretIdsVersionsResponse(_)
        | MessageBody::GetShareResponse(_)
        | MessageBody::UnpairResponse(_) => Some(SenderKind::Owner),
        // Symmetric — either Owner or Helper may initiate.
        MessageBody::UpdateChannelInfoRequest(_) | MessageBody::UpdateChannelInfoResponse(_) => {
            None
        }
        _ => None,
    }
}
