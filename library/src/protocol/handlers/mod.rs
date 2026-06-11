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
    protocol::types::Target,
    types::{ChannelId, SharedKey},
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

/// Pick the endpoint to deliver a response to.
///
/// If the inbound request carried a `reply_to`, the responder routes there
/// (ephemeral, this exchange only); otherwise it falls back to the channel's
/// stored peer endpoint. See `replyTo` on each request proto for the
/// semantics and the auto-fill switch on the orchestrator
/// ([`crate::protocol::DeRecProtocolBuilder::with_auto_reply_to`]).
pub(super) async fn resolve_response_endpoint<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    channel_id: ChannelId,
    reply_to: Option<&TransportProtocol>,
) -> Result<TransportProtocol> {
    if let Some(endpoint) = reply_to {
        return Ok(endpoint.clone());
    }
    peer_endpoint(channel_store, channel_id).await
}

/// Draw a fresh correlation token for an outbound request envelope.
///
/// Mirrors [`crate::derec_message::DeRecMessageBuilder::auto_trace_id`] but
/// for the orchestrator-level case where the envelope was built by a
/// primitive and is then re-stamped via [`apply_trace_id`]. A `0` return is
/// indistinguishable from "unset", so the chance is 2^-64 of getting a token
/// that downstream code might interpret as "no correlation requested" — not
/// worth coding around.
pub(super) fn fresh_trace_id() -> u64 {
    use rand::Rng as _;
    rand::rng().next_u64()
}

/// Internal wrapper that re-stamps a primitive-produced wire envelope's
/// `trace_id`. Thin alias for [`crate::derec_message::apply_trace_id`] kept
/// inside the handlers module so callers can stay terse with `super::`.
pub(super) fn apply_trace_id(envelope_bytes: Vec<u8>, trace_id: u64) -> Result<Vec<u8>> {
    crate::derec_message::apply_trace_id(&envelope_bytes, trace_id)
}

/// Build and dispatch an encrypted channel-mode response envelope.
///
/// `inbound_trace_id` is the `trace_id` read off the request envelope that
/// triggered this response. Echoed verbatim on the outbound envelope so the
/// requester can correlate (see the field doc on `DeRecMessage.traceId`). Pass
/// `0` when there is no inbound to echo from (e.g. unsolicited messages that
/// don't carry a meaningful correlation handle).
#[allow(clippy::too_many_arguments)]
pub(super) async fn send_channel_message<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    body: MessageBody,
    shared_key: &SharedKey,
    inbound_trace_id: u64,
    reply_to: Option<&TransportProtocol>,
) -> Result<()> {
    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(current_timestamp())
        .message_body(body)
        .trace_id(inbound_trace_id)
        .encrypt(shared_key)?
        .build()?;

    let wire_bytes = envelope.encode_to_vec();
    let endpoint = resolve_response_endpoint(channel_store, channel_id, reply_to).await?;
    transport.send(&endpoint, wire_bytes).await?;
    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    T: super::DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    transport: &T,
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
            // Role-based dispatch. On a Helper-role channel the peer is
            // the Owner pushing a share fragment (classic share path).
            // On a Replica-role channel the peer is another replica
            // pushing a full vault payload (vault-sync path); we auto-ack
            // and surface a typed event with the opaque payload.
            let channel = channel_store
                .load(channel_id)
                .await?
                .ok_or(Error::InvalidInput(
                    "channel id not present in channel store",
                ))?;
            match (channel.role, &inner) {
                (SenderKind::Helper, MessageBody::StoreShareRequest(_))
                | (SenderKind::Owner, MessageBody::StoreShareResponse(_)) => {
                    sharing::handle(channel_id, inner, *shared_key, inbound_trace_id)
                }
                (SenderKind::ReplicaDestination, MessageBody::StoreShareRequest(request)) => {
                    sharing::handle_replica_request(
                        transport,
                        &channel,
                        request.clone(),
                        *shared_key,
                        inbound_trace_id,
                    )
                    .await
                }
                (SenderKind::ReplicaSource, MessageBody::StoreShareResponse(response)) => {
                    sharing::handle_replica_response(&channel, response)
                }
                _ => Err(Error::RoleMismatch {
                    channel_id,
                    expected: SenderKind::Helper,
                    actual: channel.role,
                }),
            }
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
    replica_id: Option<u64>,
) -> Result<Vec<DeRecEvent>> {
    let inner =
        crate::derec_message::extract_inner_pairing_message(&message.message, pairing_secret)?;

    pairing::handle(
        channel_store,
        secret_store,
        &inner,
        channel_id,
        pairing_secret,
        message.trace_id,
        replica_id,
    )
    .await
}

/// Inbound role-gate table — the local role required on `channel_id` for the
/// orchestrator to honor a given inbound [`MessageBody`].
///
/// Returns `None` for messages whose role gate is multi-valued (e.g.
/// `StoreShareRequest` is valid for both `Helper` channels and `Replica`
/// channels) — the dispatcher does the branching itself. Also `None` for
/// truly role-blind messages (`UpdateChannelInfo` — either side may
/// initiate).
fn expected_role_for_inbound(body: &MessageBody) -> Option<SenderKind> {
    match body {
        // Multi-role: Helper (peer is Owner, classic share path) OR
        // Replica (peer is Replica, vault-sync path). Gate is inlined
        // in `handle`.
        MessageBody::StoreShareRequest(_) | MessageBody::StoreShareResponse(_) => None,
        // Helper accepts these; Owner sends them.
        MessageBody::VerifyShareRequest(_)
        | MessageBody::GetSecretIdsVersionsRequest(_)
        | MessageBody::GetShareRequest(_)
        | MessageBody::UnpairRequest(_) => Some(SenderKind::Helper),
        // Owner consumes these; Helper sends them.
        MessageBody::VerifyShareResponse(_)
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
