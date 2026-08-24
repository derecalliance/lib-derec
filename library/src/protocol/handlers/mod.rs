// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Inbound dispatch, and the per-flow handlers it routes to.
//!
//! Everything arriving at [`DeRecProtocol::process`](crate::protocol::DeRecProtocol::process)
//! lands here once the envelope is decrypted. Dispatch does three things
//! before a handler ever sees a message:
//!
//! 1. **Routes on the `MessageBody` variant** to the owning flow module.
//! 2. **Chooses the path** for message types that serve both the owner↔helper
//!    and the replica-group relationships. The discriminator is the presence
//!    of `replica_id` on the payload, not the channel it arrived on — several
//!    request types are legal on either path and mean different things.
//! 3. **Enforces the role gate**, rejecting a message whose sender does not
//!    hold the role that message requires on that channel.
//!
//! Handlers are internal: applications drive flows through
//! [`DeRecFlow`](crate::protocol::DeRecFlow) and observe them through
//! [`DeRecEvent`](crate::protocol::DeRecEvent).

pub(super) mod discovery;
pub(super) mod pairing;
pub(super) mod recovery;
pub(super) mod remove_replica;
pub(super) mod restore;
pub(super) mod sharing;
pub(super) mod sync_check;
pub(super) mod unpairing;
pub(super) mod update_channel_info;
pub(super) mod verification;

use super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecStateStore,
    DeRecTransport,
};
use crate::{
    Error, Result,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    protocol::types::{ChannelQuery, Target},
    types::{ChannelId, SharedKey},
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{DeRecMessage, MessageBody, SenderKind, TransportProtocol};
use prost::Message;
use std::collections::HashMap;

/// Route a decrypted channel message to its flow handler.
///
/// Each inbound body names the peer role permitted to have sent it, and
/// the channel's recorded `peer_role` must match before the body is
/// honoured: requests (`VerifyShare`, `GetSecretIdsVersions`, `GetShare`,
/// `Unpair`) are accepted only from an `Owner` peer, and their responses
/// only from a `Helper` peer.
///
/// Two families opt out of that single-valued gate. `StoreShare` traffic
/// is multi-valued — an `Owner` peer drives the classic share path while
/// a `Replica` peer drives secret sync — so the dispatcher branches on
/// `peer_role` itself below. `UpdateChannelInfo` is role-blind: either
/// side may initiate it.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: super::DeRecUserSecretStore,
    T: super::DeRecTransport,
    St: DeRecStateStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    user_secret_store: &mut Us,
    transport: &T,
    state_store: &mut St,
    own_transport: &derec_proto::TransportProtocol,
    message: &DeRecMessage,
    secret_id: u64,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    local_replica_id: Option<u64>,
    transport_policy: crate::transport::TransportPolicy,
) -> Result<Vec<DeRecEvent>> {
    let inner = crate::derec_message::extract_inner_message(&message.message, shared_key)?;

    // The single point every inbound channel message passes through, and so
    // the single place the scheme policy is applied to anything a peer chose.
    // A `reply_to` overrides the endpoint agreed at pairing for one response
    // and an `UpdateChannelInfo` replaces it outright, so pairing-time
    // validation alone would not cover either.
    for endpoint in peer_supplied_endpoints(&inner) {
        transport_policy.check_peer(endpoint)?;
    }

    if let Some(expected) = expected_role_for_inbound(&inner) {
        require_role(channel_store, secret_id, &[channel_id], expected).await?;
    }

    let inbound_trace_id = message.trace_id;

    match &inner {
        MessageBody::StoreShareRequest(_) | MessageBody::StoreShareResponse(_) => {
            // The payload's `replica_id` selects which record kind this
            // message concerns: present means replica-bound and names the
            // author, absent means helper-bound. Decryption is keyed by
            // `channel_id` alone, so the inner message is already available
            // and no separate resolution step is needed.
            let author = match &inner {
                MessageBody::StoreShareRequest(r) => r.replica_id,
                MessageBody::StoreShareResponse(r) => r.replica_id,
                _ => None,
            };

            match (author, &inner) {
                (Some(author), MessageBody::StoreShareRequest(request)) => {
                    let member =
                        load_replica_member(channel_store, secret_id, channel_id, author).await?;
                    sharing::handle_replica_request(
                        channel_store,
                        share_store,
                        secret_store,
                        user_secret_store,
                        transport,
                        &member,
                        request.clone(),
                        *shared_key,
                        inbound_trace_id,
                        local_replica_id,
                    )
                    .await
                }
                (Some(author), MessageBody::StoreShareResponse(response)) => {
                    let member =
                        load_replica_member(channel_store, secret_id, channel_id, author).await?;
                    sharing::handle_replica_response(
                        channel_store,
                        secret_store,
                        secret_id,
                        channel_id,
                        &member,
                        response,
                    )
                    .await
                }
                (Some(_), _) => Err(Error::Invariant(
                    "replica identity on a message that is not a store-share exchange",
                )),
                (None, _) => {
                    let channel = channel_store
                        .load(secret_id, ChannelQuery::Helper { channel_id })
                        .await?
                        .and_then(|r| r.as_helper().cloned())
                        .ok_or(Error::InvalidInput(
                            "channel id not present in channel store",
                        ))?;
                    match (channel.peer_role, &inner) {
                        (SenderKind::Owner, MessageBody::StoreShareRequest(_))
                        | (SenderKind::Helper, MessageBody::StoreShareResponse(_)) => {
                            sharing::handle(channel_id, inner, *shared_key, inbound_trace_id)
                        }
                        _ => Err(Error::RoleMismatch {
                            channel_id,
                            expected: SenderKind::Owner,
                            actual: channel.peer_role,
                        }),
                    }
                }
            }
        }
        MessageBody::VerifyShareRequest(_) | MessageBody::VerifyShareResponse(_) => {
            verification::handle(
                share_store,
                state_store,
                secret_id,
                channel_id,
                inner,
                *shared_key,
                inbound_trace_id,
            )
            .await
        }
        MessageBody::GetSecretIdsVersionsRequest(_)
        | MessageBody::GetSecretIdsVersionsResponse(_) => {
            // As with store-share, the payload's `replica_id` selects the
            // path: present means a group member is driving catch-up and
            // names itself, absent means the owner ↔ helper discovery flow.
            let peer = match &inner {
                MessageBody::GetSecretIdsVersionsRequest(r) => r.replica_id,
                MessageBody::GetSecretIdsVersionsResponse(r) => r.replica_id,
                _ => None,
            };
            match (peer, &inner) {
                (Some(peer), MessageBody::GetSecretIdsVersionsRequest(request)) => {
                    let member =
                        load_replica_member(channel_store, secret_id, channel_id, peer).await?;
                    sync_check::answer_versions(
                        user_secret_store,
                        transport,
                        &member,
                        request,
                        *shared_key,
                        secret_id,
                        local_replica_id,
                        inbound_trace_id,
                    )
                    .await
                }
                (Some(peer), MessageBody::GetSecretIdsVersionsResponse(response)) => {
                    let from = crate::types::ReplicaId::try_from(peer)?;
                    sync_check::collect_version(
                        channel_store,
                        secret_store,
                        state_store,
                        transport,
                        secret_id,
                        from,
                        response,
                        local_replica_id,
                        own_transport,
                    )
                    .await
                }
                _ => {
                    // Owner ↔ helper: the single-valued role gate still
                    // applies, applied here rather than up front.
                    let expected = match &inner {
                        MessageBody::GetSecretIdsVersionsRequest(_) => SenderKind::Owner,
                        _ => SenderKind::Helper,
                    };
                    require_role(channel_store, secret_id, &[channel_id], expected).await?;
                    discovery::handle(channel_id, inner, *shared_key, inbound_trace_id)
                }
            }
        }
        MessageBody::GetShareRequest(_) | MessageBody::GetShareResponse(_) => {
            let peer = match &inner {
                MessageBody::GetShareRequest(r) => r.replica_id,
                MessageBody::GetShareResponse(r) => r.replica_id,
                _ => None,
            };
            match (peer, &inner) {
                (Some(peer), MessageBody::GetShareRequest(request)) => {
                    let member =
                        load_replica_member(channel_store, secret_id, channel_id, peer).await?;
                    sync_check::answer_share(
                        channel_store,
                        secret_store,
                        user_secret_store,
                        transport,
                        &member,
                        request,
                        *shared_key,
                        secret_id,
                        local_replica_id,
                        inbound_trace_id,
                    )
                    .await
                }
                (Some(peer), MessageBody::GetShareResponse(response)) => {
                    let from = crate::types::ReplicaId::try_from(peer)?;
                    sync_check::accept_share(
                        channel_store,
                        secret_store,
                        user_secret_store,
                        secret_id,
                        from,
                        response,
                    )
                    .await
                }
                _ => {
                    let expected = match &inner {
                        MessageBody::GetShareRequest(_) => SenderKind::Owner,
                        _ => SenderKind::Helper,
                    };
                    require_role(channel_store, secret_id, &[channel_id], expected).await?;
                    recovery::handle(
                        state_store,
                        channel_id,
                        inner,
                        *shared_key,
                        inbound_trace_id,
                        secret_id,
                    )
                    .await
                }
            }
        }
        MessageBody::UnpairRequest(request) if request.replica_id.is_some() => {
            let target = request.replica_id.expect("guarded by the match");
            remove_replica::handle_request(channel_store, secret_id, request, target).await
        }
        MessageBody::UnpairRequest(_) | MessageBody::UnpairResponse(_) => {
            // Owner ↔ helper: the single-valued gate still applies, applied
            // here now that the body is multi-valued.
            if matches!(inner, MessageBody::UnpairRequest(_)) {
                require_role(channel_store, secret_id, &[channel_id], SenderKind::Owner).await?;
            }
            unpairing::handle(
                channel_store,
                share_store,
                secret_store,
                state_store,
                secret_id,
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
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn handle_pairing<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    communication_info: &HashMap<String, String>,
    message: &DeRecMessage,
    secret_id: u64,
    channel_id: ChannelId,
    pairing_secret: &PairingSecretKeyMaterial,
    replica_id: Option<u64>,
    parameter_range: Option<&derec_proto::ParameterRange>,
    transport_policy: crate::transport::TransportPolicy,
) -> Result<Vec<DeRecEvent>> {
    let inner =
        crate::derec_message::extract_inner_pairing_message(&message.message, pairing_secret)?;

    // Same single gate as the channel path: the endpoint a peer offers at
    // pairing is the one every later message to it is addressed to.
    for endpoint in peer_supplied_endpoints(&inner) {
        transport_policy.check_peer(endpoint)?;
    }

    pairing::handle(
        channel_store,
        secret_store,
        transport,
        communication_info,
        &inner,
        secret_id,
        channel_id,
        pairing_secret,
        message.trace_id,
        replica_id,
        parameter_range,
    )
    .await
}

/// Assert that every channel in `channel_ids` records `expected` as its
/// **peer's** role. The protocol's flow directionality (protect / verify /
/// discovery / recovery run against Helper peers; Helpers accept them from
/// Owner peers) is enforced through this gate.
///
/// Returns the first mismatch as [`crate::Error::RoleMismatch`]; a missing
/// channel is reported as [`crate::Error::InvalidInput`] (treated as a
/// programming error — the caller asked the protocol to operate on a
/// channel it doesn't have).
pub(super) async fn require_role<Ch: DeRecChannelStore>(
    channel_store: &Ch,
    secret_id: u64,
    channel_ids: &[ChannelId],
    expected: SenderKind,
) -> Result<()> {
    for channel_id in channel_ids {
        let channel = channel_store
            .load(
                secret_id,
                ChannelQuery::Helper {
                    channel_id: *channel_id,
                },
            )
            .await?
            .and_then(|r| r.as_helper().cloned())
            .ok_or(Error::InvalidInput(
                "channel id not present in channel store",
            ))?;
        if channel.peer_role != expected {
            return Err(Error::RoleMismatch {
                channel_id: *channel_id,
                expected,
                actual: channel.peer_role,
            });
        }
    }
    Ok(())
}

pub(super) async fn resolve_target<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    secret_id: u64,
    target: Target,
) -> Result<Vec<ChannelId>> {
    let all_channels = channel_store.helpers(secret_id).await?;
    let all_channel_ids: Vec<ChannelId> = all_channels.iter().map(|c| c.channel_id).collect();

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
    secret_id: u64,
    channel_id: ChannelId,
) -> Result<TransportProtocol> {
    let channel = channel_store
        .load(secret_id, ChannelQuery::Helper { channel_id })
        .await?;
    channel
        .map(|ch| ch.transport().clone())
        .ok_or(Error::InvalidInput("no transport endpoint for channel"))
}

/// Pick the endpoint to deliver a response to.
pub(super) async fn resolve_response_endpoint<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    secret_id: u64,
    channel_id: ChannelId,
    reply_to: Option<&TransportProtocol>,
) -> Result<TransportProtocol> {
    if let Some(endpoint) = reply_to {
        return Ok(endpoint.clone());
    }
    peer_endpoint(channel_store, secret_id, channel_id).await
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
    secret_id: u64,
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
    let endpoint =
        resolve_response_endpoint(channel_store, secret_id, channel_id, reply_to).await?;
    transport.send(&endpoint, wire_bytes).await?;
    Ok(())
}

/// Every transport endpoint an inbound message carries that a **peer** chose.
///
/// Three kinds appear:
///
/// - `PairRequest` / `PrePairRequest` `transport_protocol` — the endpoint the
///   peer will be addressed on, agreed at pairing and stored on the channel.
/// - `reply_to`, on the five request types that have one. It *overrides* that
///   agreed endpoint for one response, which is why checking only at pairing
///   time would not be enough.
/// - `UpdateChannelInfoRequest.transport_protocol`, which *replaces* the
///   agreed endpoint outright.
///
/// Collected here so [`crate::transport::TransportPolicy`] has a single
/// application point, rather than a copy in each response path and each
/// handler.
pub(in crate::protocol) fn peer_supplied_endpoints(
    body: &MessageBody,
) -> impl Iterator<Item = &TransportProtocol> {
    let endpoint = match body {
        MessageBody::StoreShareRequest(r) => r.reply_to.as_ref(),
        MessageBody::VerifyShareRequest(r) => r.reply_to.as_ref(),
        MessageBody::GetSecretIdsVersionsRequest(r) => r.reply_to.as_ref(),
        MessageBody::GetShareRequest(r) => r.reply_to.as_ref(),
        MessageBody::UnpairRequest(r) => r.reply_to.as_ref(),
        MessageBody::UpdateChannelInfoRequest(r) => r.transport_protocol.as_ref(),
        // Pairing: the endpoint the peer will be addressed on from here on.
        // This is the one the agreed channel record is built from.
        MessageBody::PairRequest(r) => r.transport_protocol.as_ref(),
        MessageBody::PrePairRequest(r) => r.transport_protocol.as_ref(),
        _ => None,
    };
    endpoint.into_iter()
}

fn expected_role_for_inbound(body: &MessageBody) -> Option<SenderKind> {
    match body {
        MessageBody::StoreShareRequest(_) | MessageBody::StoreShareResponse(_) => None,
        // Discovery and get-share are multi-valued for the same reason
        // store-share is: an `Owner` peer drives them against a helper, and a
        // group member drives catch-up against another member. The dispatcher
        // branches on the payload's `replica_id` instead, so the owner ↔
        // helper gate is applied there and stays unchanged.
        MessageBody::GetSecretIdsVersionsRequest(_)
        | MessageBody::GetSecretIdsVersionsResponse(_)
        | MessageBody::GetShareRequest(_)
        | MessageBody::GetShareResponse(_) => None,
        MessageBody::VerifyShareRequest(_) => Some(SenderKind::Owner),
        // Unpair is multi-valued: an `Owner` peer tears down a helper channel,
        // and a group member removes a member row. The dispatcher branches on
        // the payload's `replica_id`, so the owner ↔ helper gate is applied
        // there and stays unchanged.
        MessageBody::UnpairRequest(_) => None,
        MessageBody::VerifyShareResponse(_) | MessageBody::UnpairResponse(_) => {
            Some(SenderKind::Helper)
        }
        MessageBody::UpdateChannelInfoRequest(_) | MessageBody::UpdateChannelInfoResponse(_) => {
            None
        }
        _ => None,
    }
}

/// Resolve one replica-group member by the identity the payload announced.
///
/// Every member of a group answers on the same `channel_id`, so the channel
/// alone cannot name the peer — the author does. A `0` is the wire's
/// absent-value sentinel and never identifies a member.
async fn load_replica_member<Ch: DeRecChannelStore>(
    channel_store: &Ch,
    secret_id: u64,
    channel_id: ChannelId,
    author: u64,
) -> Result<crate::protocol::types::ReplicaMember> {
    let replica_id = crate::types::ReplicaId::try_from(author)?;
    channel_store
        .load(
            secret_id,
            ChannelQuery::Replica {
                channel_id,
                replica_id,
            },
        )
        .await?
        .and_then(|r| r.as_replica().cloned())
        .ok_or(Error::InvalidInput(
            "replica sync names a member that is not in the group",
        ))
}

/// T4 of the replica-group spec: `replica_id` presence discriminates the two
/// paths, and a mismatch is a protocol error rather than a silent misroute.
#[cfg(test)]
mod replica_id_discrimination_tests {
    use super::*;
    use crate::protocol::test::{InMemChannelStore, run_async};
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel};
    use crate::types::ChannelId;

    const SECRET_ID: u64 = 0xD15C;

    /// A store-share naming a member the group does not contain is refused.
    /// This is the receive-side check that stops a helper-bound message
    /// carrying a `replica_id` from being resolved against a helper channel:
    /// the replica query finds nothing, because helper channels and members
    /// live in different key spaces.
    #[test]
    fn a_store_share_naming_an_unknown_member_is_refused() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id: ChannelId(9001),
                        transport: derec_proto::TransportProtocol {
                            uri: "https://helper.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        },
                        communication_info: std::collections::HashMap::new(),
                        peer_role: derec_proto::SenderKind::Helper,
                        status: ChannelStatus::Paired,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed helper channel");

            let err = super::load_replica_member(&channels, SECRET_ID, ChannelId(9001), 1002)
                .await
                .expect_err("a helper channel holds no member, so this must not resolve");
            assert!(
                matches!(err, Error::InvalidInput(_)),
                "expected an InvalidInput protocol error, got {err:?}"
            );
        });
    }

    /// `0` is the wire's absent-value sentinel, so it can never name a member
    /// — a payload carrying it is malformed, not a lookup miss.
    #[test]
    fn replica_id_zero_never_names_a_member() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let err = super::load_replica_member(&channels, SECRET_ID, ChannelId(9001), 0)
                .await
                .expect_err("zero is the absent sentinel and must be rejected");
            assert!(
                matches!(err, Error::InvalidInput(_)),
                "expected an InvalidInput protocol error, got {err:?}"
            );
        });
    }
}
