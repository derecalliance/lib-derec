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
use derec_proto::{DeRecMessage, MessageBody, SenderKind, StatusEnum, TransportProtocol};
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
    // TODO: almost all handlers need all those 5 store plus the transport trait which adds 6
    // parameters everywhere. Lets put them all into a struct so that its shape is much simpler
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    user_secret_store: &mut Us,
    transport: &T,
    state_store: &mut St,
    // TODO: This is the legacy one and should not be preserved, even while removing it is a
    // breaking change, it is trivial to solve
    own_transport: &derec_proto::TransportProtocol,
    own_transports: &[derec_proto::TransportProtocol],
    // TODO: own_treansports, secret_id, channel_id, shared_key, local_replica_id all belong to the
    // current instance and must almost always be passed across function calls all together. Lets
    // see if we can group them into a struct that simplies parameters
    message: &DeRecMessage,
    secret_id: u64,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    local_replica_id: Option<u64>,
    // TODO: The next two parameters are configurations about how the protocol should behave, lets
    // group them together into a a struct
    transport_policy: crate::transport::TransportPolicy,
    auto_respond_on_failure: bool,
) -> Result<Vec<DeRecEvent>> {
    // TODO: All these comments should be either in rustdocs or readmes if they are really
    // important or just removed
    // Everything past this line works on an *authenticated* message:
    // decryption succeeded, so the sender holds this channel's key. That is
    // what makes a failure response safe to send back — see `auto_respond`.
    let inner = crate::derec_message::extract_inner_message(&message.message, shared_key)?;

    let inbound_trace_id = message.trace_id;

    // Captured before dispatch because dispatch consumes the body, and only
    // when the setting is on so the clone costs nothing by default.
    let responder = auto_respond_on_failure
        .then(|| FailureResponder::capture(&inner))
        .flatten();

    // Both gates below reject an authenticated message, so both are failures
    // a peer can be told about. They are collected rather than `?`-ed so the
    // auto-respond path at the bottom sees them alongside dispatch failures.
    let mut refused: Option<Error> = None;

    // The single point every inbound channel message passes through, and so
    // the single place the scheme policy is applied to a `reply_to` — which
    // overrides the endpoints agreed at pairing for one response, and so is
    // not covered by pairing-time validation.
    for endpoint in peer_supplied_endpoints(&inner) {
        if let Err(e) = transport_policy.check_peer(endpoint) {
            refused = Some(e.into());
            break;
        }
    }

    if refused.is_none()
        && let Some(expected) = expected_role_for_inbound(&inner)
        && let Err(e) = require_role(channel_store, secret_id, &[channel_id], expected).await
    {
        refused = Some(e);
    }

    let outcome = match refused {
        Some(error) => Err(error),
        None => match &inner {
            MessageBody::StoreShareRequest(_) | MessageBody::StoreShareResponse(_) => {
                // TODO: this branch is executing too much logic, put all that into a function or
                // even better, since this branch along with GetSecretIdsVersionsRequest and GetShareRequest require
                // logic for replicas, lets evaluate creating a new file that holds both. The goal
                // is to make code simpler
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
                            load_replica_member(channel_store, secret_id, channel_id, author)
                                .await?;
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
                            load_replica_member(channel_store, secret_id, channel_id, author)
                                .await?;
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
                    require_role(channel_store, secret_id, &[channel_id], SenderKind::Owner)
                        .await?;
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
            MessageBody::UpdateChannelInfoRequest(_)
            | MessageBody::UpdateChannelInfoResponse(_) => {
                match update_channel_info::handle(
                    channel_id,
                    inner,
                    *shared_key,
                    inbound_trace_id,
                    own_transports,
                )
                .await
                {
                    // Unlike pairing, the channel is already established: this
                    // side still holds the peer's previous, working endpoint, so
                    // the refusal can be sent back over it instead of only
                    // surfacing as a local error the peer never learns about.
                    Err(Error::NoUsableEndpoint { offered }) => {
                        let memo = format!(
                            "peer announced no usable transport endpoint — all \
                         {offered} offer(s) were refused by transport policy"
                        );
                        update_channel_info::reject(
                            channel_store,
                            transport,
                            secret_id,
                            channel_id,
                            shared_key,
                            StatusEnum::UnsupportedTransportProtocol,
                            &memo,
                            inbound_trace_id,
                        )
                        .await?;
                        Ok(vec![DeRecEvent::UpdateChannelInfoFailed {
                            channel_id,
                            error: memo,
                        }])
                    }
                    other => other,
                }
            }
            _ => Err(Error::Invariant(
                "unexpected MessageBody variant in channel message",
            )),
        },
    };

    if let (Err(error), Some(responder)) = (&outcome, responder) {
        auto_respond(
            channel_store,
            transport,
            secret_id,
            channel_id,
            shared_key,
            responder,
            error,
            inbound_trace_id,
            local_replica_id,
        )
        .await;
    }

    outcome
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
        transport_policy,
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

// TODO: Why is this function here? seems to be part of the trait, but the most important, it feels
// weird having this function here. It is a store specific exported from the handlers module
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

// TODO: Same as the previous TODO, this function does not seem to belong here.
/// Rebuild a peer's transport endpoint from the bare URI a roster carries.
///
/// [`HelperInfo`](crate::protocol::types::HelperInfo) and
/// [`ReplicaInfo`](crate::protocol::types::ReplicaInfo) store `transport_uri`
/// and no protocol discriminant, so the discriminant has to be derived from
/// the URI scheme on the way back in — the same derivation
/// [`crate::transport::TransportProtocol`]'s `TryFrom<&str>` performs when an
/// endpoint first enters the library. Assuming one protocol here would hand
/// every restored channel a discriminant contradicting its own URI.
///
/// Every endpoint recorded for a peer, in the order it advertised them.
///
/// Handed to [`DeRecTransport::send`](crate::protocol::DeRecTransport) as-is:
/// the library does not rank them, and the application chooses which to dial
/// and whether to fall back.
pub(super) async fn peer_endpoints<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    secret_id: u64,
    channel_id: ChannelId,
) -> Result<Vec<TransportProtocol>> {
    let channel = channel_store
        .load(secret_id, ChannelQuery::Helper { channel_id })
        .await?;
    channel
        .map(|ch| ch.transports().to_vec())
        .filter(|endpoints| !endpoints.is_empty())
        .ok_or(Error::InvalidInput("no transport endpoint for channel"))
}

// TODO: Same as the previous TODO, this function does not seem to belong here.
/// Pick the endpoint to deliver a response to.
pub(super) async fn resolve_response_endpoints<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    secret_id: u64,
    channel_id: ChannelId,
    reply_to: &[TransportProtocol],
) -> Result<Vec<TransportProtocol>> {
    // A reply-to names the addresses the requester asked to be answered on,
    // so they stand alone rather than joining the recorded set: the recorded
    // endpoints may belong to a different peer entirely (a replica talking to
    // a helper paired with a sibling), so falling back to them would misroute
    // rather than fail over.
    if !reply_to.is_empty() {
        return Ok(reply_to.to_vec());
    }
    peer_endpoints(channel_store, secret_id, channel_id).await
}

// TODO: Same as the previous TODO, this function does not seem to belong here.
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

// TODO: Same as the previous TODO, this function does not seem to belong here.
/// Internal wrapper that re-stamps a primitive-produced wire envelope's
/// `trace_id`. Thin alias for [`crate::derec_message::apply_trace_id`] kept
/// inside the handlers module so callers can stay terse with `super::`.
pub(super) fn apply_trace_id(envelope_bytes: Vec<u8>, trace_id: u64) -> Result<Vec<u8>> {
    crate::derec_message::apply_trace_id(&envelope_bytes, trace_id)
}

// TODO: Same as the previous TODO, this function does not seem to belong here.
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
    reply_to: &[TransportProtocol],
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
        resolve_response_endpoints(channel_store, secret_id, channel_id, reply_to).await?;
    transport.send(&endpoint, wire_bytes).await?;
    Ok(())
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
/// The inbound request a failure response would answer, captured before
/// dispatch because the dispatch consumes the `MessageBody`.
///
/// Only request bodies appear: nothing is owed to a peer that was itself
/// answering us, and the pairing flows carry their own accept/reject surface.
enum FailureResponder {
    StoreShare(Box<derec_proto::StoreShareRequestMessage>),
    VerifyShare(Box<derec_proto::VerifyShareRequestMessage>),
    Discovery(Box<derec_proto::GetSecretIdsVersionsRequestMessage>),
    GetShare(Box<derec_proto::GetShareRequestMessage>),
    Unpair(Box<derec_proto::UnpairRequestMessage>),
    UpdateChannelInfo,
}

impl FailureResponder {
    fn capture(inner: &MessageBody) -> Option<Self> {
        match inner {
            MessageBody::StoreShareRequest(r) => Some(Self::StoreShare(Box::new(r.clone()))),
            MessageBody::VerifyShareRequest(r) => Some(Self::VerifyShare(Box::new(r.clone()))),
            MessageBody::GetSecretIdsVersionsRequest(r) => {
                Some(Self::Discovery(Box::new(r.clone())))
            }
            MessageBody::GetShareRequest(r) => Some(Self::GetShare(Box::new(r.clone()))),
            MessageBody::UnpairRequest(r) => Some(Self::Unpair(Box::new(r.clone()))),
            MessageBody::UpdateChannelInfoRequest(_) => Some(Self::UpdateChannelInfo),
            _ => None,
        }
    }
}

/// Tell the peer its request failed, when the application has opted into
/// [`with_auto_respond_on_failure`](crate::protocol::DeRecProtocolBuilder::with_auto_respond_on_failure).
///
/// # Why this is only reachable here
///
/// It runs after `extract_inner_message` succeeded, so the request was
/// decrypted under the channel key and is therefore *authenticated*. That is
/// the precondition for replying at all: a message that failed to decrypt
/// carries no proof it came from the peer it names, and answering it would
/// make this device an oracle for anyone able to send bytes at it. Those
/// failures surface to the application as `ProcessError` and nothing goes
/// back on the wire.
///
/// # Best effort
///
/// The reply is a courtesy on top of an already-failed exchange, so a failure
/// to send it is logged and swallowed rather than replacing the error the
/// caller actually needs to see.
#[allow(clippy::too_many_arguments)]
async fn auto_respond<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    responder: FailureResponder,
    error: &Error,
    trace_id: u64,
    local_replica_id: Option<u64>,
) {
    let status = status_for(error);
    let memo = error.to_string();

    let sent = match &responder {
        FailureResponder::StoreShare(r) => {
            sharing::reject(
                channel_store,
                transport,
                secret_id,
                channel_id,
                r,
                shared_key,
                status,
                &memo,
                trace_id,
                local_replica_id,
            )
            .await
        }
        FailureResponder::VerifyShare(r) => {
            verification::reject(
                channel_store,
                transport,
                secret_id,
                channel_id,
                r,
                shared_key,
                status,
                &memo,
                trace_id,
            )
            .await
        }
        FailureResponder::Discovery(r) => {
            discovery::reject(
                channel_store,
                transport,
                secret_id,
                channel_id,
                r,
                shared_key,
                status,
                &memo,
                trace_id,
                local_replica_id,
            )
            .await
        }
        FailureResponder::GetShare(r) => {
            recovery::reject(
                channel_store,
                transport,
                secret_id,
                channel_id,
                r,
                shared_key,
                status,
                &memo,
                trace_id,
                local_replica_id,
            )
            .await
        }
        FailureResponder::Unpair(r) => {
            unpairing::reject(
                channel_store,
                transport,
                secret_id,
                channel_id,
                r,
                shared_key,
                status,
                &memo,
                trace_id,
            )
            .await
        }
        FailureResponder::UpdateChannelInfo => {
            update_channel_info::reject(
                channel_store,
                transport,
                secret_id,
                channel_id,
                shared_key,
                status,
                &memo,
                trace_id,
            )
            .await
        }
    };

    if let Err(_send_error) = sent {
        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = channel_id.0,
            error = %_send_error,
            "auto_respond_on_failure could not deliver the failure response; \
             the original error is still returned to the caller",
        );
    }
}

// TODO: Can we implement Into or From?
/// Map an internal failure to the closest [`StatusEnum`] the peer can act on.
///
/// Deliberately coarse: a peer can only decide whether to retry, correct its
/// request, or give up, and the memo carries the detail. `FAIL` is the honest
/// answer for anything that does not map cleanly, rather than inventing a
/// more specific-sounding status than the error actually supports.
fn status_for(error: &Error) -> StatusEnum {
    match error {
        Error::ProtobufDecode(_) => StatusEnum::FormatError,
        Error::RoleMismatch { .. } => StatusEnum::Rejected,
        Error::NoUsableEndpoint { .. } => StatusEnum::UnsupportedTransportProtocol,
        _ => StatusEnum::Fail,
    }
}

/// Every transport endpoint an inbound message carries that a **peer** chose.
///
/// One kind appears: `reply_to`, on the five request types that have one. It
/// *overrides* the endpoints agreed at pairing for a single response, which
/// is why checking only at pairing time would not be enough.
///
/// # What is deliberately absent
///
/// `PairRequest`, `PrePairRequest` and `UpdateChannelInfoRequest` all carry
/// peer-chosen endpoints and none appears here. Each advertises a
/// `supportedTransports` list, and filtering that list — applying this same
/// `check_peer` to every entry — happens in its handler instead, where a
/// failing entry is skipped rather than aborting the whole message. Gating
/// them here would fail-fast on one bad entry even when a later one would
/// have served, which for `UpdateChannelInfo` would additionally leave the
/// peer's *stale* endpoints in place.
///
/// `PrePairRequest` could not be gated here in any case: it travels in
/// plaintext and takes its own dispatch path, which never reaches either
/// caller of this function.
///
/// Collected here so [`crate::transport::TransportPolicy`] has a single
/// application point for what remains, rather than a copy in each response
/// path and each handler.
pub(in crate::protocol) fn peer_supplied_endpoints(
    body: &MessageBody,
) -> impl Iterator<Item = &TransportProtocol> {
    // `reply_to` is a list in its own right, so it is read directly.
    let listed: Vec<&TransportProtocol> = match body {
        MessageBody::StoreShareRequest(r) => r.reply_to.iter().collect::<Vec<_>>(),
        MessageBody::VerifyShareRequest(r) => r.reply_to.iter().collect::<Vec<_>>(),
        MessageBody::GetSecretIdsVersionsRequest(r) => r.reply_to.iter().collect::<Vec<_>>(),
        MessageBody::GetShareRequest(r) => r.reply_to.iter().collect::<Vec<_>>(),
        MessageBody::UnpairRequest(r) => r.reply_to.iter().collect::<Vec<_>>(),
        _ => Vec::new(),
    };

    listed.into_iter()
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
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "https://helper.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
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
