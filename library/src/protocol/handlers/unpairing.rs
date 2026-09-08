// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Unpair flow handlers — initiator side ([`start`], [`on_response`])
//! and responder side ([`accept`], [`reject`]).
//!
//! # Security: response replay is harmless by design
//!
//! The on-wire [`UnpairResponseMessage`] carries no nonce or
//! request-id binding, and the primitive's
//! [`crate::primitives::unpairing::response::extract`] only checks
//! the envelope/body timestamp equality (not freshness). A captured
//! `OK` response can therefore be re-decoded indefinitely under the
//! long-lived channel key. This flow nevertheless tolerates replay
//! safely because:
//!
//! 1. **Per-channel pending-unpair guard.** [`on_response`] requires
//!    a matching [`crate::protocol::StateItem::PendingUnpair`] row in
//!    the state store (written by [`start`] under
//!    [`crate::protocol::UnpairAck::Required`]) and consumes it via
//!    [`crate::protocol::DeRecStateStore::remove`], which returns
//!    `Ok(true)` iff a row was actually deleted. A replayed response
//!    after the entry has already been consumed sees a `false` return
//!    and yields [`DeRecEvent::NoOp`] — no state is touched.
//! 2. **Destructive-idempotent teardown.** When a pending entry is
//!    present, the response IS legitimate (or indistinguishable
//!    from one) and [`drop_channel_state`] runs. That function only
//!    deletes per-`(secret_id, channel_id)` rows whose store
//!    [`crate::protocol::DeRecChannelStore::remove`] /
//!    [`crate::protocol::DeRecShareStore::remove_channel`] /
//!    [`crate::protocol::DeRecSecretStore::remove`] contracts are
//!    explicitly idempotent — running them twice on the same key
//!    converges to the same end state as running them once.
//! 3. **Channel-id freshness across re-pair.** After teardown the
//!    `channel_id` is gone from the channel store; any future pair
//!    handshake mints a fresh cryptographically-derived id, so a
//!    stale response cannot accidentally target a newly-paired
//!    channel.
//!
//! The worst case under replay is therefore "unpair a channel that's
//! already unpaired" — the same end state the legitimate flow
//! produces. No cross-request satisfaction is possible because the
//! pending-unpair state store row is keyed by `channel_id` and the
//! response envelope is routed by channel id at the stores.transport layer.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecStateStore,
    DeRecTransport, PendingAction, SecretKind, SecretValue, StateItem, StateKey, events::UnpairAck,
};
use super::replicas::unpairing as replica;
use crate::derec_message::current_timestamp;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::message_body::{MessageBodyExt as _, Route};
use crate::protocol::context::{Exchange, Local, Round};
use crate::protocol::stores::{StoreSet, Stores};
use crate::{
    Error, Result,
    primitives::unpairing::{
        request::produce as produce_unpair_request,
        response::{self as unpairing_response, process as process_unpair_response},
    },
    types::ChannelId,
};
use derec_proto::{
    DeRecResult, MessageBody, SenderKind, StatusEnum, UnpairRequestMessage, UnpairResponseMessage,
};

/// Route an inbound unpair message.
///
/// On the initiator side under [`crate::protocol::UnpairAck::Required`],
/// the [`crate::protocol::DeRecStateStore::remove`] of the
/// `PendingUnpair` row is the flow's replay guard: an `UnpairResponse`
/// is acted on only while a matching outbound `UnpairRequest` is still
/// in flight for that `channel_id`. `remove` returning `false` means no
/// row existed, so the response — legitimate, stale, or replayed, a
/// distinction the primitive alone cannot make (see the module-level
/// Security section) — falls through to [`DeRecEvent::NoOp`] without
/// mutating any state.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    match (inner.route(), inner) {
        (Route::Replica(target), inner) => replica::handle(stores, local, target, inner).await,
        (_, MessageBody::UnpairRequest(request)) => {
            stores
                .channels
                .require_role(local.secret_id, &[exchange.channel_id], SenderKind::Owner)
                .await?;
            on_request(exchange, request)
        }
        (_, MessageBody::UnpairResponse(response)) => {
            on_response(stores, local, exchange, &response).await
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in unpairing handler",
        )),
    }
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = round.trace_id)))]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    memo: Option<String>,
    unpair_ack: UnpairAck,
    now: u64,
    round: &Round<'_>,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    let memo_str = memo.unwrap_or_default();
    let mut events = Vec::new();

    let shared_key = match stores
        .secrets
        .load(secret_id, channel_id, SecretKind::SharedKey)
        .await?
    {
        Some(SecretValue::SharedKey(k)) => k,
        _ => {
            return Err(crate::Error::InvalidInput(
                "channel has no shared key — not yet paired",
            ));
        }
    };

    // Helper unpair: no member is named, which is what marks this the
    // owner ↔ helper path rather than a replica-group removal.
    let request = produce_unpair_request(channel_id, &memo_str, &shared_key, round.reply_to, None)?;
    let envelope = crate::derec_message::apply_trace_id(&request.envelope, round.trace_id)?;
    let endpoint = stores
        .channels
        .peer_endpoints(secret_id, channel_id)
        .await?;
    stores.transport.send(&endpoint, envelope).await?;

    match unpair_ack {
        UnpairAck::NotRequired => {
            drop_channel_state(stores, local, channel_id).await?;
            events.push(DeRecEvent::Unpaired { channel_id });
        }
        UnpairAck::Required => {
            stores
                .state
                .save(
                    secret_id,
                    StateItem::PendingUnpair {
                        channel_id,
                        started_at: now,
                    },
                )
                .await?;
        }
    }

    #[cfg(feature = "logging")]
    tracing::debug!(
        channel_id = channel_id.0,
        ack = ?unpair_ack,
        "unpair request sent"
    );

    Ok(events)
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
pub(in crate::protocol) async fn accept<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &UnpairRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    let channel_id = exchange.channel_id;
    let resp = unpairing_response::produce(channel_id, exchange.shared_key)?;
    let envelope = crate::derec_message::apply_trace_id(&resp.envelope, exchange.trace_id)?;
    let endpoint = stores
        .channels
        .resolve_response_endpoints(local.secret_id, channel_id, &request.reply_to)
        .await?;
    stores.transport.send(&endpoint, envelope).await?;

    drop_channel_state(stores, local, channel_id).await?;

    #[cfg(feature = "logging")]
    tracing::info!("unpair accepted; local state dropped");

    Ok(vec![DeRecEvent::Unpaired { channel_id }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0, status = status as i32))
)]
pub(in crate::protocol) async fn reject<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &UnpairRequestMessage,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let response = UnpairResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        timestamp: Some(current_timestamp()),
    };

    crate::extensions::channel_store::send_channel_message(
        stores.channels,
        stores.transport,
        local.secret_id,
        exchange.channel_id,
        MessageBody::UnpairResponse(response),
        exchange.shared_key,
        exchange.trace_id,
        &request.reply_to,
    )
    .await
}

pub(in crate::protocol) async fn drop_channel_state<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
) -> Result<()> {
    let secret_id = local.secret_id;
    stores.shares.remove_channel(secret_id, channel_id).await?;

    let _ = stores
        .secrets
        .remove(secret_id, channel_id, SecretKind::SharedKey)
        .await;
    let _ = stores
        .secrets
        .remove(secret_id, channel_id, SecretKind::PairingSecret)
        .await;
    let _ = stores
        .secrets
        .remove(secret_id, channel_id, SecretKind::PairingContact)
        .await;

    let _ = stores
        .channels
        .remove(
            secret_id,
            crate::protocol::types::ChannelQuery::Helper { channel_id },
        )
        .await?;
    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
fn on_request(exchange: &Exchange<'_>, request: UnpairRequestMessage) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id: exchange.channel_id,
        action: PendingAction::Unpair {
            channel_id: exchange.channel_id,
            request,
            shared_key: *exchange.shared_key,
            trace_id: exchange.trace_id,
        },
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    response: &UnpairResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    if !stores
        .state
        .remove(
            local.secret_id,
            StateKey::PendingUnpair {
                channel_id: exchange.channel_id,
            },
        )
        .await?
    {
        return Ok(vec![DeRecEvent::NoOp]);
    }

    match process_unpair_response(response) {
        Ok(_) => {
            drop_channel_state(stores, local, exchange.channel_id).await?;
            Ok(vec![DeRecEvent::Unpaired {
                channel_id: exchange.channel_id,
            }])
        }
        Err(Error::Unpairing(crate::primitives::unpairing::UnpairingError::NonOkStatus {
            status,
            memo,
        })) => Ok(vec![DeRecEvent::UnpairRejected {
            channel_id: exchange.channel_id,
            status,
            memo,
        }]),
        Err(e) => Err(e),
    }
}
