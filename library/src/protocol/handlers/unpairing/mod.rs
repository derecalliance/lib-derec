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
//!    [`crate::protocol::UnpairAck::Required`]), and removes it only once
//!    the response has been applied. A replayed response after that finds
//!    no entry and yields [`DeRecEvent::NoOp`] — no state is touched. A
//!    response whose effect could not be stored keeps the entry, so
//!    processing it again, or the acknowledgement timeout, finishes it.
//! 2. **Destructive-idempotent teardown.** When a pending entry is
//!    present, the response IS legitimate (or indistinguishable
//!    from one) and [`drop_channels_state`] runs. That function only
//!    deletes per-`(secret_id, channel_id)` rows whose store
//!    [`crate::protocol::DeRecChannelStore::remove_many`] /
//!    [`crate::protocol::DeRecShareStore::remove_channel`] /
//!    [`crate::protocol::DeRecSecretStore::remove_many`] contracts are
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
    ChannelRequest, DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore,
    DeRecStateStore, DeRecTransport, PendingAction, PendingActionKind, SecretKind, StateItem,
    StateKey, events::UnpairAck,
};
use super::replicas::unpairing as replica;
use crate::derec_message::{apply_trace_id, current_timestamp};
use crate::extensions::advertised_endpoints::reply_to_owned;
use crate::extensions::channel_store::{ChannelStoreExt as _, send_channel_message};
use crate::extensions::message_body::{MessageBodyExt as _, Route};
use crate::extensions::secret_store::SecretStoreExt as _;
use crate::primitives::unpairing::UnpairingError;
use crate::protocol::context::{Exchange, Local, Round};
use crate::protocol::obligation;
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::types::{ChannelQuery, ChannelRecord, ChannelStatus, Share};
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
            if let Some((status, memo)) = refusal(stores, local, exchange, &request).await? {
                return refuse(stores, local, exchange, &request, status, memo).await;
            }
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
/// Send an unpair request on `channel_id` naming `unpaired`: the same channel
/// for an ordinary unpair, an older linked one for a linked unpair. The
/// pending entry, the status change and every event are keyed by `unpaired`,
/// so `channel_id` stays usable while a linked unpair is in flight.
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    unpaired: ChannelId,
    memo: Option<String>,
    unpair_ack: UnpairAck,
    now: u64,
    round: &Round<'_>,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    let memo_str = memo.unwrap_or_default();
    let mut events = vec![DeRecEvent::UnpairStarted {
        channel_id: unpaired,
        trace_id: round.trace_id,
    }];

    let key = stores.secrets.current_key(secret_id, channel_id).await?;

    // Helper unpair: no member is named, which is what marks this the
    // owner ↔ helper path rather than a replica-group removal.
    let request =
        produce_unpair_request(channel_id, &memo_str, &key, round.reply_to, None, unpaired)?;
    let envelope = apply_trace_id(&request.envelope, round.trace_id)?;
    let endpoint = stores
        .channels
        .peer_endpoints(secret_id, channel_id)
        .await?;
    stores.transport.send(&endpoint, envelope).await?;

    match unpair_ack {
        UnpairAck::NotRequired => {
            drop_channels_state(stores, local, &[unpaired]).await?;
            events.push(DeRecEvent::Unpaired {
                channel_id: unpaired,
            });
        }
        UnpairAck::Required => {
            stores
                .state
                .save(
                    secret_id,
                    StateItem::PendingUnpair {
                        channel_id: unpaired,
                        started_at: now,
                    },
                )
                .await?;
            // Written after the pending row, so an `Unpairing` channel always
            // has one and the acknowledgement timeout always reaches it.
            set_status(
                stores,
                local,
                unpaired,
                ChannelStatus::Paired,
                ChannelStatus::Unpairing,
            )
            .await?;
        }
    }

    #[cfg(feature = "logging")]
    tracing::debug!(
        channel_id = channel_id.0,
        unpaired = unpaired.0,
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
    // The channel to drop: the arrival channel itself, or an older channel
    // linked to it, which `refusal` already checked before this was raised.
    let unpaired = ChannelId(request.channel_id);
    let resp = unpairing_response::produce(channel_id, exchange.key, unpaired)?;
    let envelope = apply_trace_id(&resp.envelope, exchange.trace_id)?;
    let endpoint = stores
        .channels
        .resolve_response_endpoints(
            local.secret_id,
            channel_id,
            local.policy,
            &reply_to_owned(request),
        )
        .await?;
    let sent = obligation::deliver(
        exchange.obligation,
        stores.transport,
        &endpoint,
        envelope,
        StatusEnum::Ok,
        "",
    )
    .await;
    if sent.is_err() && !obligation::attempted(exchange.obligation) {
        return sent.map(|()| Vec::new());
    }

    // The acknowledgement is out, so the peer may already have dropped its
    // side: the local state goes too, and a failure from here on is
    // reported after `Unpaired`, never answered a second time.
    let dropped = drop_channels_state(stores, local, &[unpaired]).await;

    #[cfg(feature = "logging")]
    tracing::info!(
        unpaired = unpaired.0,
        "unpair accepted; local state dropped"
    );

    obligation::reported(
        exchange.obligation,
        vec![DeRecEvent::Unpaired {
            channel_id: unpaired,
        }],
        sent.and(dropped),
    )
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
    send_channel_message(
        stores.channels,
        stores.transport,
        local.secret_id,
        exchange.channel_id,
        failure_response(request, status, memo),
        exchange.key,
        exchange.trace_id,
        local.policy,
        &reply_to_owned(request),
        exchange.obligation,
        status,
        memo,
    )
    .await
}

/// The `UnpairResponse` that answers `request` with a non-`Ok` `status`,
/// echoing the channel it named; no channel is dropped.
pub(in crate::protocol) fn failure_response(
    request: &UnpairRequestMessage,
    status: StatusEnum,
    memo: &str,
) -> MessageBody {
    MessageBody::UnpairResponse(UnpairResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        timestamp: Some(current_timestamp()),
        channel_id: request.channel_id,
    })
}

/// Why an inbound unpair request is refused before the application sees it,
/// or `None` when it may go ahead.
///
/// A request naming the channel it arrived on is an ordinary unpair. One
/// naming another channel is a linked unpair: the owner recovered on this
/// channel and wants the older one dropped. It goes ahead only when that
/// older channel is linked to this one, so an owner can never name another
/// owner's channel; only once a share is stored on this channel, so
/// dropping the older one never leaves this helper holding nothing for the
/// owner; and only when the named channel holds no newer version than this
/// one, so a device left with the old channel's key cannot retire the
/// channel the owner recovered on. A named channel that is neither linked
/// nor held was dropped by an earlier linked unpair, and a retry goes ahead.
/// These are protocol rules, refused whatever the application's settings.
async fn refusal<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &UnpairRequestMessage,
) -> Result<Option<(StatusEnum, &'static str)>> {
    let arrival = exchange.channel_id;
    if request.channel_id == 0 {
        return Ok(Some((
            StatusEnum::FormatError,
            "the unpair request names no channel",
        )));
    }
    if request.channel_id == arrival.0 {
        return Ok(None);
    }
    let target = ChannelId(request.channel_id);
    let linked = stores
        .channels
        .linked_channels(local.secret_id, arrival)
        .await?;
    // A store may drop a channel's links along with the channel. A target
    // that is neither linked nor held is one an earlier linked unpair
    // already dropped, so a retry is answered as the first one was.
    if !linked.contains(&target)
        && stores
            .channels
            .load_helper(local.secret_id, target)
            .await?
            .is_some()
    {
        return Ok(Some((
            StatusEnum::Fail,
            "the named channel is not linked to this one",
        )));
    }
    let newest_on = |shares: Vec<Share>| shares.iter().map(|share| share.version).max();
    let Some(arrival_newest) = newest_on(stores.shares.load(local.secret_id, arrival, &[]).await?)
    else {
        return Ok(Some((
            StatusEnum::Fail,
            "no share is stored on this channel yet",
        )));
    };
    // Only an older channel is retired: one holding a newer version than
    // this one is the channel the owner recovered on, not the one it left.
    if newest_on(stores.shares.load(local.secret_id, target, &[]).await?)
        .is_some_and(|target_newest| target_newest > arrival_newest)
    {
        return Ok(Some((
            StatusEnum::Fail,
            "the named channel holds a newer version than this one",
        )));
    }
    Ok(None)
}

/// Answer `request` with `status` and report it as a failed request the
/// library has already answered.
async fn refuse<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &UnpairRequestMessage,
    status: StatusEnum,
    memo: &'static str,
) -> Result<Vec<DeRecEvent>> {
    let sent = reject(stores, local, exchange, request, status, memo).await;
    let event = obligation::request_failed(
        exchange.channel_id,
        PendingActionKind::Unpair,
        sent.is_ok(),
        status as i32,
        memo,
        &Error::InvalidInput(memo),
        None,
    );
    obligation::refused(exchange.obligation, event, status, memo, sent)
}

/// Drop everything this device holds for `channel_ids`: their shares, their
/// keys and their channel records.
///
/// Every removal is idempotent, so a call that fails part way is completed
/// by calling it again. The keys and the records each go in one call; the
/// shares go one channel at a time, since a share store removes a whole
/// channel only one at a time.
pub(in crate::protocol) async fn drop_channels_state<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_ids: &[ChannelId],
) -> Result<()> {
    if channel_ids.is_empty() {
        return Ok(());
    }
    let secret_id = local.secret_id;
    for &channel_id in channel_ids {
        stores.shares.remove_channel(secret_id, channel_id).await?;
    }

    let secrets: Vec<(ChannelId, SecretKind)> = channel_ids
        .iter()
        .flat_map(|&channel_id| {
            [
                SecretKind::SharedKey,
                SecretKind::KeyRing,
                SecretKind::PairingSecret,
                SecretKind::PairingContact,
            ]
            .map(|kind| (channel_id, kind))
        })
        .collect();
    stores.secrets.remove_many(secret_id, &secrets).await?;

    let records: Vec<ChannelQuery> = channel_ids
        .iter()
        .map(|&channel_id| ChannelQuery::Helper { channel_id })
        .collect();
    stores.channels.remove_many(secret_id, &records).await?;
    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
fn on_request(exchange: &Exchange<'_>, request: UnpairRequestMessage) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id: exchange.channel_id,
        action: PendingAction::request(
            exchange.channel_id,
            exchange.trace_id,
            ChannelRequest::Unpair(request),
        )
        .sealed_with(exchange.key),
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0, unpaired = response.channel_id))
)]
async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    response: &UnpairResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    // The answer names the channel the request named, which for a linked
    // unpair is not the channel it travels on. A linked unpair only ever
    // names a channel this device no longer holds, so an answer naming a
    // held channel settles nothing unless it arrived on that channel:
    // another helper cannot complete or refuse it.
    let unpaired = ChannelId(response.channel_id);
    if unpaired != exchange.channel_id
        && stores
            .channels
            .load_helper(local.secret_id, unpaired)
            .await?
            .is_some()
    {
        return Ok(vec![DeRecEvent::NoOp]);
    }
    let pending = StateKey::PendingUnpair {
        channel_id: unpaired,
    };
    if stores
        .state
        .load(local.secret_id, pending.clone())
        .await?
        .is_none()
    {
        return Ok(vec![DeRecEvent::NoOp]);
    }

    let events = match process_unpair_response(response) {
        Ok(_) => {
            drop_channels_state(stores, local, &[unpaired]).await?;
            vec![DeRecEvent::Unpaired {
                channel_id: unpaired,
            }]
        }
        Err(Error::Unpairing(UnpairingError::NonOkStatus { status, memo })) => {
            set_status(
                stores,
                local,
                unpaired,
                ChannelStatus::Unpairing,
                ChannelStatus::Paired,
            )
            .await?;
            vec![DeRecEvent::UnpairRejected {
                channel_id: unpaired,
                status,
                memo,
            }]
        }
        Err(e) => return Err(e),
    };

    // The entry goes last: until it does, processing this response again,
    // or the acknowledgement timeout, completes what this call started.
    stores.state.remove(local.secret_id, pending).await?;
    Ok(events)
}

/// Move a helper channel from `from` to `to`, leaving any other status alone.
///
/// Only a `Paired` channel becomes `Unpairing`: one still `Pending` is
/// already excluded from every flow, and a rejection must not promote it.
async fn set_status<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    from: ChannelStatus,
    to: ChannelStatus,
) -> Result<()> {
    let Some(mut helper) = stores
        .channels
        .load_helper(local.secret_id, channel_id)
        .await?
        .filter(|helper| helper.status == from)
    else {
        return Ok(());
    };
    helper.status = to;
    stores
        .channels
        .save(local.secret_id, ChannelRecord::Helper(helper))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
