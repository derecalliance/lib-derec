// SPDX-License-Identifier: Apache-2.0

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
//! response envelope is routed by channel id at the transport layer.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecStateStore,
    DeRecTransport, PendingAction, SecretKind, SecretValue, StateItem, StateKey,
    events::UnpairAck,
};
use super::peer_endpoint;
use crate::derec_message::current_timestamp;
use crate::{
    Error, Result,
    primitives::unpairing::{
        request::produce as produce_unpair_request,
        response::{self as unpairing_response, process as process_unpair_response},
    },
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecResult, MessageBody, StatusEnum, UnpairRequestMessage, UnpairResponseMessage,
};

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn handle<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    St: DeRecStateStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    state_store: &mut St,
    secret_id: u64,
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::UnpairRequest(request) => {
            on_request(channel_id, request, shared_key, inbound_trace_id)
        }
        MessageBody::UnpairResponse(response) => {
            on_response(
                channel_store,
                share_store,
                secret_store,
                state_store,
                secret_id,
                channel_id,
                &response,
            )
            .await
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in unpairing handler",
        )),
    }
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    transport: &T,
    state_store: &mut St,
    secret_id: u64,
    channel_id: ChannelId,
    memo: Option<String>,
    unpair_ack: UnpairAck,
    now: u64,
    reply_to: Option<derec_proto::TransportProtocol>,
) -> Result<Vec<DeRecEvent>> {
    let memo_str = memo.unwrap_or_default();
    let mut events = Vec::new();

    let shared_key = match secret_store
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

    let request = produce_unpair_request(channel_id, &memo_str, &shared_key, reply_to)?;
    let envelope = super::apply_trace_id(request.envelope, super::fresh_trace_id())?;
    let endpoint = peer_endpoint(channel_store, secret_id, channel_id).await?;
    transport.send(&endpoint, envelope).await?;

    match unpair_ack {
        UnpairAck::NotRequired => {
            drop_channel_state(
                channel_store,
                share_store,
                secret_store,
                secret_id,
                channel_id,
            )
            .await?;
            events.push(DeRecEvent::Unpaired { channel_id });
        }
        UnpairAck::Required => {
            state_store
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
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn accept<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    request: &UnpairRequestMessage,
    shared_key: &SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let resp = unpairing_response::produce(channel_id, shared_key)?;
    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    let endpoint = super::resolve_response_endpoint(
        channel_store,
        secret_id,
        channel_id,
        request.reply_to.as_ref(),
    )
    .await?;
    transport.send(&endpoint, envelope).await?;

    drop_channel_state(
        channel_store,
        share_store,
        secret_store,
        secret_id,
        channel_id,
    )
    .await?;

    #[cfg(feature = "logging")]
    tracing::info!("unpair accepted; local state dropped");

    Ok(vec![DeRecEvent::Unpaired { channel_id }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, status = status as i32))
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    request: &UnpairRequestMessage,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
) -> Result<()> {
    let response = UnpairResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        timestamp: Some(current_timestamp()),
    };

    super::send_channel_message(
        channel_store,
        transport,
        secret_id,
        channel_id,
        MessageBody::UnpairResponse(response),
        shared_key,
        trace_id,
        request.reply_to.as_ref(),
    )
    .await
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
fn on_request(
    channel_id: ChannelId,
    request: UnpairRequestMessage,
    shared_key: SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::Unpair {
            channel_id,
            request,
            shared_key,
            trace_id,
        },
    }])
}

/// Handle an inbound [`UnpairResponseMessage`] on the initiator
/// side under [`crate::protocol::UnpairAck::Required`].
///
/// The [`crate::protocol::DeRecStateStore::remove`] call below is the
/// flow's replay guard: an `UnpairResponse` is only acted on when a
/// matching outbound `UnpairRequest` is still in flight for that
/// `channel_id`. Replayed or stale responses (which the primitive
/// alone cannot detect — see the module-level Security section)
/// fall through to [`DeRecEvent::NoOp`] without mutating any state.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
async fn on_response<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    St: DeRecStateStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    state_store: &mut St,
    secret_id: u64,
    channel_id: ChannelId,
    response: &UnpairResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    // Replay/freshness guard. See the module docs for the full
    // idempotency argument — `remove` returns `false` when no row
    // existed for this channel, i.e. no in-flight unpair, so the
    // response (legitimate or replayed) is dropped as a no-op.
    if !state_store
        .remove(secret_id, StateKey::PendingUnpair { channel_id })
        .await?
    {
        return Ok(vec![DeRecEvent::NoOp]);
    }

    match process_unpair_response(response) {
        Ok(_) => {
            drop_channel_state(
                channel_store,
                share_store,
                secret_store,
                secret_id,
                channel_id,
            )
            .await?;
            Ok(vec![DeRecEvent::Unpaired { channel_id }])
        }
        Err(Error::Unpairing(crate::primitives::unpairing::UnpairingError::NonOkStatus {
            status,
            memo,
        })) => Ok(vec![DeRecEvent::UnpairRejected {
            channel_id,
            status,
            memo,
        }]),
        Err(e) => Err(e),
    }
}

pub(in crate::protocol) async fn drop_channel_state<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    secret_id: u64,
    channel_id: ChannelId,
) -> Result<()> {
    share_store.remove_channel(secret_id, channel_id).await?;

    let _ = secret_store
        .remove(secret_id, channel_id, SecretKind::SharedKey)
        .await;
    let _ = secret_store
        .remove(secret_id, channel_id, SecretKind::PairingSecret)
        .await;
    let _ = secret_store
        .remove(secret_id, channel_id, SecretKind::PairingContact)
        .await;

    let _ = channel_store.remove(secret_id, channel_id).await?;
    Ok(())
}
