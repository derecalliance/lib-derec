// SPDX-License-Identifier: Apache-2.0

//! Unpairing flow handler (orchestrator-side).
//!
//! Wraps the [`crate::primitives::unpairing`] primitive with the
//! state-management logic the orchestrator needs:
//!
//! - [`start`]: sends `UnpairRequest` envelopes to the targeted channels and,
//!   depending on the configured [`UnpairAck`], either drops local state
//!   immediately (fire-and-forget) or records a pending entry and waits for
//!   the peer's response.
//! - [`accept`]: invoked from [`super::super::DeRecProtocol::accept`] when the
//!   application accepts an [`crate::protocol::PendingAction::Unpair`] action.
//!   Sends back an `Ok` response and tears down the local state for the
//!   channel.
//! - [`reject`]: sends back a non-`Ok` response without touching local state.
//! - [`handle`]: dispatches incoming `UnpairRequest` / `UnpairResponse`
//!   envelopes from the channel-message route.
//!
//! The actual deletion is performed by [`drop_channel_state`], which removes
//! the channel record, the shared key, and any per-channel share entries.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    PendingAction, SecretKind, SecretValue, events::UnpairAck,
};
use super::peer_endpoint;
use crate::{
    Error, Result,
    primitives::unpairing::{
        request::produce as produce_unpair_request,
        response::{
            self as unpairing_response, process as process_unpair_response,
        },
    },
    types::{ChannelId, SharedKey, Target},
};
use derec_proto::{MessageBody, StatusEnum, UnpairRequestMessage, UnpairResponseMessage};

pub(in crate::protocol) async fn handle<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    pending_unpair: &mut std::collections::HashMap<ChannelId, u64>,
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::UnpairRequest(request) => Ok(on_request(channel_id, request, shared_key)),
        MessageBody::UnpairResponse(response) => {
            on_response(
                channel_store,
                share_store,
                secret_store,
                pending_unpair,
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

/// Send unpair-request envelopes to the targeted channels.
///
/// For each channel:
///
/// - Load the channel's `shared_key`. Channels without a key are silently
///   skipped — they were never paired or have already been torn down.
/// - Produce and send the [`derec_proto::UnpairRequestMessage`].
/// - If `unpair_ack == UnpairAck::NotRequired`, drop the local state right
///   away and emit [`DeRecEvent::Unpaired`].
/// - If `unpair_ack == UnpairAck::Required`, record the channel in
///   `pending_unpair` along with `started_at` so the protocol can later
///   time out the wait inside `process()`.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    transport: &T,
    pending_unpair: &mut std::collections::HashMap<ChannelId, u64>,
    target: Target,
    memo: Option<String>,
    unpair_ack: UnpairAck,
    now: u64,
) -> Result<Vec<DeRecEvent>> {
    let channel_ids = resolve_target(channel_store, target).await?;
    let memo_str = memo.unwrap_or_default();
    let mut events = Vec::new();

    for channel_id in channel_ids {
        let Some(SecretValue::SharedKey(shared_key)) =
            secret_store.load(channel_id, SecretKind::SharedKey).await?
        else {
            // Not (or no longer) paired — nothing to do for this channel.
            continue;
        };

        let envelope = produce_unpair_request(channel_id, &memo_str, &shared_key)?;
        let endpoint = peer_endpoint(channel_store, channel_id).await?;
        transport.send(&endpoint, envelope.envelope).await?;

        match unpair_ack {
            UnpairAck::NotRequired => {
                drop_channel_state(channel_store, share_store, secret_store, channel_id)
                    .await?;
                events.push(DeRecEvent::Unpaired { channel_id });
            }
            UnpairAck::Required => {
                pending_unpair.insert(channel_id, now);
            }
        }

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel_id.0,
            ack = ?unpair_ack,
            "unpair request sent"
        );
    }

    #[cfg(feature = "logging")]
    tracing::info!("unpair requests dispatched");

    Ok(events)
}

/// Accept an incoming unpair request: send `Ok` response, drop local state,
/// emit [`DeRecEvent::Unpaired`].
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
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
    channel_id: ChannelId,
    _request: &UnpairRequestMessage,
    shared_key: &SharedKey,
) -> Result<Vec<DeRecEvent>> {
    // Send Ok response BEFORE dropping state so the response uses the still-
    // live channel transport URI and shared key.
    let resp = unpairing_response::produce(channel_id, shared_key)?;
    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, resp.envelope).await?;

    drop_channel_state(channel_store, share_store, secret_store, channel_id).await?;

    #[cfg(feature = "logging")]
    tracing::info!("unpair accepted; local state dropped");

    Ok(vec![DeRecEvent::Unpaired { channel_id }])
}

/// Reject an incoming unpair request: send a non-`Ok` response and keep
/// local state intact.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, status = status as i32))
)]
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let resp = unpairing_response::reject(channel_id, shared_key, status, memo)?;
    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, resp.envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!("unpair rejected by application");

    Ok(())
}

/// Resolve the `Target` against the channel store's view of paired channels.
async fn resolve_target<Ch: DeRecChannelStore>(
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

/// Drop every piece of state the protocol holds for `channel_id`.
///
/// Idempotent — non-existent entries are no-ops.
pub(super) async fn drop_channel_state<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    channel_id: ChannelId,
) -> Result<()> {
    // Share entries first — they reference the channel and key by id, so
    // dropping them before the channel record itself avoids any window where
    // shares point at a vanished channel.
    share_store.remove_channel(channel_id).await?;

    let _ = secret_store.remove(channel_id, SecretKind::SharedKey).await;
    let _ = secret_store
        .remove(channel_id, SecretKind::PairingSecret)
        .await;
    let _ = secret_store
        .remove(channel_id, SecretKind::PairingContact)
        .await;

    let _ = channel_store.remove(channel_id).await?;
    Ok(())
}

fn on_request(
    channel_id: ChannelId,
    request: UnpairRequestMessage,
    shared_key: SharedKey,
) -> Vec<DeRecEvent> {
    vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::Unpair {
            channel_id,
            request,
            shared_key,
        },
    }]
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
async fn on_response<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    pending_unpair: &mut std::collections::HashMap<ChannelId, u64>,
    channel_id: ChannelId,
    response: &UnpairResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    // Acknowledgements only matter when we're actually waiting for one — the
    // `UnpairAck::NotRequired` path has already dropped local state and
    // never inserted into `pending_unpair`.
    if pending_unpair.remove(&channel_id).is_none() {
        // Either we never asked, or we asked under `NotRequired`. Treat the
        // late response as a benign no-op.
        return Ok(vec![DeRecEvent::NoOp]);
    }

    match process_unpair_response(response) {
        Ok(_) => {
            drop_channel_state(channel_store, share_store, secret_store, channel_id).await?;
            Ok(vec![DeRecEvent::Unpaired { channel_id }])
        }
        Err(Error::Unpairing(
            crate::primitives::unpairing::UnpairingError::NonOkStatus { status, memo },
        )) => Ok(vec![DeRecEvent::UnpairRejected {
            channel_id,
            status,
            memo,
        }]),
        Err(e) => Err(e),
    }
}

/// Walk `pending_unpair` and emit [`DeRecEvent::Unpaired`] for entries whose
/// `started_at` is older than `timeout_secs`, dropping their local state.
///
/// Called from [`super::super::DeRecProtocol::process`] on every inbound
/// message so the timeout fires without relying on a separate timer.
pub(in crate::protocol) async fn check_timeouts<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    pending_unpair: &mut std::collections::HashMap<ChannelId, u64>,
    now: u64,
    timeout_secs: u64,
) -> Vec<DeRecEvent> {
    let expired: Vec<ChannelId> = pending_unpair
        .iter()
        .filter_map(|(cid, started_at)| {
            if now.saturating_sub(*started_at) > timeout_secs {
                Some(*cid)
            } else {
                None
            }
        })
        .collect();

    let mut events = Vec::with_capacity(expired.len());
    for cid in expired {
        pending_unpair.remove(&cid);
        if drop_channel_state(channel_store, share_store, secret_store, cid)
            .await
            .is_ok()
        {
            events.push(DeRecEvent::Unpaired { channel_id: cid });
        }
    }
    events
}
