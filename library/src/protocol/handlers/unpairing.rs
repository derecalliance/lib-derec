// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    MissingPolicy, PendingAction, SecretKind, SecretValue, events::UnpairAck,
};
use super::{peer_endpoint, resolve_target};
use crate::derec_message::current_timestamp;
use crate::{
    Error, Result,
    primitives::unpairing::{
        request::produce as produce_unpair_request,
        response::{self as unpairing_response, process as process_unpair_response},
    },
    types::{ChannelId, SharedKey, Target},
};
use derec_proto::{
    DeRecResult, MessageBody, StatusEnum, UnpairRequestMessage, UnpairResponseMessage,
};

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
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

    let keys = secret_store
        .load_many(&channel_ids, SecretKind::SharedKey, MissingPolicy::Fail)
        .await?;

    for (channel_id, value) in keys {
        let SecretValue::SharedKey(shared_key) = value else {
            continue;
        };

        let envelope = produce_unpair_request(channel_id, &memo_str, &shared_key)?;
        let endpoint = peer_endpoint(channel_store, channel_id).await?;
        transport.send(&endpoint, envelope.envelope).await?;

        match unpair_ack {
            UnpairAck::NotRequired => {
                drop_channel_state(channel_store, share_store, secret_store, channel_id).await?;
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
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let resp = unpairing_response::produce(channel_id, shared_key)?;
    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, envelope).await?;

    drop_channel_state(channel_store, share_store, secret_store, channel_id).await?;

    #[cfg(feature = "logging")]
    tracing::info!("unpair accepted; local state dropped");

    Ok(vec![DeRecEvent::Unpaired { channel_id }])
}

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
        channel_id,
        MessageBody::UnpairResponse(response),
        shared_key,
        trace_id,
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

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
async fn on_response<Ch: DeRecChannelStore, Sh: DeRecShareStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    pending_unpair: &mut std::collections::HashMap<ChannelId, u64>,
    channel_id: ChannelId,
    response: &UnpairResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    if pending_unpair.remove(&channel_id).is_none() {
        return Ok(vec![DeRecEvent::NoOp]);
    }

    match process_unpair_response(response) {
        Ok(_) => {
            drop_channel_state(channel_store, share_store, secret_store, channel_id).await?;
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
    channel_id: ChannelId,
) -> Result<()> {
    share_store.remove_channel(channel_id).await?;

    // TODO: These removes should be condensed intoa  single function, many implementations might
    // want to have these atomic and in single db rount-trip
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
