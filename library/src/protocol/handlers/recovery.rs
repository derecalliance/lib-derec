// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    MissingPolicy, PendingAction, PendingRecovery, SecretKind, SecretValue,
};
use super::peer_endpoint;
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::recovery::{RecoveryError, request, response},
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecResult, GetShareRequestMessage, GetShareResponseMessage, MessageBody, StatusEnum,
    StoreShareRequestMessage,
};
use prost::Message;

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) fn handle(
    pending_recovery: &mut PendingRecovery,
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::GetShareRequest(request) => {
            on_request(channel_id, request, shared_key, inbound_trace_id)
        }
        MessageBody::GetShareResponse(response) => {
            on_response(pending_recovery, channel_id, &response)
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in recovery handler",
        )),
    }
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(secret_id = secret_id, version = version))
)]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    pending_recovery: &mut PendingRecovery,
    secret_id: u64,
    version: u32,
) -> Result<()> {
    pending_recovery.insert((secret_id, version), Vec::new());

    let all_channels = channel_store.channels().await?;
    let channel_ids: Vec<ChannelId> = all_channels.iter().map(|c| c.id).collect();
    let mut keys: std::collections::HashMap<ChannelId, SharedKey> = secret_store
        .load_many(&channel_ids, SecretKind::SharedKey, MissingPolicy::Fail)
        .await?
        .into_iter()
        .filter_map(|(cid, v)| match v {
            SecretValue::SharedKey(k) => Some((cid, k)),
            _ => None,
        })
        .collect();

    for channel in all_channels {
        let shared_key = keys
            .remove(&channel.id)
            .expect("load_many(MissingPolicy::Fail) guarantees an entry per id");

        let msg = request::produce(channel.id, secret_id, version, &shared_key)?;
        transport.send(&channel.transport, msg.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel.id.0,
            secret_id,
            version,
            "share request sent"
        );
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id,
        version,
        "share requests dispatched to all helpers"
    );

    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
pub(in crate::protocol) async fn accept<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    transport: &T,
    channel_id: ChannelId,
    request: &GetShareRequestMessage,
    shared_key: &SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let linked_ids = channel_store.linked_channels(channel_id).await?;

    let encoded = share_store
        .load_many(&linked_ids, request.secret_id, &[request.version])
        .await?
        .into_iter()
        .next()
        .map(|s| s.bytes)
        .ok_or(Error::InvalidInput("no stored share for recovery request"))?;

    let stored =
        StoreShareRequestMessage::decode(encoded.as_slice()).map_err(Error::ProtobufDecode)?;

    let resp = response::produce(channel_id, request, &stored, shared_key)?;

    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        secret_id = request.secret_id,
        version = request.version,
        "recovery share response sent"
    );

    Ok(vec![DeRecEvent::NoOp])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    request: &GetShareRequestMessage,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
) -> Result<()> {
    let response = GetShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        committed_de_rec_share: Vec::new(),
        share_algorithm: 0,
        timestamp: Some(current_timestamp()),
        secret_id: request.secret_id,
        version: request.version,
    };

    super::send_channel_message(
        channel_store,
        transport,
        channel_id,
        MessageBody::GetShareResponse(response),
        shared_key,
        trace_id,
    )
    .await
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
fn on_request(
    channel_id: ChannelId,
    request: GetShareRequestMessage,
    shared_key: SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::GetShare {
            channel_id,
            request,
            shared_key,
            trace_id,
        },
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = response.secret_id,
            version = response.version
        )
    )
)]
fn on_response(
    pending_recovery: &mut PendingRecovery,
    channel_id: ChannelId,
    response: &GetShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let key = (response.secret_id, response.version);
    let (secret_id, version) = key;

    let Some(bucket) = pending_recovery.get_mut(&key) else {
        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel_id.0,
            secret_id,
            version,
            "recovery response has no matching pending recovery; dropping"
        );
        return Ok(vec![DeRecEvent::NoOp]);
    };

    bucket.push(response.clone());
    let shares_received = bucket.len();
    let inputs: Vec<&GetShareResponseMessage> = bucket.iter().collect();

    let event = match response::recover(secret_id, version, &inputs) {
        Ok(result) => {
            pending_recovery.remove(&key);

            #[cfg(feature = "logging")]
            tracing::info!(
                channel_id = channel_id.0,
                secret_id,
                version,
                shares_received,
                "secret reconstructed from shares"
            );

            DeRecEvent::SecretRecovered {
                secret: result.secret_data,
            }
        }
        Err(Error::Recovery(RecoveryError::ReconstructionFailed { ref source }))
            if matches!(
                source,
                derec_cryptography::vss::DerecVSSError::InsufficientShares
            ) =>
        {
            #[cfg(feature = "logging")]
            tracing::debug!(
                channel_id = channel_id.0,
                secret_id,
                version,
                shares_received,
                "reconstruction not yet possible — insufficient shares"
            );

            DeRecEvent::RecoveryShareReceived {
                channel_id,
                shares_received,
            }
        }
        Err(e) => {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                secret_id,
                version,
                shares_received,
                error = %e,
                "recovery share response received but reconstruction failed"
            );

            DeRecEvent::RecoveryShareError {
                channel_id,
                shares_received,
                error: e.to_string(),
            }
        }
    };

    Ok(vec![event])
}
