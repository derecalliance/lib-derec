// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    PendingAction, PendingRecovery, SecretKind, SecretValue,
};
use super::peer_endpoint;
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::recovery::{
        RecoveryError,
        request::produce as produce_get_share_request_message,
        response::{self as recovery_response},
    },
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
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::GetShareRequest(request) => on_request(channel_id, request, shared_key),
        MessageBody::GetShareResponse(response) => {
            on_response(pending_recovery, channel_id, &response)
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in recovery handler",
        )),
    }
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(version = version)))]
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

    for channel in all_channels {
        // TODO: Not being able to load a shared_key for a channel is completely unexpected,
        // continuing is not an option. At this point the owner is in recovery mode, it has already
        // paired with channels, so shared_key for the channel must be there
        // TODO: add a load_many function to reduce DB roundtrips
        let Some(SecretValue::SharedKey(shared_key)) =
            secret_store.load(channel.id, SecretKind::SharedKey).await?
        else {
            continue;
        };

        // TODO: see if we can send all requests in parallel and wait them all together
        let msg = produce_get_share_request_message(channel.id, secret_id, version, &shared_key)?;
        transport.send(&channel.transport, msg.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel.id.0,
            version = version,
            "share request sent"
        );
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        version = version,
        "share requests dispatched to all helpers"
    );

    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = request.share_version))
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
) -> Result<Vec<DeRecEvent>> {
    let linked_ids = channel_store.linked_channels(channel_id).await?;

    let encoded = share_store
        .load_many(&linked_ids, request.secret_id, &[request.share_version])
        .await?
        .into_iter()
        .next()
        .map(|s| s.bytes)
        .ok_or(Error::InvalidInput("no stored share for recovery request"))?;

    let stored =
        StoreShareRequestMessage::decode(encoded.as_slice()).map_err(Error::ProtobufDecode)?;

    let resp = recovery_response::produce(channel_id, request, &stored, shared_key)?;

    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, resp.envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!("recovery share response sent");

    Ok(vec![DeRecEvent::NoOp])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let response = GetShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        committed_de_rec_share: Vec::new(),
        share_algorithm: 0,
        timestamp: Some(current_timestamp()),
    };

    super::send_channel_message(
        channel_store,
        transport,
        channel_id,
        MessageBody::GetShareResponse(response),
        shared_key,
    )
    .await
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
fn on_request(
    channel_id: ChannelId,
    request: GetShareRequestMessage,
    shared_key: SharedKey,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::GetShare {
            channel_id,
            request,
            shared_key,
        },
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
fn on_response(
    pending_recovery: &mut PendingRecovery,
    channel_id: ChannelId,
    response: &GetShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let mut events = Vec::new();

    let keys: Vec<(u64, u32)> = pending_recovery.keys().cloned().collect();
    for key in keys {
        let (secret_id, version) = key;
        let bucket = pending_recovery.get_mut(&key).unwrap();
        bucket.push(response.clone());

        let shares_received = bucket.len();

        let inputs: Vec<&GetShareResponseMessage> = bucket.iter().collect();

        match recovery_response::recover(secret_id, version, &inputs) {
            Ok(result) => {
                pending_recovery.remove(&key);

                #[cfg(feature = "logging")]
                tracing::info!(
                    version = version,
                    shares_received,
                    "secret reconstructed from shares"
                );

                events.push(DeRecEvent::SecretRecovered {
                    secret: result.secret_data,
                });
            }
            Err(Error::Recovery(RecoveryError::ReconstructionFailed { ref source }))
                if matches!(
                    source,
                    derec_cryptography::vss::DerecVSSError::InsufficientShares
                ) =>
            {
                #[cfg(feature = "logging")]
                tracing::debug!(
                    version = version,
                    shares_received,
                    channel_id = channel_id.0,
                    "reconstruction not yet possible — insufficient shares"
                );

                events.push(DeRecEvent::RecoveryShareReceived {
                    channel_id,
                    shares_received,
                });
            }
            Err(e) => {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    version = version,
                    shares_received,
                    channel_id = channel_id.0,
                    error = %e,
                    "recovery share response received but reconstruction failed"
                );

                events.push(DeRecEvent::RecoveryShareError {
                    channel_id,
                    shares_received,
                    error: e.to_string(),
                });
            }
        }
    }

    if events.is_empty() {
        events.push(DeRecEvent::NoOp);
    }

    Ok(events)
}
