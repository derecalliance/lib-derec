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
        response::{self as recovery_response, RecoveryResponseInput},
    },
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecResult, GetShareRequestMessage, GetShareResponseMessage, MessageBody, StatusEnum,
    StoreShareRequestMessage,
};
use prost::Message;

/// Dispatch an inbound recovery message (request or response).
pub(in crate::protocol) fn handle(
    pending_recovery: &mut PendingRecovery,
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::GetShareRequest(request) => Ok(on_request(channel_id, request, shared_key)),
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
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
fn on_request(
    channel_id: ChannelId,
    request: GetShareRequestMessage,
    shared_key: SharedKey,
) -> Vec<DeRecEvent> {
    vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::GetShare {
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
fn on_response(
    pending_recovery: &mut PendingRecovery,
    channel_id: ChannelId,
    response: &GetShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let mut events = Vec::new();

    let keys: Vec<(Vec<u8>, i32)> = pending_recovery.keys().cloned().collect();
    for key in keys {
        let (ref secret_id, version) = key;
        let bucket = pending_recovery.get_mut(&key).unwrap();
        bucket.push(response.clone());

        let shares_received = bucket.len();

        let inputs: Vec<RecoveryResponseInput<'_>> = bucket
            .iter()
            .map(|r| RecoveryResponseInput { share_response: r })
            .collect();

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

/// Accept a get-share request: load share and send response.
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
    let encoded = share_store
        .load(channel_id, &[request.share_version])
        .await?
        .into_iter()
        .next()
        .map(|(_, data)| data)
        .ok_or(Error::InvalidInput("no stored share for recovery request"))?;
    let stored =
        StoreShareRequestMessage::decode(encoded.as_slice()).map_err(Error::ProtobufDecode)?;

    let resp =
        recovery_response::produce(channel_id, &request.secret_id, request, &stored, shared_key)?;

    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, resp.envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!("recovery share response sent");

    Ok(vec![DeRecEvent::NoOp])
}

/// Reject a get-share request: send FAIL response.
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    memo: &str,
) -> Result<()> {
    let response = GetShareResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Fail as i32,
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

/// Request shares from all paired helpers to recover a secret.
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
    secret_id: Vec<u8>,
    version: i32,
) -> Result<()> {
    pending_recovery.insert((secret_id.clone(), version), Vec::new());

    let all_channels = channel_store.channels().await?;

    for channel in all_channels {
        let Some(SecretValue::SharedKey(shared_key)) =
            secret_store.load(channel.id, SecretKind::SharedKey).await?
        else {
            continue;
        };

        let msg = produce_get_share_request_message(channel.id, &secret_id, version, &shared_key)?;
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
