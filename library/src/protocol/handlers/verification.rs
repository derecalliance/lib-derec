// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    MissingPolicy, PendingAction, SecretKind, SecretValue,
};
use super::peer_endpoint;
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::verification::{
        request::produce as produce_verify_share_request_message,
        response::{self as verification_response},
    },
    types::{ChannelId, SharedKey, Target},
};
use derec_proto::{
    DeRecResult, MessageBody, StatusEnum, StoreShareRequestMessage, VerifyShareRequestMessage,
    VerifyShareResponseMessage,
};
use prost::Message;

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn handle<Sh: DeRecShareStore>(
    share_store: &mut Sh,
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::VerifyShareRequest(request) => on_request(channel_id, request, shared_key),
        MessageBody::VerifyShareResponse(response) => {
            on_response(share_store, channel_id, &response).await
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in verification handler",
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
    version: u32,
    target: Target,
    secret_id: u64,
) -> Result<()> {
    let all_channels = channel_store.channels().await?;
    let all_channel_ids: Vec<ChannelId> = all_channels.iter().map(|c| c.id).collect();

    let channel_ids = match target {
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
    };

    let keys = secret_store
        .load_many(&channel_ids, SecretKind::SharedKey, MissingPolicy::Fail)
        .await?;

    for (channel_id, value) in keys {
        let SecretValue::SharedKey(shared_key) = value else {
            continue;
        };

        let endpoint = peer_endpoint(channel_store, channel_id).await?;
        let msg =
            produce_verify_share_request_message(channel_id, secret_id, version, &shared_key)?;

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel_id.0,
            secret_id = secret_id,
            version = version,
            "verification challenge sent"
        );

        transport.send(&endpoint, msg.envelope).await?;
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id = secret_id,
        version = version,
        "verification challenges sent"
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
    request: &VerifyShareRequestMessage,
    shared_key: &SharedKey,
) -> Result<Vec<DeRecEvent>> {
    let stored_bytes = share_store
        .load(channel_id, request.secret_id, &[request.version])
        .await?
        .into_iter()
        .next()
        .map(|s| s.bytes)
        .ok_or(Error::InvalidInput(
            "no stored share for verification request",
        ))?;
    let stored =
        StoreShareRequestMessage::decode(stored_bytes.as_slice()).map_err(Error::ProtobufDecode)?;

    let resp = verification_response::produce(channel_id, request, shared_key, &stored.share)?;

    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, resp.envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        secret_id = request.secret_id,
        version = request.version,
        "verification response sent"
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
    request: &VerifyShareRequestMessage,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let response = VerifyShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        secret_id: request.secret_id,
        version: request.version,
        nonce: request.nonce,
        hash: Vec::new(),
        timestamp: Some(current_timestamp()),
    };
    super::send_channel_message(
        channel_store,
        transport,
        channel_id,
        MessageBody::VerifyShareResponse(response),
        shared_key,
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
    request: VerifyShareRequestMessage,
    shared_key: SharedKey,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::VerifyShare {
            channel_id,
            request,
            shared_key,
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
async fn on_response<Sh: DeRecShareStore>(
    share_store: &mut Sh,
    channel_id: ChannelId,
    response: &VerifyShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let version = response.version;

    let committed_share_bytes = share_store
        .load(channel_id, response.secret_id, &[version])
        .await?
        .into_iter()
        .next()
        .map(|s| s.bytes)
        .ok_or(Error::InvalidInput(
            "no committed share stored for this channel/version — cannot verify proof",
        ))?;

    let valid = verification_response::process(response, &committed_share_bytes)?;

    if !valid {
        return Err(Error::Invariant("verification proof is invalid"));
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        secret_id = response.secret_id,
        version = version,
        "share verified"
    );

    Ok(vec![DeRecEvent::ShareVerified {
        channel_id,
        version,
    }])
}
