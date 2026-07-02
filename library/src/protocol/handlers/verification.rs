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
    protocol::types::Target,
    types::{ChannelId, SharedKey},
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
    pending_verification: &mut crate::protocol::PendingVerification,
    secret_id: u64,
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::VerifyShareRequest(request) => {
            on_request(channel_id, request, shared_key, inbound_trace_id)
        }
        MessageBody::VerifyShareResponse(response) => {
            on_response(
                share_store,
                pending_verification,
                secret_id,
                channel_id,
                &response,
            )
            .await
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
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    pending_verification: &mut crate::protocol::PendingVerification,
    version: u32,
    target: Target,
    secret_id: u64,
    reply_to: Option<derec_proto::TransportProtocol>,
) -> Result<()> {
    let all_channels = channel_store.channels(secret_id).await?;
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
        .load_many(
            secret_id,
            &channel_ids,
            SecretKind::SharedKey,
            MissingPolicy::Fail,
        )
        .await?;

    for (channel_id, value) in keys {
        let SecretValue::SharedKey(shared_key) = value else {
            continue;
        };

        let endpoint = peer_endpoint(channel_store, secret_id, channel_id).await?;
        let msg = produce_verify_share_request_message(
            channel_id,
            secret_id,
            version,
            &shared_key,
            reply_to.clone(),
        )?;

        // Record the outstanding challenge so the matching inbound
        // response can be bound back to it. The map is keyed by
        // `channel_id` — re-issuing `start(VerifyShares)` for the
        // same channel overwrites any in-flight challenge, and the
        // newer nonce wins. Stale responses tied to the older nonce
        // fall through `on_response`'s binding check below.
        pending_verification.insert(
            channel_id,
            derec_proto::VerifyShareRequestMessage {
                secret_id,
                version,
                nonce: msg.nonce,
                timestamp: None,
                reply_to: reply_to.clone(),
            },
        );

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel_id.0,
            secret_id = secret_id,
            version = version,
            "verification challenge sent"
        );

        let envelope = super::apply_trace_id(msg.envelope, super::fresh_trace_id())?;
        transport.send(&endpoint, envelope).await?;
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
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn accept<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    request: &VerifyShareRequestMessage,
    shared_key: &SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let stored_bytes = share_store
        .load(secret_id, channel_id, &[request.version])
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

    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    let endpoint = super::resolve_response_endpoint(
        channel_store,
        secret_id,
        channel_id,
        request.reply_to.as_ref(),
    )
    .await?;
    transport.send(&endpoint, envelope).await?;

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
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    request: &VerifyShareRequestMessage,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
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
        secret_id,
        channel_id,
        MessageBody::VerifyShareResponse(response),
        shared_key,
        trace_id,
        request.reply_to.as_ref(),
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
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::VerifyShare {
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
async fn on_response<Sh: DeRecShareStore>(
    share_store: &mut Sh,
    pending_verification: &mut crate::protocol::PendingVerification,
    secret_id: u64,
    channel_id: ChannelId,
    response: &VerifyShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    // Replay/freshness gate. Pop the outstanding request for this
    // channel — if there isn't one, the response is either a replay
    // of a now-consumed challenge or arrived without any owner-side
    // request to correspond to. Drop it silently as a NoOp; the
    // primitive's binding check would fail anyway, but a no-op event
    // matches the existing pattern used by `unpairing::on_response`.
    let Some(request) = pending_verification.remove(&channel_id) else {
        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = channel_id.0,
            "verification response with no outstanding challenge; dropping as no-op"
        );
        return Ok(vec![DeRecEvent::NoOp]);
    };

    let version = response.version;

    let committed_share_bytes = share_store
        .load(secret_id, channel_id, &[version])
        .await?
        .into_iter()
        .next()
        .map(|s| s.bytes)
        .ok_or(Error::InvalidInput(
            "no committed share stored for this channel/version — cannot verify proof",
        ))?;

    // The primitive's `process` enforces (nonce, secret_id, version)
    // binding against `request` before the SHA-384 check. A binding
    // mismatch surfaces here as `Error::Verification(...)` and is
    // returned to the caller so the application sees the failure
    // explicitly.
    let valid = verification_response::process(&request, response, &committed_share_bytes)?;

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
