// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport, MissingPolicy,
    PendingAction, SecretKind, SecretValue, StateItem, StateKey,
};
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::protocol::context::{Exchange, Local, Round};
use crate::protocol::stores::{StoreSet, Stores};
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

/// Route an inbound verification message.
///
/// A response is admitted only against an outstanding challenge: the
/// `PendingVerification` row for the channel is read and deleted, so a
/// replay of a consumed challenge — or a response with no owner-side
/// request behind it — is dropped as a `NoOp`. The `load` + `remove`
/// pair is two round-trips and not atomic across instances (see the
/// multi-instance concurrency contract on [`crate::protocol::DeRecStateStore`]);
/// duplicate `ShareVerified` events from two racing instances are
/// idempotent for the application.
///
/// Binding of `(nonce, secret_id, version)` against the recorded request
/// is enforced by the primitive before the SHA-384 check. A binding
/// mismatch surfaces as `Error::Verification(..)` and is returned to the
/// caller rather than swallowed.
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
    match inner {
        MessageBody::VerifyShareRequest(request) => on_request(exchange, request),
        MessageBody::VerifyShareResponse(response) => {
            on_response(stores, local.secret_id, exchange.channel_id, &response).await
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in verification handler",
        )),
    }
}

/// Challenge each targeted helper to prove it still holds the stored
/// share for `version`.
///
/// Each outstanding challenge is recorded in the state store before the
/// request goes out, so the matching response can be bound back to it.
/// The row is keyed by `(secret_id, channel_id)`: re-issuing
/// `start(VerifyShares)` for the same channel overwrites any in-flight
/// challenge under the store's full-replacement `save` semantic and the
/// newer nonce wins, leaving stale responses to fail the binding check.
///
/// Dispatch failure is isolated per channel and surfaced as
/// `VerifySharesFailed` rather than short-circuiting the fan-out.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = round.trace_id, secret_id = local.secret_id, version = version))
)]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    version: u32,
    target: Target,
    round: &Round<'_>,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    let known: Vec<ChannelId> = stores
        .channels
        .helpers_matching(
            secret_id,
            crate::protocol::types::HelperFilter {
                ids: target.ids(),
                ..Default::default()
            },
        )
        .await?
        .iter()
        .map(|c| c.channel_id)
        .collect();

    let channel_ids = target.filter(&known);

    let keys = stores
        .secrets
        .load_many(
            secret_id,
            &channel_ids,
            SecretKind::SharedKey,
            MissingPolicy::Fail,
        )
        .await?;

    let events = dispatch_all(stores, secret_id, version, keys, round).await;

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id = secret_id,
        version = version,
        "verification challenges sent"
    );

    Ok(events)
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
pub(in crate::protocol) async fn accept<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &VerifyShareRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    let (secret_id, channel_id) = (local.secret_id, exchange.channel_id);

    let stored_bytes = stores
        .shares
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

    let resp =
        verification_response::produce(channel_id, request, exchange.shared_key, &stored.share)?;

    let envelope = crate::derec_message::apply_trace_id(&resp.envelope, exchange.trace_id)?;
    let endpoint = stores
        .channels
        .resolve_response_endpoints(secret_id, channel_id, &request.reply_to)
        .await?;
    stores.transport.send(&endpoint, envelope).await?;

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
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
pub(in crate::protocol) async fn reject<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &VerifyShareRequestMessage,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let (secret_id, channel_id) = (local.secret_id, exchange.channel_id);
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
    crate::extensions::channel_store::send_channel_message(
        stores.channels,
        stores.transport,
        secret_id,
        channel_id,
        MessageBody::VerifyShareResponse(response),
        exchange.shared_key,
        exchange.trace_id,
        &request.reply_to,
    )
    .await
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
fn on_request(
    exchange: &Exchange<'_>,
    request: VerifyShareRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id: exchange.channel_id,
        action: PendingAction::VerifyShare {
            channel_id: exchange.channel_id,
            request,
            shared_key: *exchange.shared_key,
            trace_id: exchange.trace_id,
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
async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    secret_id: u64,
    channel_id: ChannelId,
    response: &VerifyShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let key = StateKey::PendingVerification { channel_id };
    let Some(StateItem::PendingVerification { request, .. }) =
        stores.state.load(secret_id, key.clone()).await?
    else {
        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = channel_id.0,
            "verification response with no outstanding challenge; dropping as no-op"
        );
        return Ok(vec![DeRecEvent::NoOp]);
    };
    let _ = stores.state.remove(secret_id, key).await?;

    let version = response.version;

    let committed_share_bytes = stores
        .shares
        .load(secret_id, channel_id, &[version])
        .await?
        .into_iter()
        .next()
        .map(|s| s.bytes)
        .ok_or(Error::InvalidInput(
            "no committed share stored for this channel/version — cannot verify proof",
        ))?;

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

/// Send a challenge to every resolved channel, reporting each outcome.
///
/// One event per target, in the order the targets were resolved. A failure is
/// isolated to its own target: it becomes a `VerifySharesFailed` and the
/// fan-out continues.
async fn dispatch_all<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    secret_id: u64,
    version: u32,
    keys: Vec<(ChannelId, SecretValue)>,
    round: &Round<'_>,
) -> Vec<DeRecEvent> {
    let mut events = Vec::with_capacity(keys.len());
    for (channel_id, value) in keys {
        let SecretValue::SharedKey(shared_key) = value else {
            events.push(DeRecEvent::VerifySharesFailed {
                channel_id,
                version,
                error: "channel has no shared key".to_owned(),
            });
            continue;
        };

        match dispatch_one(stores, secret_id, version, channel_id, &shared_key, round).await {
            Ok(()) => {
                events.push(DeRecEvent::VerifySharesStarted {
                    channel_id,
                    version,
                    trace_id: round.trace_id,
                });
                #[cfg(feature = "logging")]
                tracing::debug!(
                    channel_id = channel_id.0,
                    secret_id = secret_id,
                    version = version,
                    "verification challenge sent"
                );
            }
            Err(e) => {
                events.push(DeRecEvent::VerifySharesFailed {
                    channel_id,
                    version,
                    error: e.to_string(),
                });
                #[cfg(feature = "logging")]
                tracing::warn!(
                    channel_id = channel_id.0,
                    secret_id = secret_id,
                    version = version,
                    error = %e,
                    "verification challenge dispatch failed"
                );
            }
        }
    }
    events
}

async fn dispatch_one<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    secret_id: u64,
    version: u32,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    round: &Round<'_>,
) -> Result<()> {
    let endpoint = stores
        .channels
        .peer_endpoints(secret_id, channel_id)
        .await?;
    let msg = produce_verify_share_request_message(
        channel_id,
        secret_id,
        version,
        shared_key,
        round.reply_to,
    )?;

    stores
        .state
        .save(
            secret_id,
            StateItem::PendingVerification {
                channel_id,
                request: derec_proto::VerifyShareRequestMessage {
                    secret_id,
                    version,
                    nonce: msg.nonce,
                    timestamp: None,
                    reply_to: round.reply_to.to_vec(),
                },
            },
        )
        .await?;

    let envelope = crate::derec_message::apply_trace_id(&msg.envelope, round.trace_id)?;
    stores.transport.send(&endpoint, envelope).await?;
    Ok(())
}
