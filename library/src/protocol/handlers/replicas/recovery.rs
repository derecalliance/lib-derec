// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The replica side of recovery.
//!
//! `GetShare` serves both relationships. Against a helper it pulls that
//! helper's share of a secret; against another group member it pulls the
//! whole secret, which is the second leg of catch-up. The owner↔helper side
//! lives in [`handlers::recovery`](super::super::recovery), which routes here
//! when the payload names an author.
use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::primitives::sharing::request::SHARE_ALGORITHM_REPLICA_SECRET;
use crate::protocol::context::{Exchange, Local};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::types::ReplicaMember;
use crate::protocol::{DeRecEvent, DeRecTransport};
use crate::types::{ReplicaId, SharedKey};
use crate::{Error, Result};
use derec_proto::{
    DeRecResult, GetShareRequestMessage, GetShareResponseMessage, MessageBody, StatusEnum,
};
use prost::Message as _;

/// Handle a recovery message a group member authored.
///
/// The author is what the request must be answered to and what a response is
/// attributed to, so resolving it is this module's job rather than the
/// dispatcher's.
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    author: u64,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::GetShareRequest(request) => {
            let member = stores
                .channels
                .load_replica_member(local.secret_id, exchange.channel_id, author)
                .await?;
            on_request(
                stores,
                local,
                &member,
                &request,
                *exchange.shared_key,
                exchange.trace_id,
            )
            .await
        }
        MessageBody::GetShareResponse(response) => {
            on_response(stores, local, ReplicaId::try_from(author)?, &response).await
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in replica recovery handler",
        )),
    }
}

/// Serve another member's request for the current state.
///
/// The reply carries the whole secret under
/// `SHARE_ALGORITHM_REPLICA_SECRET`, not a share — the same overload a
/// publish uses on the replica path.
async fn on_request<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    member: &ReplicaMember,
    request: &GetShareRequestMessage,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let composite = super::super::sharing::build_catch_up_payload(stores, local).await?;

    let (status, memo, share) = match composite {
        Some(payload) => (StatusEnum::Ok, String::new(), payload.encode_to_vec()),
        None => (
            StatusEnum::UnknownSecretId,
            "this device holds no state for that secret".to_owned(),
            Vec::new(),
        ),
    };

    let timestamp = current_timestamp();
    let response = GetShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo,
        }),
        committed_de_rec_share: share,
        // The discriminator: the bytes are the whole secret, not a share.
        share_algorithm: SHARE_ALGORITHM_REPLICA_SECRET,
        timestamp: Some(timestamp),
        secret_id: local.secret_id,
        version: request.version,
        replica_id: local.replica_id,
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(member.channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetShareResponse(response))
        .encrypt(&shared_key)?
        .build()?
        .encode_to_vec();
    let envelope = crate::derec_message::apply_trace_id(&envelope, inbound_trace_id)?;
    // A reply-to overrides the recorded endpoints for this exchange only.
    let reply_to = crate::extensions::advertised_endpoints::reply_to_owned(request);
    let endpoint = if reply_to.is_empty() {
        member.transports.clone()
    } else {
        reply_to
    };
    stores.transport.send(&endpoint, envelope).await?;

    Ok(vec![DeRecEvent::NoOp])
}

/// Hydrate the state a peer served.
async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    from: ReplicaId,
    response: &GetShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let status = response.result.as_ref().map(|r| r.status).unwrap_or(-1);
    if status != StatusEnum::Ok as i32 {
        return Ok(vec![DeRecEvent::NoOp]);
    }
    if response.share_algorithm != SHARE_ALGORITHM_REPLICA_SECRET {
        return Err(Error::InvalidInput(
            "a member answered a catch-up with a helper share rather than the secret",
        ));
    }

    super::super::sharing::hydrate_catch_up(
        stores,
        local,
        from.0,
        response.version,
        &response.committed_de_rec_share,
    )
    .await
}
