// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Inbound dispatch, and the per-flow handlers it routes to.
//!
//! Everything arriving at [`DeRecProtocol::process`](crate::protocol::DeRecProtocol::process)
//! lands here once the envelope is decrypted. [`handle`] does only what is
//! the same for every message — apply the transport policy to any endpoint
//! the peer supplied, gate the bodies that name exactly one permitted
//! sender role, then hand the body to the module that owns its flow, and
//! answer the peer if that module failed.
//!
//! **Everything flow-specific belongs to the flow.** A message type that
//! serves both the owner↔helper and the replica-group relationships is
//! decided inside its own handler, not here: that handler reads
//! [`MessageBodyExt::route`](crate::extensions::message_body::MessageBodyExt::route), loads the group
//! member if there is one, applies the role gate its route calls for, and
//! picks what to run. So a failure in store-share is answered in
//! `sharing.rs`, and one in recovery in `recovery.rs`, without going through
//! the dispatcher first.
//!
//! The replica reading of each flow lives in [`replicas`], one file per flow
//! under the same name, so a handler here is the owner↔helper half plus a
//! delegation. A flow with no owner↔helper counterpart lives there whole.
//!
//! Handlers are internal: applications drive flows through
//! [`DeRecFlow`](crate::protocol::DeRecFlow) and observe them through
//! [`DeRecEvent`](crate::protocol::DeRecEvent).

pub(super) mod discovery;
pub(super) mod pairing;
pub(super) mod recovery;
pub(super) mod replicas;
pub(super) mod restore;
pub(super) mod sharing;
pub(super) mod unpairing;
pub(super) mod update_channel_info;
pub(super) mod verification;

use super::DeRecEvent;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::message_body::MessageBodyExt as _;
use crate::{
    Error, Result,
    protocol::{
        context::{Exchange, Local, PairingConfig},
        stores::{StoreSet, Stores},
    },
    types::{ChannelId, SharedKey},
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{DeRecMessage, MessageBody};

/// Route a decrypted channel message to the module that owns its flow.
///
/// Does only the part that is identical for every message: the peer-supplied
/// endpoint policy check, the role gate for bodies that name exactly one
/// permitted sender (see [`MessageBodyExt::expected_sender_role`](crate::extensions::message_body::MessageBodyExt::expected_sender_role)),
/// the hand-off, and
/// the courtesy failure response. Which relationship a multi-valued body
/// concerns, and what to run for it, is the owning flow's decision.
///
/// Both gates run before dispatch and their failures are collected rather
/// than returned, so a refusal reaches the auto-respond path below on the
/// same footing as a failure from the flow itself.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = message.trace_id, channel_id = channel_id.0))
)]
pub(super) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    message: &DeRecMessage,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    auto_respond_on_failure: bool,
) -> Result<Vec<DeRecEvent>> {
    let inner_message = crate::derec_message::extract_inner_message(&message.message, shared_key)?;

    let inbound_trace_id = message.trace_id;
    let exchange = &Exchange {
        channel_id,
        shared_key,
        trace_id: inbound_trace_id,
    };

    // Captured before dispatch because dispatch consumes the body, and only
    // when the setting is on so the clone costs nothing by default.
    let responder = auto_respond_on_failure
        .then(|| FailureResponder::capture(&inner_message))
        .flatten();

    // Both gates below reject an authenticated message, so both are failures
    // a peer can be told about. They are collected rather than `?`-ed so the
    // auto-respond path at the bottom sees them alongside dispatch failures.
    let mut refused: Option<Error> = None;

    for endpoint in inner_message.peer_supplied_endpoints() {
        if let Err(e) = local.policy.check_peer(endpoint) {
            refused = Some(e.into());
            break;
        }
    }

    if refused.is_none()
        && let Some(expected) = inner_message.expected_sender_role()
        && let Err(e) = stores
            .channels
            .require_role(local.secret_id, &[channel_id], expected)
            .await
    {
        refused = Some(e);
    }

    let outcome = match refused {
        Some(error) => Err(error),
        None => match &inner_message {
            MessageBody::StoreShareRequest(_) | MessageBody::StoreShareResponse(_) => {
                sharing::handle(stores, local, exchange, inner_message).await
            }
            MessageBody::VerifyShareRequest(_) | MessageBody::VerifyShareResponse(_) => {
                verification::handle(stores, local, exchange, inner_message).await
            }
            MessageBody::GetSecretIdsVersionsRequest(_)
            | MessageBody::GetSecretIdsVersionsResponse(_) => {
                discovery::handle(stores, local, exchange, inner_message).await
            }
            MessageBody::GetShareRequest(_) | MessageBody::GetShareResponse(_) => {
                recovery::handle(stores, local, exchange, inner_message).await
            }
            MessageBody::UnpairRequest(_) | MessageBody::UnpairResponse(_) => {
                unpairing::handle(stores, local, exchange, inner_message).await
            }
            MessageBody::UpdateChannelInfoRequest(_)
            | MessageBody::UpdateChannelInfoResponse(_) => {
                update_channel_info::handle(stores, local, exchange, inner_message).await
            }
            _ => Err(Error::Invariant(
                "unexpected MessageBody variant in channel message",
            )),
        },
    };

    if let (Err(error), Some(responder)) = (&outcome, responder) {
        auto_respond(stores, local, exchange, responder, error).await;
    }

    outcome
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = message.trace_id, channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn handle_pairing<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    pairing: &PairingConfig<'_>,
    message: &DeRecMessage,
    channel_id: ChannelId,
    pairing_secret: &PairingSecretKeyMaterial,
) -> Result<Vec<DeRecEvent>> {
    let inner =
        crate::derec_message::extract_inner_pairing_message(&message.message, pairing_secret)?;

    // Same single gate as the channel path: the endpoint a peer offers at
    // pairing is the one every later message to it is addressed to.
    for endpoint in inner.peer_supplied_endpoints() {
        local.policy.check_peer(endpoint)?;
    }

    pairing::handle(
        stores,
        local,
        pairing,
        &inner,
        channel_id,
        pairing_secret,
        message.trace_id,
    )
    .await
}

/// The inbound request a failure response would answer, captured before
/// dispatch because the dispatch consumes the `MessageBody`.
///
/// Only request bodies appear: nothing is owed to a peer that was itself
/// answering us, and the pairing flows carry their own accept/reject surface.
// Compatibility, not oversight — see the `transport` module docs.
#[allow(deprecated)]
enum FailureResponder {
    StoreShare(Box<derec_proto::StoreShareRequestMessage>),
    VerifyShare(Box<derec_proto::VerifyShareRequestMessage>),
    Discovery(Box<derec_proto::GetSecretIdsVersionsRequestMessage>),
    GetShare(Box<derec_proto::GetShareRequestMessage>),
    Unpair(Box<derec_proto::UnpairRequestMessage>),
    UpdateChannelInfo,
}

impl FailureResponder {
    fn capture(inner: &MessageBody) -> Option<Self> {
        match inner {
            MessageBody::StoreShareRequest(r) => Some(Self::StoreShare(Box::new(r.clone()))),
            MessageBody::VerifyShareRequest(r) => Some(Self::VerifyShare(Box::new(r.clone()))),
            MessageBody::GetSecretIdsVersionsRequest(r) => {
                Some(Self::Discovery(Box::new(r.clone())))
            }
            MessageBody::GetShareRequest(r) => Some(Self::GetShare(Box::new(r.clone()))),
            MessageBody::UnpairRequest(r) => Some(Self::Unpair(Box::new(r.clone()))),
            MessageBody::UpdateChannelInfoRequest(_) => Some(Self::UpdateChannelInfo),
            _ => None,
        }
    }
}

/// Tell the peer its request failed, when the application has opted into
/// [`with_auto_respond_on_failure`](crate::protocol::DeRecProtocolBuilder::with_auto_respond_on_failure).
///
/// # Why this is only reachable here
///
/// It runs after `extract_inner_message` succeeded, so the request was
/// decrypted under the channel key and is therefore *authenticated*. That is
/// the precondition for replying at all: a message that failed to decrypt
/// carries no proof it came from the peer it names, and answering it would
/// make this device an oracle for anyone able to send bytes at it. Those
/// failures surface to the application as `ProcessError` and nothing goes
/// back on the wire.
///
/// # Best effort
///
/// The reply is a courtesy on top of an already-failed exchange, so a failure
/// to send it is logged and swallowed rather than replacing the error the
/// caller actually needs to see.
async fn auto_respond<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    responder: FailureResponder,
    error: &Error,
) {
    let status = derec_proto::StatusEnum::from(error);
    let memo = error.to_string();

    let sent = match &responder {
        FailureResponder::StoreShare(r) => {
            sharing::reject(stores, local, exchange, r, status, &memo).await
        }
        FailureResponder::VerifyShare(r) => {
            verification::reject(stores, local, exchange, r, status, &memo).await
        }
        FailureResponder::Discovery(r) => {
            discovery::reject(stores, local, exchange, r, status, &memo).await
        }
        FailureResponder::GetShare(r) => {
            recovery::reject(stores, local, exchange, r, status, &memo).await
        }
        FailureResponder::Unpair(r) => {
            unpairing::reject(stores, local, exchange, r, status, &memo).await
        }
        FailureResponder::UpdateChannelInfo => {
            update_channel_info::reject(stores, local, exchange, status, &memo).await
        }
    };

    if let Err(_send_error) = sent {
        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = exchange.channel_id.0,
            error = %_send_error,
            "auto_respond_on_failure could not deliver the failure response; \
             the original error is still returned to the caller",
        );
    }
}

/// T4 of the replica-group spec: `replica_id` presence discriminates the two
/// paths, and a mismatch is a protocol error rather than a silent misroute.
#[cfg(test)]
mod replica_id_discrimination_tests {
    use super::*;
    use crate::protocol::DeRecChannelStore as _;
    use crate::protocol::test::{StoreRig, run_async};
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel};
    use crate::types::ChannelId;

    const SECRET_ID: u64 = 0xD15C;

    /// A store-share naming a member the group does not contain is refused.
    /// This is the receive-side check that stops a helper-bound message
    /// carrying a `replica_id` from being resolved against a helper channel:
    /// the replica query finds nothing, because helper channels and members
    /// live in different key spaces.
    #[test]
    fn a_store_share_naming_an_unknown_member_is_refused() {
        run_async(async {
            let mut rig = StoreRig::new();
            rig.channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id: ChannelId(9001),
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "https://helper.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
                        communication_info: std::collections::HashMap::new(),
                        peer_role: derec_proto::SenderKind::Helper,
                        status: ChannelStatus::Paired,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed helper channel");

            let err = rig
                .channels
                .load_replica_member(SECRET_ID, ChannelId(9001), 1002)
                .await
                .expect_err("a helper channel holds no member, so this must not resolve");
            assert!(
                matches!(err, Error::InvalidInput(_)),
                "expected an InvalidInput protocol error, got {err:?}"
            );
        });
    }

    /// `0` is the wire's absent-value sentinel, so it can never name a member
    /// — a payload carrying it is malformed, not a lookup miss.
    #[test]
    fn replica_id_zero_never_names_a_member() {
        run_async(async {
            let rig = StoreRig::new();
            let err = rig
                .channels
                .load_replica_member(SECRET_ID, ChannelId(9001), 0)
                .await
                .expect_err("zero is the absent sentinel and must be rejected");
            assert!(
                matches!(err, Error::InvalidInput(_)),
                "expected an InvalidInput protocol error, got {err:?}"
            );
        });
    }
}
