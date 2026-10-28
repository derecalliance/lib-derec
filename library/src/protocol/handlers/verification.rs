// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport, IgnoreReason,
    MissingPolicy, PendingAction, SecretKind, SecretValue, ShareStoreError, StateItem, StateKey,
    VerifyFailureReason,
};
use super::NO_SHARE_FOR_VERSION;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::derec_result::DeRecResultExt as _;
use crate::extensions::verify_share_response::VerifyShareResponseExt as _;
use crate::protocol::context::{Exchange, Local, Round};
use crate::protocol::obligation::{deliver, refused, reported};
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
/// `PendingVerification` row for the channel is read, so a replay of a
/// consumed challenge — or a response with no owner-side request behind
/// it — is dropped as a `NoOp`.
///
/// The response must name the recorded request's `(nonce, secret_id,
/// version)`. One that does not answers an earlier challenge a newer one
/// replaced: it is dropped as [`IgnoreReason::StaleResponse`] and the row is
/// kept, so the current challenge's own answer still completes it.
///
/// A bound response consumes the row and ends in exactly one verdict:
///
/// - a non-OK status is the helper refusing the challenge:
///   `ShareVerifyRejected` carrying its status and memo, whether or not this
///   device still holds a proof;
/// - with no proof stored for the channel at that version:
///   `VerifySharesFailed` with [`VerifyFailureReason::NoProof`];
/// - otherwise the SHA-384 proof decides: `ShareVerified` or
///   `ShareVerifyInvalid`.
///
/// A wrong or missing proof is never an error. A response with no `result`
/// is malformed: it is returned as an error and the row is kept, so a
/// well-formed answer to the same challenge still completes it.
///
/// The `load` + `remove` pair is two round-trips and not atomic across
/// instances (see the multi-instance concurrency contract on
/// [`crate::protocol::DeRecStateStore`]); duplicate verdict events from two
/// racing instances are idempotent for the application.
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
            on_response(stores, local.secret_id, exchange, &response).await
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
/// newer nonce wins, and a response to the replaced challenge is ignored.
///
/// A channel is challenged only while this device holds a proof of its share
/// at `version`; without one there is nothing to check an answer against, so
/// the channel gets `VerifySharesFailed` with
/// [`VerifyFailureReason::NoProof`] and no challenge is sent. The publishing
/// device holds no proof for a version the channel's Helper failed to store,
/// nor for one it removed under a later round's `keepVersion` once it confirmed
/// that round. A missing
/// shared key or a dispatch failure is reported the same way, with its own
/// reason. Each failure is isolated to its channel rather than
/// short-circuiting the fan-out.
///
/// # Answering a member of a replica group
///
/// A Helper holds exactly one endpoint per channel: the device that paired
/// with it. Every other member of the group is invisible to it, so a
/// challenge from a group carries this device's own endpoint or the answer is
/// routed to whoever paired — which for a Destination verifying a mirrored
/// vault is the Source, leaving the challenger waiting on a reply another
/// device silently drops. Decided here rather than left to the application's
/// `auto_reply_to` setting, on the same terms as the helper leg of
/// [`sharing::start`](super::sharing::start).
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
    let channel_ids = stores.channels.resolve_target(secret_id, target).await?;

    let keys = stores
        .secrets
        .load_many(
            secret_id,
            &channel_ids,
            SecretKind::SharedKey,
            MissingPolicy::Fail,
        )
        .await?;

    let roster = stores
        .channels
        .replicas_matching(secret_id, crate::protocol::types::ReplicaFilter::default())
        .await?;
    let reply_to: Vec<derec_proto::TransportProtocol> = if roster.is_empty() {
        round.reply_to.to_vec()
    } else {
        vec![local.primary().clone()]
    };

    let events = dispatch_all(stores, secret_id, version, keys, &reply_to, round).await;

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id = secret_id,
        version = version,
        "verification challenges sent"
    );

    Ok(events)
}

/// Answer a verification challenge with the proof for the stored share.
///
/// A helper holding no share for the challenged version still answers: the
/// response carries `UNKNOWN_SHARE_VERSION` and no proof, which the owner
/// surfaces as [`DeRecEvent::ShareVerifyRejected`] rather than waiting on a
/// reply that never comes. That is an answer rather than a failure of this
/// device, so `accept` succeeds either way, whether the application accepted
/// the action or the [`AutoAcceptPolicy`](crate::protocol::AutoAcceptPolicy)
/// did.
///
/// Once a stored share is found, the application's
/// [`DeRecShareStore::record_verification`] hook is called before the
/// response is produced. A [`ShareStoreError::Refused`] from it is answered
/// to the owner with the refusal's mapped status instead of the proof, the
/// same way a `save` refusal is answered on the sharing path; any other
/// error propagates to the caller unchanged.
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

    let Some(stored_bytes) = stores
        .shares
        .load(secret_id, channel_id, &[request.version])
        .await?
        .into_iter()
        .next()
        .map(|s| s.bytes)
    else {
        #[cfg(feature = "logging")]
        tracing::info!(
            channel_id = channel_id.0,
            secret_id = request.secret_id,
            version = request.version,
            "no stored share for the challenged version; answering UNKNOWN_SHARE_VERSION"
        );
        let sent = reject(
            stores,
            local,
            exchange,
            request,
            StatusEnum::UnknownShareVersion,
            NO_SHARE_FOR_VERSION,
        )
        .await;
        return refused(
            exchange.obligation,
            DeRecEvent::NoOp,
            StatusEnum::UnknownShareVersion,
            NO_SHARE_FOR_VERSION,
            sent,
        );
    };

    let stored =
        StoreShareRequestMessage::decode(stored_bytes.as_slice()).map_err(Error::ProtobufDecode)?;

    match stores
        .shares
        .record_verification(secret_id, channel_id, request.version)
        .await
    {
        Ok(()) => {}
        Err(ShareStoreError::Refused(refusal)) => {
            let sent = reject(
                stores,
                local,
                exchange,
                request,
                refusal.status(),
                refusal.memo(),
            )
            .await;

            #[cfg(feature = "logging")]
            tracing::info!(
                channel_id = channel_id.0,
                secret_id = request.secret_id,
                version = request.version,
                "verification refused by the application's share store"
            );

            return refused(
                exchange.obligation,
                DeRecEvent::NoOp,
                refusal.status(),
                refusal.memo(),
                sent,
            );
        }
        Err(other) => return Err(other.into()),
    }

    let resp =
        verification_response::produce(channel_id, request, exchange.shared_key, &stored.share)?;

    let envelope = crate::derec_message::apply_trace_id(&resp.envelope, exchange.trace_id)?;
    let endpoint = stores
        .channels
        .resolve_response_endpoints(
            secret_id,
            channel_id,
            local.policy,
            &crate::extensions::advertised_endpoints::reply_to_owned(request),
        )
        .await?;
    let sent = deliver(
        exchange.obligation,
        stores.transport,
        &endpoint,
        envelope,
        StatusEnum::Ok,
        "",
    )
    .await;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        secret_id = request.secret_id,
        version = request.version,
        "verification response sent"
    );

    reported(exchange.obligation, vec![DeRecEvent::NoOp], sent)
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
    crate::extensions::channel_store::send_channel_message(
        stores.channels,
        stores.transport,
        secret_id,
        channel_id,
        failure_response(request, status, memo),
        exchange.shared_key,
        exchange.trace_id,
        local.policy,
        &crate::extensions::advertised_endpoints::reply_to_owned(request),
        exchange.obligation,
        status,
        memo,
    )
    .await
}

/// The `VerifyShareResponse` that answers `request` with a non-`Ok` `status`
/// and no proof.
pub(in crate::protocol) fn failure_response(
    request: &VerifyShareRequestMessage,
    status: StatusEnum,
    memo: &str,
) -> MessageBody {
    MessageBody::VerifyShareResponse(VerifyShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        secret_id: request.secret_id,
        version: request.version,
        nonce: request.nonce,
        hash: Vec::new(),
        timestamp: Some(current_timestamp()),
    })
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
            channel_id = exchange.channel_id.0,
            secret_id = response.secret_id,
            version = response.version
        )
    )
)]
async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    secret_id: u64,
    exchange: &Exchange<'_>,
    response: &VerifyShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let channel_id = exchange.channel_id;
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

    if response.validate_binding(&request).is_err() {
        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = channel_id.0,
            "verification response does not answer the outstanding challenge; ignoring"
        );
        return Ok(vec![DeRecEvent::MessageIgnored {
            channel_id,
            reason: IgnoreReason::StaleResponse,
            trace_id: exchange.trace_id,
        }]);
    }

    let Some(result) = response.result.as_ref() else {
        return Err(Error::Invariant(
            "VerifyShareResponseMessage is missing result field",
        ));
    };

    let _ = stores.state.remove(secret_id, key).await?;

    let version = response.version;

    if let Err((status, memo)) = result.validate(|status, memo| (status, memo)) {
        return Ok(vec![DeRecEvent::ShareVerifyRejected {
            channel_id,
            version,
            status,
            memo,
        }]);
    }

    let Some((committed_share_bytes, subshares, threshold)) = stores
        .shares
        .load(secret_id, channel_id, &[version])
        .await?
        .into_iter()
        .next()
        .map(|s| (s.bytes, s.subshares, s.threshold))
    else {
        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = channel_id.0,
            secret_id = response.secret_id,
            version = version,
            "no proof stored for the answered challenge"
        );
        return Ok(vec![DeRecEvent::VerifySharesFailed {
            channel_id,
            version,
            reason: VerifyFailureReason::NoProof,
            error: "proof removed before the response arrived".to_owned(),
        }]);
    };

    let valid = verification_response::process(&request, response, &committed_share_bytes)?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        secret_id = response.secret_id,
        version = version,
        verified = valid,
        "verification proof checked"
    );

    Ok(vec![if valid {
        DeRecEvent::ShareVerified {
            channel_id,
            version,
            subshares,
            threshold,
        }
    } else {
        DeRecEvent::ShareVerifyInvalid {
            channel_id,
            version,
        }
    }])
}

/// Send a challenge to every resolved channel, reporting each outcome.
///
/// One event per target, in the order the targets were resolved. A failure is
/// isolated to its own target: it becomes a `VerifySharesFailed` carrying
/// its [`VerifyFailureReason`], and the fan-out continues.
async fn dispatch_all<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    secret_id: u64,
    version: u32,
    keys: Vec<(ChannelId, SecretValue)>,
    reply_to: &[derec_proto::TransportProtocol],
    round: &Round<'_>,
) -> Vec<DeRecEvent> {
    let mut events = Vec::with_capacity(keys.len());
    for (channel_id, value) in keys {
        let SecretValue::SharedKey(shared_key) = value else {
            events.push(DeRecEvent::VerifySharesFailed {
                channel_id,
                version,
                reason: VerifyFailureReason::NoSharedKey,
                error: "channel has no shared key".to_owned(),
            });
            continue;
        };

        match has_proof(stores, secret_id, channel_id, version).await {
            Ok(true) => {}
            Ok(false) => {
                events.push(DeRecEvent::VerifySharesFailed {
                    channel_id,
                    version,
                    reason: VerifyFailureReason::NoProof,
                    error: "no proof stored for this channel at this version".to_owned(),
                });
                continue;
            }
            Err(e) => {
                events.push(DeRecEvent::VerifySharesFailed {
                    channel_id,
                    version,
                    reason: VerifyFailureReason::DispatchFailed,
                    error: e.to_string(),
                });
                continue;
            }
        }

        match dispatch_one(
            stores,
            secret_id,
            version,
            channel_id,
            &shared_key,
            reply_to,
            round,
        )
        .await
        {
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
                    reason: VerifyFailureReason::DispatchFailed,
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

async fn has_proof<S: StoreSet>(
    stores: &Stores<'_, S>,
    secret_id: u64,
    channel_id: ChannelId,
    version: u32,
) -> Result<bool> {
    Ok(!stores
        .shares
        .load(secret_id, channel_id, &[version])
        .await?
        .is_empty())
}

async fn dispatch_one<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    secret_id: u64,
    version: u32,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    reply_to: &[derec_proto::TransportProtocol],
    round: &Round<'_>,
) -> Result<()> {
    let endpoint = stores
        .channels
        .peer_endpoints(secret_id, channel_id)
        .await?;
    let msg =
        produce_verify_share_request_message(channel_id, secret_id, version, shared_key, reply_to)?;

    let reply_to_transports = reply_to.to_vec();

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
                    reply_to_transports,
                },
            },
        )
        .await?;

    let envelope = crate::derec_message::apply_trace_id(&msg.envelope, round.trace_id)?;
    stores.transport.send(&endpoint, envelope).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tests::{StoreRig, run_async};
    use crate::protocol::types::Share;

    const SECRET_ID: u64 = 0x5E1F;
    const CHANNEL: ChannelId = ChannelId(21);
    const VERSION: u32 = 3;

    /// A helper refusing a challenge is reported with its status and memo,
    /// as a refused share is, rather than failing `process` with no event.
    #[test]
    fn a_refused_challenge_surfaces_as_share_verify_rejected() {
        run_async(async {
            let mut rig = StoreRig::new();
            let request = VerifyShareRequestMessage {
                secret_id: SECRET_ID,
                version: VERSION,
                nonce: 0x0BAD_5EED,
                timestamp: None,
                reply_to_transports: Vec::new(),
            };
            rig.state
                .save(
                    SECRET_ID,
                    StateItem::PendingVerification {
                        channel_id: CHANNEL,
                        request: request.clone(),
                    },
                )
                .await
                .expect("seed challenge");
            rig.shares
                .save(
                    SECRET_ID,
                    CHANNEL,
                    Share {
                        secret_id: SECRET_ID,
                        version: VERSION,
                        bytes: vec![0x5A; 16],
                        subshares: None,
                        threshold: None,
                    },
                )
                .await
                .expect("seed committed share");

            let response = VerifyShareResponseMessage {
                result: Some(DeRecResult {
                    status: StatusEnum::UnknownShareVersion as i32,
                    memo: "no stored share for verification request".to_owned(),
                }),
                secret_id: SECRET_ID,
                version: VERSION,
                nonce: request.nonce,
                hash: Vec::new(),
                timestamp: Some(current_timestamp()),
            };
            let local = crate::protocol::tests::LocalFixture::new(SECRET_ID);
            let events = handle(
                &mut rig.stores(),
                &local.local(),
                &Exchange {
                    channel_id: CHANNEL,
                    shared_key: &[0u8; 32],
                    trace_id: 0,
                    obligation: None,
                },
                MessageBody::VerifyShareResponse(response),
            )
            .await
            .expect("a refusal is an outcome, not an error");

            assert!(
                matches!(
                    events.as_slice(),
                    [DeRecEvent::ShareVerifyRejected { channel_id, version, status, memo }]
                        if *channel_id == CHANNEL
                            && *version == VERSION
                            && *status == StatusEnum::UnknownShareVersion as i32
                            && memo == "no stored share for verification request"
                ),
                "got {events:?}"
            );
            assert!(
                rig.state
                    .load(
                        SECRET_ID,
                        StateKey::PendingVerification {
                            channel_id: CHANNEL
                        }
                    )
                    .await
                    .expect("load")
                    .is_none(),
                "the refused challenge is consumed"
            );
        });
    }

    /// A helper challenged for a version it does not hold answers
    /// `UNKNOWN_SHARE_VERSION` instead of leaving the challenge unanswered,
    /// and the owner reads that answer as [`DeRecEvent::ShareVerifyRejected`].
    mod helper_without_the_share {
        use super::*;
        use crate::protocol::tests::{
            InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
            InMemUserSecretStore, RecordingTransport,
        };
        use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel};
        use crate::protocol::{AutoAcceptPolicy, DeRecChannelStore, DeRecProtocolBuilder};
        use derec_proto::{DeRecMessage, SenderKind, TransportProtocol};

        type TestProto = crate::protocol::DeRecProtocol<
            InMemChannelStore,
            InMemShareStore,
            InMemSecretStore,
            InMemUserSecretStore,
            InMemPersistedStateStore,
            RecordingTransport,
        >;

        const HELPER_PARTITION: u64 = 0x4E1;
        const KEY: SharedKey = [0xC3; 32];

        async fn helper(auto_accept: AutoAcceptPolicy) -> (TestProto, RecordingTransport) {
            let mut rig = StoreRig::new();
            rig.channels
                .save(
                    HELPER_PARTITION,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id: CHANNEL,
                        transports: vec![TransportProtocol {
                            uri: "https://owner.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
                        communication_info: Default::default(),
                        status: ChannelStatus::Paired,
                        created_at: 1,
                        peer_role: SenderKind::Owner,
                        weight: 1,
                    }),
                )
                .await
                .expect("channel saved");
            rig.secrets
                .save(HELPER_PARTITION, CHANNEL, SecretValue::SharedKey(KEY))
                .await
                .expect("shared key saved");
            let protocol = DeRecProtocolBuilder::new(HELPER_PARTITION)
                .with_channel_store(rig.channels)
                .with_share_store(InMemShareStore::default())
                .with_secret_store(rig.secrets)
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_state_store(rig.state)
                .with_transport(rig.transport.clone())
                .with_own_transports(["https://helper.example"])
                .with_auto_accept(auto_accept)
                .build()
                .expect("test rig builds");
            (protocol, rig.transport)
        }

        fn sent_response(transport: &RecordingTransport) -> VerifyShareResponseMessage {
            let envelopes = transport.sent_envelopes();
            assert_eq!(envelopes.len(), 1, "exactly one answer must be sent");
            let msg = DeRecMessage::decode(envelopes[0].as_slice()).expect("envelope decodes");
            match crate::derec_message::extract_inner_message(&msg.message, &KEY)
                .expect("inner message decrypts")
            {
                MessageBody::VerifyShareResponse(r) => r,
                other => panic!("expected VerifyShareResponse, got {other:?}"),
            }
        }

        /// Feed the helper's answer to an owner holding the challenge it
        /// answers, and return what the owner reports.
        async fn owner_reads(nonce: u64, response: VerifyShareResponseMessage) -> Vec<DeRecEvent> {
            let mut rig = StoreRig::new();
            rig.state
                .save(
                    SECRET_ID,
                    StateItem::PendingVerification {
                        channel_id: CHANNEL,
                        request: VerifyShareRequestMessage {
                            secret_id: SECRET_ID,
                            version: VERSION,
                            nonce,
                            timestamp: None,
                            reply_to_transports: Vec::new(),
                        },
                    },
                )
                .await
                .expect("seed challenge");
            rig.shares
                .save(
                    SECRET_ID,
                    CHANNEL,
                    Share {
                        secret_id: SECRET_ID,
                        version: VERSION,
                        bytes: vec![0x5A; 16],
                        subshares: None,
                        threshold: None,
                    },
                )
                .await
                .expect("seed committed share");
            let local = crate::protocol::tests::LocalFixture::new(SECRET_ID);
            handle(
                &mut rig.stores(),
                &local.local(),
                &Exchange {
                    channel_id: CHANNEL,
                    shared_key: &KEY,
                    trace_id: 0,
                    obligation: None,
                },
                MessageBody::VerifyShareResponse(response),
            )
            .await
            .expect("a refusal is an outcome, not an error")
        }

        fn assert_owner_sees_rejection(events: &[DeRecEvent]) {
            assert!(
                matches!(
                    events,
                    [DeRecEvent::ShareVerifyRejected { channel_id, version, status, .. }]
                        if *channel_id == CHANNEL
                            && *version == VERSION
                            && *status == StatusEnum::UnknownShareVersion as i32
                ),
                "got {events:?}"
            );
        }

        fn challenge() -> (Vec<u8>, u64) {
            let produced =
                produce_verify_share_request_message(CHANNEL, SECRET_ID, VERSION, &KEY, &[])
                    .expect("challenge produced");
            (produced.envelope, produced.nonce)
        }

        #[test]
        fn auto_accept_answers_unknown_share_version_end_to_end() {
            run_async(async {
                let (mut protocol, transport) = helper(AutoAcceptPolicy {
                    verify_share: true,
                    ..Default::default()
                })
                .await;
                let (envelope, nonce) = challenge();

                let events = protocol
                    .process(&envelope)
                    .await
                    .expect("a challenge for a share not held is answered, not failed");
                assert!(
                    events
                        .iter()
                        .any(|e| matches!(e, DeRecEvent::AutoAccepted { .. })),
                    "got {events:?}"
                );

                let response = sent_response(&transport);
                assert_eq!(
                    response.result.as_ref().map(|r| r.status),
                    Some(StatusEnum::UnknownShareVersion as i32)
                );
                assert_eq!(response.nonce, nonce);
                assert!(response.hash.is_empty());

                assert_owner_sees_rejection(&owner_reads(nonce, response).await);
            });
        }

        #[test]
        fn manual_accept_answers_unknown_share_version_end_to_end() {
            run_async(async {
                let (mut protocol, transport) = helper(AutoAcceptPolicy::default()).await;
                let (envelope, nonce) = challenge();

                let action = protocol
                    .process(&envelope)
                    .await
                    .expect("the challenge surfaces for a decision")
                    .into_iter()
                    .find_map(|e| match e {
                        DeRecEvent::ActionRequired { action, .. } => Some(action),
                        _ => None,
                    })
                    .expect("ActionRequired for the VerifyShare request");

                let accepted = protocol
                    .accept(action)
                    .await
                    .expect("accepting a challenge for a share not held succeeds");
                assert!(
                    matches!(accepted.as_slice(), [DeRecEvent::NoOp]),
                    "got {accepted:?}"
                );

                let response = sent_response(&transport);
                assert_eq!(
                    response.result.as_ref().map(|r| r.status),
                    Some(StatusEnum::UnknownShareVersion as i32)
                );
                assert_owner_sees_rejection(&owner_reads(nonce, response).await);
            });
        }
    }

    /// The helper's verification `accept` calls the app's
    /// [`crate::protocol::DeRecShareStore::record_verification`] hook after
    /// the challenged share is found and before answering, and turns a
    /// refusal from it into the matching status response rather than an
    /// error.
    mod record_verification_tests {
        use super::*;
        use crate::protocol::Refusal;
        use crate::protocol::tests::{
            InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemUserSecretStore,
            LocalFixture, RecordingTransport, RefusingShareStore, StoreRig,
        };
        use derec_proto::{DeRecMessage, Protocol, TransportProtocol};

        const REC_SECRET_ID: u64 = 0xBEE5;
        const REC_CHANNEL: ChannelId = ChannelId(41);
        const REC_KEY: SharedKey = [7u8; 32];

        type RecRig = StoreRig<
            InMemChannelStore,
            RefusingShareStore,
            InMemSecretStore,
            InMemUserSecretStore,
            InMemPersistedStateStore,
            RecordingTransport,
        >;

        fn rec_rig() -> RecRig {
            StoreRig {
                channels: InMemChannelStore::default(),
                shares: RefusingShareStore::default(),
                secrets: InMemSecretStore::default(),
                user_secrets: InMemUserSecretStore::default(),
                state: InMemPersistedStateStore::default(),
                transport: RecordingTransport::default(),
            }
        }

        fn rec_reply_to() -> TransportProtocol {
            TransportProtocol {
                uri: "https://owner.example".to_owned(),
                protocol: Protocol::Https as i32,
            }
        }

        /// A challenge carrying an explicit `reply_to`, so these tests need
        /// no seeded channel record to resolve a response endpoint.
        fn rec_request(version: u32, nonce: u64) -> VerifyShareRequestMessage {
            VerifyShareRequestMessage {
                secret_id: REC_SECRET_ID,
                version,
                nonce,
                timestamp: None,
                reply_to_transports: vec![rec_reply_to()],
            }
        }

        /// Store a `StoreShareRequestMessage`-encoded share for `version`,
        /// matching what the sharing handler persists on a Helper — the
        /// format [`accept`] decodes the stored bytes as.
        async fn seed_stored_share(rig: &mut RecRig, version: u32) {
            let stored = StoreShareRequestMessage {
                share: b"a plausible committed share payload".to_vec(),
                share_algorithm: 0,
                version,
                keep_version: 0,
                version_description: String::new(),
                timestamp: None,
                secret_id: REC_SECRET_ID,
                reply_to_transports: Vec::new(),
                replica_id: None,
            };
            rig.shares
                .save(
                    REC_SECRET_ID,
                    REC_CHANNEL,
                    Share {
                        secret_id: REC_SECRET_ID,
                        version,
                        bytes: stored.encode_to_vec(),
                        subshares: None,
                        threshold: None,
                    },
                )
                .await
                .expect("seed stored share");
        }

        fn decode_verify_share_response(
            envelope_bytes: &[u8],
            shared_key: &SharedKey,
        ) -> VerifyShareResponseMessage {
            let envelope = DeRecMessage::decode(envelope_bytes).expect("decode response envelope");
            match crate::derec_message::extract_inner_message(&envelope.message, shared_key)
                .expect("decrypt response")
            {
                MessageBody::VerifyShareResponse(r) => r,
                other => panic!("expected a VerifyShareResponse, got {other:?}"),
            }
        }

        /// Feed the helper's answer to an owner holding the matching
        /// challenge, and return what the owner reports.
        async fn owner_reads(
            request: &VerifyShareRequestMessage,
            response: VerifyShareResponseMessage,
        ) -> Vec<DeRecEvent> {
            let mut rig = StoreRig::new();
            rig.state
                .save(
                    REC_SECRET_ID,
                    StateItem::PendingVerification {
                        channel_id: REC_CHANNEL,
                        request: request.clone(),
                    },
                )
                .await
                .expect("seed challenge");
            rig.shares
                .save(
                    REC_SECRET_ID,
                    REC_CHANNEL,
                    Share {
                        secret_id: REC_SECRET_ID,
                        version: request.version,
                        bytes: vec![0x5A; 16],
                        subshares: None,
                        threshold: None,
                    },
                )
                .await
                .expect("seed committed share");
            let local = LocalFixture::new(REC_SECRET_ID);
            handle(
                &mut rig.stores(),
                &local.local(),
                &Exchange {
                    channel_id: REC_CHANNEL,
                    shared_key: &REC_KEY,
                    trace_id: 0,
                    obligation: None,
                },
                MessageBody::VerifyShareResponse(response),
            )
            .await
            .expect("a refusal is an outcome, not an error")
        }

        /// A `record_verification` refusal is answered to the owner with
        /// the mapped status, not raised as a local error.
        #[test]
        fn helper_verification_refusal_answers_the_mapped_status() {
            run_async(async {
                let mut rig = rec_rig();
                seed_stored_share(&mut rig, 1).await;
                rig.shares
                    .set_verification_refusal(Some(Refusal::TooFrequent));
                let request = rec_request(1, 0x0BAD_5EED);
                let local = LocalFixture::new(REC_SECRET_ID);

                let events = accept(
                    &mut rig.stores(),
                    &local.local(),
                    &Exchange {
                        channel_id: REC_CHANNEL,
                        shared_key: &REC_KEY,
                        trace_id: 1,
                        obligation: None,
                    },
                    &request,
                )
                .await
                .expect("a record_verification refusal is answered, not raised as an error");

                assert!(
                    matches!(events.as_slice(), [DeRecEvent::NoOp]),
                    "got {events:?}"
                );

                let sent = rig.transport.sent_envelopes();
                assert_eq!(sent.len(), 1, "exactly one answer is sent to the owner");
                let response = decode_verify_share_response(&sent[0], &REC_KEY);
                assert_eq!(
                    response.result.as_ref().map(|r| r.status),
                    Some(StatusEnum::TooFrequent as i32)
                );

                let owner_events = owner_reads(&request, response).await;
                assert!(
                    matches!(
                        owner_events.as_slice(),
                        [DeRecEvent::ShareVerifyRejected { status, .. }]
                            if *status == StatusEnum::TooFrequent as i32
                    ),
                    "got {owner_events:?}"
                );
            });
        }

        /// Each accepted challenge calls `record_verification` once, with
        /// the challenged `(secret_id, channel_id, version)`.
        #[test]
        fn helper_verification_records_each_accepted_challenge() {
            run_async(async {
                let mut rig = rec_rig();
                seed_stored_share(&mut rig, 1).await;
                seed_stored_share(&mut rig, 2).await;
                let local = LocalFixture::new(REC_SECRET_ID);

                for version in [1u32, 2u32] {
                    accept(
                        &mut rig.stores(),
                        &local.local(),
                        &Exchange {
                            channel_id: REC_CHANNEL,
                            shared_key: &REC_KEY,
                            trace_id: 1,
                            obligation: None,
                        },
                        &rec_request(version, u64::from(version)),
                    )
                    .await
                    .expect("an accepted challenge is answered");
                }

                assert_eq!(
                    rig.shares.verification_calls(),
                    vec![
                        (REC_SECRET_ID, REC_CHANNEL, 1),
                        (REC_SECRET_ID, REC_CHANNEL, 2),
                    ],
                    "record_verification is called once per accepted challenge, in order"
                );
            });
        }

        /// A challenge for a version the Helper does not hold answers
        /// `UNKNOWN_SHARE_VERSION` and never reaches `record_verification`.
        #[test]
        fn unknown_version_does_not_record_a_verification() {
            run_async(async {
                let mut rig = rec_rig();
                let local = LocalFixture::new(REC_SECRET_ID);

                let events = accept(
                    &mut rig.stores(),
                    &local.local(),
                    &Exchange {
                        channel_id: REC_CHANNEL,
                        shared_key: &REC_KEY,
                        trace_id: 1,
                        obligation: None,
                    },
                    &rec_request(1, 0x0BAD_5EED),
                )
                .await
                .expect("an unknown version is answered, not raised as an error");

                assert!(matches!(events.as_slice(), [DeRecEvent::NoOp]));
                let sent = rig.transport.sent_envelopes();
                assert_eq!(sent.len(), 1);
                let response = decode_verify_share_response(&sent[0], &REC_KEY);
                assert_eq!(
                    response.result.as_ref().map(|r| r.status),
                    Some(StatusEnum::UnknownShareVersion as i32)
                );
                assert!(
                    rig.shares.verification_calls().is_empty(),
                    "no stored share means record_verification is never reached"
                );
            });
        }

        /// A non-refusal `record_verification` failure is the router's to
        /// answer: `FAIL` with the generic memo when the library responds, a
        /// token when it does not. No proof is sent either way.
        #[test]
        fn helper_verification_backend_error_is_answered_through_the_router() {
            for respond in [true, false] {
                run_async(async move {
                    use crate::protocol::obligation::{GENERIC_FAILURE_MEMO, Obligation, settle};

                    let mut rig = rec_rig();
                    seed_stored_share(&mut rig, 1).await;
                    rig.shares.set_verification_backend_error(true);
                    let local = LocalFixture::new(REC_SECRET_ID);
                    let request = rec_request(1, 0x0BAD_5EED);
                    let action = PendingAction::VerifyShare {
                        channel_id: REC_CHANNEL,
                        request: request.clone(),
                        shared_key: REC_KEY,
                        trace_id: 1,
                    };
                    let obligation =
                        Obligation::for_action(&action, local.local().policy).expect("a request");

                    let outcome = accept(
                        &mut rig.stores(),
                        &local.local(),
                        &Exchange {
                            channel_id: REC_CHANNEL,
                            shared_key: &REC_KEY,
                            trace_id: 1,
                            obligation: Some(&obligation),
                        },
                        &request,
                    )
                    .await;
                    assert!(
                        matches!(
                            outcome,
                            Err(crate::Error::ShareStore(
                                crate::protocol::ShareStoreError::Backend(_)
                            ))
                        ),
                        "the flow itself leaves the failure to the router; got {outcome:?}"
                    );
                    assert!(rig.transport.sent_envelopes().is_empty());

                    // The paired channel's key is in the secret store. The token
                    // carries none: `reject` reads it from there.
                    crate::protocol::DeRecSecretStore::save(
                        &mut rig.secrets,
                        REC_SECRET_ID,
                        REC_CHANNEL,
                        crate::protocol::SecretValue::SharedKey(REC_KEY),
                    )
                    .await
                    .expect("seed the channel key");
                    let events = settle(
                        &mut rig.stores(),
                        &local.local(),
                        &obligation,
                        respond,
                        outcome,
                    )
                    .await;
                    let token = match events.as_slice() {
                        [
                            DeRecEvent::RequestFailed {
                                responded, action, ..
                            },
                        ] => {
                            assert_eq!(*responded, respond);
                            action.clone()
                        }
                        other => panic!("expected one RequestFailed, got {other:?}"),
                    };
                    if let Some(PendingAction::RespondToFailure {
                        channel_id,
                        trace_id,
                        reply,
                        request,
                    }) = token
                    {
                        assert!(rig.transport.sent_envelopes().is_empty());
                        let answer = Obligation::for_failure(
                            channel_id,
                            trace_id,
                            &reply,
                            request,
                            local.local().policy,
                        );
                        crate::protocol::obligation::respond_to_failure(
                            &mut rig.stores(),
                            &local.local(),
                            &answer,
                            StatusEnum::Fail,
                            GENERIC_FAILURE_MEMO,
                        )
                        .await
                        .expect("the token answers the request");
                    }

                    let sent = rig.transport.sent_envelopes();
                    assert_eq!(sent.len(), 1, "exactly one response");
                    let response = decode_verify_share_response(&sent[0], &REC_KEY);
                    assert!(response.hash.is_empty(), "no proof is sent");
                    let result = response.result.expect("a result");
                    assert_eq!(result.status, StatusEnum::Fail as i32);
                    assert_eq!(result.memo, GENERIC_FAILURE_MEMO);
                });
            }
        }
    }

    /// Every challenged channel ends in exactly one verdict event, and a
    /// wrong or missing proof is reported rather than raised as an error.
    mod verdicts {
        use super::*;
        use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel};
        use crate::protocol::{DeRecChannelStore, IgnoreReason, VerifyFailureReason};
        use derec_proto::{ContactMessage, SenderKind, TransportProtocol};

        const OTHER: ChannelId = ChannelId(22);
        const KEY: SharedKey = [0x3C; 32];
        const PROOF: &[u8] = b"the share bytes the owner committed to";

        fn endpoint(uri: &str) -> TransportProtocol {
            TransportProtocol {
                uri: uri.to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            }
        }

        async fn seed_helper(rig: &mut StoreRig, channel_id: ChannelId, uri: &str) {
            rig.channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id,
                        transports: vec![endpoint(uri)],
                        communication_info: Default::default(),
                        status: ChannelStatus::Paired,
                        created_at: 1,
                        peer_role: SenderKind::Helper,
                        weight: 1,
                    }),
                )
                .await
                .expect("channel saved");
            rig.secrets
                .save(SECRET_ID, channel_id, SecretValue::SharedKey(KEY))
                .await
                .expect("shared key saved");
        }

        async fn seed_proof(rig: &mut StoreRig, channel_id: ChannelId) {
            seed_counted_proof(rig, channel_id, None).await;
        }

        async fn seed_counted_proof(
            rig: &mut StoreRig,
            channel_id: ChannelId,
            subshares: Option<u32>,
        ) {
            seed_recorded_proof(rig, channel_id, subshares, None).await;
        }

        async fn seed_recorded_proof(
            rig: &mut StoreRig,
            channel_id: ChannelId,
            subshares: Option<u32>,
            threshold: Option<u32>,
        ) {
            rig.shares
                .save(
                    SECRET_ID,
                    channel_id,
                    Share {
                        secret_id: SECRET_ID,
                        version: VERSION,
                        bytes: PROOF.to_vec(),
                        subshares,
                        threshold,
                    },
                )
                .await
                .expect("proof saved");
        }

        fn request(nonce: u64) -> VerifyShareRequestMessage {
            VerifyShareRequestMessage {
                secret_id: SECRET_ID,
                version: VERSION,
                nonce,
                timestamp: None,
                reply_to_transports: Vec::new(),
            }
        }

        async fn seed_challenge(rig: &mut StoreRig, nonce: u64) {
            rig.state
                .save(
                    SECRET_ID,
                    StateItem::PendingVerification {
                        channel_id: CHANNEL,
                        request: request(nonce),
                    },
                )
                .await
                .expect("challenge saved");
        }

        async fn pending_nonce(rig: &StoreRig) -> Option<u64> {
            match rig
                .state
                .load(
                    SECRET_ID,
                    StateKey::PendingVerification {
                        channel_id: CHANNEL,
                    },
                )
                .await
                .expect("load")
            {
                Some(StateItem::PendingVerification { request, .. }) => Some(request.nonce),
                _ => None,
            }
        }

        /// A helper's OK answer to the challenge with `nonce`, proving
        /// possession of `share`.
        fn answer(nonce: u64, share: &[u8]) -> VerifyShareResponseMessage {
            let produced = verification_response::produce(CHANNEL, &request(nonce), &KEY, share)
                .expect("response produced");
            verification_response::extract(&produced.envelope, &KEY)
                .expect("response extracted")
                .response
        }

        fn refusal(nonce: u64) -> VerifyShareResponseMessage {
            VerifyShareResponseMessage {
                result: Some(DeRecResult {
                    status: StatusEnum::UnknownShareVersion as i32,
                    memo: "no stored share for verification request".to_owned(),
                }),
                secret_id: SECRET_ID,
                version: VERSION,
                nonce,
                hash: Vec::new(),
                timestamp: Some(current_timestamp()),
            }
        }

        async fn owner_reads(
            rig: &mut StoreRig,
            response: VerifyShareResponseMessage,
        ) -> Result<Vec<DeRecEvent>> {
            let local = crate::protocol::tests::LocalFixture::new(SECRET_ID);
            handle(
                &mut rig.stores(),
                &local.local(),
                &Exchange {
                    channel_id: CHANNEL,
                    shared_key: &KEY,
                    trace_id: 77,
                    obligation: None,
                },
                MessageBody::VerifyShareResponse(response),
            )
            .await
        }

        #[test]
        fn hash_mismatch_is_share_verify_invalid() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_proof(&mut rig, CHANNEL).await;
                seed_challenge(&mut rig, 0xA1).await;

                let events = owner_reads(&mut rig, answer(0xA1, b"some other share"))
                    .await
                    .expect("a wrong proof is a verdict, not an error");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ShareVerifyInvalid { channel_id, version }]
                            if *channel_id == CHANNEL && *version == VERSION
                    ),
                    "got {events:?}"
                );
                assert_eq!(pending_nonce(&rig).await, None, "the challenge is spent");
            });
        }

        #[test]
        fn matching_proof_is_share_verified() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_proof(&mut rig, CHANNEL).await;
                seed_challenge(&mut rig, 0xA2).await;

                let events = owner_reads(&mut rig, answer(0xA2, PROOF))
                    .await
                    .expect("verified");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ShareVerified { channel_id, version, subshares: None, threshold: None }]
                            if *channel_id == CHANNEL && *version == VERSION
                    ),
                    "a row written before the count was recorded verifies with none; got {events:?}"
                );
            });
        }

        /// The verdict carries the count recorded on the owner's row for that
        /// version, whatever weight the channel holds now.
        #[test]
        fn share_verified_carries_the_recorded_subshares() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_helper(&mut rig, CHANNEL, "https://weighted.example").await;
                seed_counted_proof(&mut rig, CHANNEL, Some(2)).await;
                seed_challenge(&mut rig, 0xA3).await;

                let events = owner_reads(&mut rig, answer(0xA3, PROOF))
                    .await
                    .expect("verified");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ShareVerified { channel_id, version, subshares: Some(2), threshold: None }]
                            if *channel_id == CHANNEL && *version == VERSION
                    ),
                    "got {events:?}"
                );
            });
        }

        /// The verdict carries the threshold recorded on the owner's row for
        /// that version.
        #[test]
        fn share_verified_carries_the_recorded_threshold() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_helper(&mut rig, CHANNEL, "https://threshold.example").await;
                seed_recorded_proof(&mut rig, CHANNEL, Some(1), Some(3)).await;
                seed_challenge(&mut rig, 0xA4).await;

                let events = owner_reads(&mut rig, answer(0xA4, PROOF))
                    .await
                    .expect("verified");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ShareVerified { channel_id, version, subshares: Some(1), threshold: Some(3) }]
                            if *channel_id == CHANNEL && *version == VERSION
                    ),
                    "got {events:?}"
                );
            });
        }

        #[test]
        fn refusal_without_owner_proof_is_share_verify_rejected() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_challenge(&mut rig, 0xB1).await;

                let events = owner_reads(&mut rig, refusal(0xB1))
                    .await
                    .expect("a refusal needs no proof");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ShareVerifyRejected { channel_id, version, status, .. }]
                            if *channel_id == CHANNEL
                                && *version == VERSION
                                && *status == StatusEnum::UnknownShareVersion as i32
                    ),
                    "got {events:?}"
                );
                assert_eq!(pending_nonce(&rig).await, None, "the challenge is spent");
            });
        }

        #[test]
        fn missing_result_is_an_error_and_keeps_the_challenge() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_challenge(&mut rig, 0xE1).await;
                let mut malformed = answer(0xE1, PROOF);
                malformed.result = None;

                let outcome = owner_reads(&mut rig, malformed).await;

                assert!(
                    matches!(outcome, Err(Error::Invariant(_))),
                    "a response with no result is malformed; got {outcome:?}"
                );
                assert_eq!(
                    pending_nonce(&rig).await,
                    Some(0xE1),
                    "a malformed response does not consume the challenge"
                );
            });
        }

        #[test]
        fn proof_removed_before_response_is_verify_shares_failed_no_proof() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_challenge(&mut rig, 0xC1).await;

                let events = owner_reads(&mut rig, answer(0xC1, PROOF))
                    .await
                    .expect("a missing proof is reported, not raised");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::VerifySharesFailed { channel_id, version, reason, .. }]
                            if *channel_id == CHANNEL
                                && *version == VERSION
                                && *reason == VerifyFailureReason::NoProof
                    ),
                    "got {events:?}"
                );
                assert_eq!(pending_nonce(&rig).await, None, "the challenge is spent");
            });
        }

        #[test]
        fn delayed_response_to_earlier_challenge_is_ignored_and_current_challenge_completes() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_proof(&mut rig, CHANNEL).await;
                seed_challenge(&mut rig, 0xD2).await;

                let stale = owner_reads(&mut rig, answer(0xD1, PROOF))
                    .await
                    .expect("a stale response is dropped, not raised");
                assert!(
                    matches!(
                        stale.as_slice(),
                        [DeRecEvent::MessageIgnored { channel_id, reason, trace_id }]
                            if *channel_id == CHANNEL
                                && *reason == IgnoreReason::StaleResponse
                                && *trace_id == 77
                    ),
                    "got {stale:?}"
                );
                assert_eq!(
                    pending_nonce(&rig).await,
                    Some(0xD2),
                    "the current challenge survives a stale response"
                );

                let current = owner_reads(&mut rig, answer(0xD2, PROOF))
                    .await
                    .expect("the current challenge completes");
                assert!(
                    matches!(
                        current.as_slice(),
                        [DeRecEvent::ShareVerified { channel_id, version, .. }]
                            if *channel_id == CHANNEL && *version == VERSION
                    ),
                    "got {current:?}"
                );
                assert_eq!(pending_nonce(&rig).await, None);
            });
        }

        #[test]
        fn delayed_refusal_of_earlier_challenge_is_ignored() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_challenge(&mut rig, 0xD4).await;

                let stale = owner_reads(&mut rig, refusal(0xD3))
                    .await
                    .expect("a stale refusal is dropped, not raised");
                assert!(
                    matches!(
                        stale.as_slice(),
                        [DeRecEvent::MessageIgnored { reason, .. }]
                            if *reason == IgnoreReason::StaleResponse
                    ),
                    "got {stale:?}"
                );
                assert_eq!(pending_nonce(&rig).await, Some(0xD4));
            });
        }

        #[test]
        fn no_proof_at_start_fails_that_channel_and_sends_no_challenge() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_helper(&mut rig, CHANNEL, "https://no-proof.example").await;
                seed_helper(&mut rig, OTHER, "https://with-proof.example").await;
                seed_proof(&mut rig, OTHER).await;
                let local = crate::protocol::tests::LocalFixture::new(SECRET_ID);

                let events = start(
                    &mut rig.stores(),
                    &local.local(),
                    VERSION,
                    Target::All,
                    &Round {
                        reply_to: &[],
                        trace_id: 9,
                    },
                )
                .await
                .expect("a missing proof fails its channel, not the round");

                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        DeRecEvent::VerifySharesFailed { channel_id, version, reason, .. }
                            if *channel_id == CHANNEL
                                && *version == VERSION
                                && *reason == VerifyFailureReason::NoProof
                    )),
                    "got {events:?}"
                );
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        DeRecEvent::VerifySharesStarted { channel_id, .. } if *channel_id == OTHER
                    )),
                    "got {events:?}"
                );
                assert_eq!(events.len(), 2, "one event per channel; got {events:?}");
                assert_eq!(
                    rig.transport.sent_uris(),
                    vec!["https://with-proof.example".to_owned()],
                    "only the channel with a proof is challenged"
                );
                assert_eq!(
                    pending_nonce(&rig).await,
                    None,
                    "no challenge is recorded for the channel without a proof"
                );
            });
        }

        #[test]
        fn no_shared_key_reason() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_proof(&mut rig, CHANNEL).await;

                let events = dispatch_all(
                    &mut rig.stores(),
                    SECRET_ID,
                    VERSION,
                    vec![(
                        CHANNEL,
                        SecretValue::PairingContact(ContactMessage::default()),
                    )],
                    &[],
                    &Round {
                        reply_to: &[],
                        trace_id: 9,
                    },
                )
                .await;

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::VerifySharesFailed { channel_id, reason, .. }]
                            if *channel_id == CHANNEL
                                && *reason == VerifyFailureReason::NoSharedKey
                    ),
                    "got {events:?}"
                );
                assert!(rig.transport.sent_envelopes().is_empty());
            });
        }

        #[test]
        fn dispatch_failure_reason() {
            run_async(async {
                let mut rig = StoreRig::new();
                seed_proof(&mut rig, CHANNEL).await;

                let events = dispatch_all(
                    &mut rig.stores(),
                    SECRET_ID,
                    VERSION,
                    vec![(CHANNEL, SecretValue::SharedKey(KEY))],
                    &[],
                    &Round {
                        reply_to: &[],
                        trace_id: 9,
                    },
                )
                .await;

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::VerifySharesFailed { channel_id, reason, .. }]
                            if *channel_id == CHANNEL
                                && *reason == VerifyFailureReason::DispatchFailed
                    ),
                    "got {events:?}"
                );
                assert!(rig.transport.sent_envelopes().is_empty());
            });
        }
    }
}
