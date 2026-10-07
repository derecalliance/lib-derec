// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport, MissingPolicy,
    PendingAction, SecretKind, SecretValue, StateItem, StateKey,
};
use super::NO_SHARE_FOR_VERSION;
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
///
/// A bound response whose status is not OK is the helper refusing the
/// challenge, not a failure of this device: it surfaces as
/// `ShareVerifyRejected` carrying the helper's status and memo. The
/// challenge row is consumed all the same, so the helper is challenged again
/// only by a new round.
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
        reject(
            stores,
            local,
            exchange,
            request,
            StatusEnum::UnknownShareVersion,
            NO_SHARE_FOR_VERSION,
        )
        .await?;
        return Ok(vec![DeRecEvent::NoOp]);
    };

    let stored =
        StoreShareRequestMessage::decode(stored_bytes.as_slice()).map_err(Error::ProtobufDecode)?;

    let resp =
        verification_response::produce(channel_id, request, exchange.shared_key, &stored.share)?;

    let envelope = crate::derec_message::apply_trace_id(&resp.envelope, exchange.trace_id)?;
    let endpoint = stores
        .channels
        .resolve_response_endpoints(
            secret_id,
            channel_id,
            &crate::extensions::advertised_endpoints::reply_to_owned(request),
        )
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
        &crate::extensions::advertised_endpoints::reply_to_owned(request),
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

    let valid = match verification_response::process(&request, response, &committed_share_bytes) {
        Ok(valid) => valid,
        Err(err) => {
            let Some((status, memo)) = err.as_non_ok_status() else {
                return Err(err);
            };
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                secret_id = response.secret_id,
                version = version,
                status,
                memo,
                "verification challenge rejected by helper"
            );
            return Ok(vec![DeRecEvent::ShareVerifyRejected {
                channel_id,
                version,
                status,
                memo: memo.to_owned(),
            }]);
        }
    };

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
    reply_to: &[derec_proto::TransportProtocol],
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
    use crate::protocol::test::{StoreRig, run_async};
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
            let local = crate::protocol::test::LocalFixture::new(SECRET_ID);
            let events = handle(
                &mut rig.stores(),
                &local.local(),
                &Exchange {
                    channel_id: CHANNEL,
                    shared_key: &[0u8; 32],
                    trace_id: 0,
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
        use crate::protocol::test::{
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
                    },
                )
                .await
                .expect("seed committed share");
            let local = crate::protocol::test::LocalFixture::new(SECRET_ID);
            handle(
                &mut rig.stores(),
                &local.local(),
                &Exchange {
                    channel_id: CHANNEL,
                    shared_key: &KEY,
                    trace_id: 0,
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
}
