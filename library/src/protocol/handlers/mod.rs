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
use crate::extensions::message_body::{MessageBodyExt as _, Route};
use crate::{
    Error, Result,
    protocol::{
        context::{Exchange, Local, PairingConfig},
        obligation::Obligation,
        stores::{StoreSet, Stores},
    },
    types::{ChannelId, SharedKey},
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{DeRecMessage, MessageBody};

/// The memo a helper sends with `UNKNOWN_SHARE_VERSION` when it is asked to
/// serve or prove a share it does not hold.
const NO_SHARE_FOR_VERSION: &str = "no share stored for this secret and version";

/// Route a decrypted channel message to the module that owns its flow.
///
/// Does only the part that is identical for every message: the
/// envelope-vs-inner timestamp binding (a mismatch is
/// [`IgnoreReason::TimestampMismatch`](crate::protocol::IgnoreReason::TimestampMismatch)),
/// the peer-supplied endpoint policy check, the role gate for bodies that name exactly one
/// permitted sender (see [`MessageBodyExt::expected_sender_role`](crate::extensions::message_body::MessageBodyExt::expected_sender_role)),
/// the member gate for bodies that name a group member (the member must be
/// recorded on the channel the message arrived on), the hand-off, and the
/// failure router. Which relationship a multi-valued body concerns, and what
/// to run for it, is the owning flow's decision.
///
/// A message that does not decrypt under `shared_key` has no authenticated
/// sender and fails with `Err`; nothing is sent. One that decrypts but whose
/// body cannot be decoded, or that carries a pairing request the channel
/// cannot carry, is a request owed an answer: an `ErrorResponseMessage` with
/// `FORMAT_ERROR`, sent by the library or handed to the application as a
/// [`DeRecEvent::RequestFailed`] token. A received `ErrorResponseMessage` is
/// reported as [`DeRecEvent::ErrorResponseReceived`] once it passes the
/// timestamp binding, and is never answered.
///
/// A request body builds an [`Obligation`] here, after decryption, so every
/// response to it goes out once. A failure of an answerable request is
/// returned as [`DeRecEvent::RequestFailed`] inside `Ok`, answered by the
/// library or handed to the application as a token (see
/// [`settle`](crate::protocol::obligation::settle)). The gates run before
/// dispatch and their failures are collected rather than returned, so a
/// refusal reaches the router on the same footing as a failure from the flow
/// itself.
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
    let plaintext = crate::derec_message::decrypt_inner_message(&message.message, shared_key)?;
    // The sender holds the channel key, so a body that does not decode is
    // still a request owed an answer, though no request type can be named.
    let inner_message = match MessageBody::decode_from_vec(&plaintext) {
        Ok(body) => body,
        Err(error) => {
            let obligation =
                Obligation::undecodable(channel_id, shared_key, message.trace_id, local.policy);
            return Ok(crate::protocol::obligation::settle(
                stores,
                local,
                &obligation,
                auto_respond_on_failure,
                Err(Error::ProtobufDecode(error)),
            )
            .await);
        }
    };

    // The sender stamps the envelope and the inner message with one value.
    // A mismatch is dropped before any handler runs, so nothing is stored
    // and nothing, not even a failure response, is sent.
    if crate::utils::verify_timestamps(message.timestamp, inner_message.timestamp().copied())
        .is_err()
    {
        return Ok(vec![DeRecEvent::MessageIgnored {
            channel_id,
            reason: super::IgnoreReason::TimestampMismatch,
            trace_id: message.trace_id,
        }]);
    }

    let inbound_trace_id = message.trace_id;
    let obligation = Obligation::for_body(
        &inner_message,
        channel_id,
        shared_key,
        inbound_trace_id,
        local.policy,
    );
    let exchange = &Exchange {
        channel_id,
        shared_key,
        trace_id: inbound_trace_id,
        obligation: obligation.as_ref(),
    };

    // The gates below reject an authenticated message, so all are failures
    // a peer can be told about. They are collected rather than `?`-ed so the
    // router at the bottom answers them alongside dispatch failures.
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

    // A body naming a group member is read as the replica relationship only
    // on that member's own channel. The `replica_id` is written by the
    // sender, so on any other channel it is a peer impersonating a member.
    if refused.is_none()
        && let Route::Replica(author) = inner_message.route()
        && let Err(e) = stores
            .channels
            .load_replica_member(local.secret_id, channel_id, author)
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
            MessageBody::ErrorResponse(response) => {
                let (status, memo) = response
                    .result
                    .as_ref()
                    .map(|r| (r.status, r.memo.clone()))
                    .unwrap_or_default();
                Ok(vec![DeRecEvent::ErrorResponseReceived {
                    channel_id,
                    status,
                    memo,
                }])
            }
            MessageBody::PairRequest(_) | MessageBody::PrePairRequest(_) => Err(
                Error::InvalidInput("a pairing request cannot travel under a channel key"),
            ),
            MessageBody::PairResponse(_) | MessageBody::PrePairResponse(_) => Err(
                Error::Invariant("unexpected MessageBody variant in channel message"),
            ),
        },
    };

    match &obligation {
        Some(obligation) => Ok(crate::protocol::obligation::settle(
            stores,
            local,
            obligation,
            auto_respond_on_failure,
            outcome,
        )
        .await),
        None => outcome,
    }
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

/// T4 of the replica-group spec: `replica_id` presence discriminates the two
/// paths, and a mismatch is a protocol error rather than a silent misroute.
#[cfg(test)]
mod replica_id_discrimination_tests {
    use super::*;
    use crate::protocol::DeRecChannelStore as _;
    use crate::protocol::tests::{StoreRig, run_async};
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
                        weight: 1,
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

/// The envelope and the inner message carry one timestamp, the send time.
/// A channel message whose two copies disagree is dropped before dispatch.
#[cfg(test)]
mod timestamp_binding_tests {
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::tests::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, RecordingTransport, run_async,
    };
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel, SecretValue};
    use crate::protocol::{
        AutoAcceptPolicy, DeRecChannelStore as _, DeRecEvent, DeRecProtocol, DeRecSecretStore as _,
        IgnoreReason,
    };
    use crate::types::ChannelId;
    use prost::Message as _;

    const SECRET_ID: u64 = 0x7153;
    const CHANNEL: ChannelId = ChannelId(4242);
    const SHARED_KEY: crate::types::SharedKey = [5u8; 32];
    const TRACE: u64 = 99;
    const ORIGINAL_URI: &str = "https://peer.example.com/derec";
    const MOVED_URI: &str = "https://moved.example.com/derec";

    fn endpoint(uri: &str) -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: uri.to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    async fn seed(channels: &mut InMemChannelStore, secrets: &mut InMemSecretStore) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: CHANNEL,
                    transports: vec![endpoint(ORIGINAL_URI)],
                    communication_info: std::collections::HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: crate::utils::now_secs(),
                    peer_role: derec_proto::SenderKind::Helper,
                    weight: 1,
                }),
            )
            .await
            .expect("seed channel");
        secrets
            .save(SECRET_ID, CHANNEL, SecretValue::SharedKey(SHARED_KEY))
            .await
            .expect("seed shared key");
    }

    fn build(
        channels: InMemChannelStore,
        secrets: InMemSecretStore,
        transport: RecordingTransport,
    ) -> DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
        RecordingTransport,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels)
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets)
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(transport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://helper.example.com"])
            .with_threshold(2)
            .with_auto_accept(AutoAcceptPolicy::all())
            .with_auto_respond_on_failure(true)
            .build()
            .expect("test protocol builds")
    }

    /// An update-channel-info request that, if processed, would rewrite the
    /// stored endpoint and send a response.
    fn update_request(
        envelope_ts: prost_types::Timestamp,
        inner_ts: prost_types::Timestamp,
    ) -> Vec<u8> {
        crate::derec_message::DeRecMessageBuilder::channel()
            .channel_id(CHANNEL)
            .timestamp(envelope_ts)
            .trace_id(TRACE)
            .message_body(derec_proto::MessageBody::UpdateChannelInfoRequest(
                derec_proto::UpdateChannelInfoRequestMessage {
                    communication_info: None,
                    supported_transports: vec![endpoint(MOVED_URI)],
                    timestamp: Some(inner_ts),
                },
            ))
            .encrypt(&SHARED_KEY)
            .expect("encrypt")
            .build()
            .expect("build")
            .encode_to_vec()
    }

    fn stored_uris(channels: &InMemChannelStore) -> Vec<String> {
        channels
            .helper_rows
            .lock()
            .unwrap()
            .get(&(SECRET_ID, CHANNEL.0))
            .expect("channel row")
            .transports
            .iter()
            .map(|t| t.uri.clone())
            .collect()
    }

    #[test]
    fn inbound_message_with_mismatched_timestamps_is_ignored() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed(&mut c, &mut s).await;
            let secrets_before = secrets.data.lock().unwrap().len();

            let envelope_ts = crate::derec_message::current_timestamp();
            let inner_ts = prost_types::Timestamp {
                seconds: envelope_ts.seconds - 1,
                nanos: envelope_ts.nanos,
            };
            let mut protocol = build(channels.clone(), secrets.clone(), transport.clone());
            let events = protocol
                .process(&update_request(envelope_ts, inner_ts))
                .await
                .expect("an ignored message is not an error");

            assert!(
                matches!(
                    events.as_slice(),
                    [DeRecEvent::MessageIgnored {
                        channel_id: CHANNEL,
                        reason: IgnoreReason::TimestampMismatch,
                        trace_id: TRACE,
                    }]
                ),
                "expected one MessageIgnored(TimestampMismatch), got {events:?}"
            );
            assert!(transport.sent_envelopes().is_empty(), "nothing is sent");
            assert_eq!(stored_uris(&channels), vec![ORIGINAL_URI.to_owned()]);
            assert_eq!(secrets.data.lock().unwrap().len(), secrets_before);
        });
    }

    #[test]
    fn inbound_message_with_matching_timestamps_is_processed() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed(&mut c, &mut s).await;

            let ts = crate::derec_message::current_timestamp();
            let mut protocol = build(channels.clone(), secrets, transport.clone());
            let events = protocol
                .process(&update_request(ts, ts))
                .await
                .expect("processed");

            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ChannelInfoUpdated { channel_id } if *channel_id == CHANNEL)),
                "expected ChannelInfoUpdated, got {events:?}"
            );
            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::MessageIgnored { .. })),
                "{events:?}"
            );
            assert_eq!(transport.sent_envelopes().len(), 1);
            assert_eq!(stored_uris(&channels), vec![MOVED_URI.to_owned()]);
        });
    }
}

/// A body naming a group member is accepted only on that member's own
/// channel. A paired helper holds a valid key for its channel, so a
/// `replica_id` it writes into a body must not open the replica path there.
#[cfg(test)]
mod replica_channel_binding_tests {
    use crate::primitives::sharing::request::SHARE_ALGORITHM_REPLICA_SECRET;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::tests::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, RecordingTransport, run_async,
    };
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, HelperChannel, HelperInfo, ReplicaMember, ReplicaRole,
        ReplicaSecretPayload, Secret, SecretValue, UserSecrets,
    };
    use crate::protocol::{
        AutoAcceptPolicy, DeRecChannelStore as _, DeRecEvent, DeRecProtocol, DeRecSecretStore as _,
        DeRecUserSecretStore as _,
    };
    use crate::types::{ChannelId, ReplicaId, SharedKey};
    use derec_proto::{DeRecResult, MessageBody, StatusEnum};
    use prost::Message as _;

    const SECRET_ID: u64 = 0xB1D0;
    const OWN_ID: u64 = 1;
    const HELPER_CHANNEL: ChannelId = ChannelId(4242);
    const HELPER_KEY: SharedKey = [5u8; 32];
    const GROUP_CHANNEL: ChannelId = ChannelId(5001);
    const GROUP_KEY: SharedKey = [9u8; 32];
    const MEMBER: u64 = 7;
    const FORGED_HELPER: u64 = 777;

    fn endpoint(uri: &str) -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: uri.to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    struct Rig {
        channels: InMemChannelStore,
        user_secrets: InMemUserSecretStore,
        protocol: DeRecProtocol<
            InMemChannelStore,
            InMemShareStore,
            InMemSecretStore,
            InMemUserSecretStore,
            InMemStateStore,
            RecordingTransport,
        >,
    }

    /// An owner with one paired helper, one group member, and a version-1
    /// snapshot.
    async fn rig() -> Rig {
        let mut channels = InMemChannelStore::default();
        let mut secrets = InMemSecretStore::default();
        let mut user_secrets = InMemUserSecretStore::default();
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: HELPER_CHANNEL,
                    transports: vec![endpoint("https://helper.example")],
                    communication_info: std::collections::HashMap::new(),
                    peer_role: derec_proto::SenderKind::Helper,
                    status: ChannelStatus::Paired,
                    created_at: crate::utils::now_secs(),
                    weight: 1,
                }),
            )
            .await
            .expect("seed helper channel");
        secrets
            .save(
                SECRET_ID,
                HELPER_CHANNEL,
                SecretValue::SharedKey(HELPER_KEY),
            )
            .await
            .expect("seed helper key");
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: GROUP_CHANNEL,
                    replica_id: ReplicaId(MEMBER),
                    transports: vec![endpoint("https://member.example")],
                    communication_info: std::collections::HashMap::new(),
                    role: ReplicaRole::Source,
                    status: ChannelStatus::Paired,
                    created_at: crate::utils::now_secs(),
                }),
            )
            .await
            .expect("seed member");
        secrets
            .save(SECRET_ID, GROUP_CHANNEL, SecretValue::SharedKey(GROUP_KEY))
            .await
            .expect("seed group key");
        user_secrets
            .save_latest(
                SECRET_ID,
                UserSecrets {
                    version: 1,
                    secrets: Vec::new(),
                    description: None,
                    author_replica_id: None,
                    threshold: None,
                },
            )
            .await
            .expect("seed snapshot");

        let protocol = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels.clone())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets)
            .with_user_secret_store(user_secrets.clone())
            .with_transport(RecordingTransport::default())
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example"])
            .with_threshold(2)
            .with_replica_id(OWN_ID)
            .with_auto_accept(AutoAcceptPolicy::all())
            .with_auto_respond_on_failure(true)
            .build()
            .expect("test protocol builds");
        Rig {
            channels,
            user_secrets,
            protocol,
        }
    }

    /// A version-2 copy of the secret that lists a helper the owner never
    /// paired with.
    fn forged_payload() -> Vec<u8> {
        ReplicaSecretPayload {
            secret: Some(Secret {
                helpers: vec![HelperInfo {
                    channel_id: FORGED_HELPER,
                    transports: vec![endpoint("https://attacker.example")],
                    shared_key: vec![0xEE; 32],
                    communication_info: std::collections::HashMap::new(),
                    weight: 1,
                }],
                secrets: Vec::new(),
                replicas: None,
                threshold: None,
            }),
            shares: Vec::new(),
            shared_key: Vec::new(),
            version: 2,
            author_replica_id: Some(MEMBER),
        }
        .encode_to_vec()
    }

    fn catch_up_response(replica_id: u64, ts: prost_types::Timestamp) -> MessageBody {
        MessageBody::GetShareResponse(derec_proto::GetShareResponseMessage {
            result: Some(DeRecResult {
                status: StatusEnum::Ok as i32,
                memo: String::new(),
            }),
            committed_de_rec_share: forged_payload(),
            share_algorithm: SHARE_ALGORITHM_REPLICA_SECRET,
            timestamp: Some(ts),
            secret_id: SECRET_ID,
            version: 2,
            replica_id: Some(replica_id),
        })
    }

    fn envelope(
        channel_id: ChannelId,
        key: &SharedKey,
        build: impl FnOnce(prost_types::Timestamp) -> MessageBody,
    ) -> Vec<u8> {
        let ts = crate::derec_message::current_timestamp();
        crate::derec_message::DeRecMessageBuilder::channel()
            .channel_id(channel_id)
            .timestamp(ts)
            .message_body(build(ts))
            .encrypt(key)
            .expect("encrypt")
            .build()
            .expect("build")
            .encode_to_vec()
    }

    fn assert_untouched(rig: &Rig) {
        assert!(
            !rig.channels
                .helper_rows
                .lock()
                .unwrap()
                .contains_key(&(SECRET_ID, FORGED_HELPER)),
            "the forged helper must not be installed"
        );
        let version = rig
            .user_secrets
            .data
            .lock()
            .unwrap()
            .get(&SECRET_ID)
            .map(|s| s.version);
        assert_eq!(version, Some(1), "the snapshot must not be replaced");
    }

    fn member_status(rig: &Rig) -> ChannelStatus {
        rig.channels
            .member_rows
            .lock()
            .unwrap()
            .get(&(SECRET_ID, MEMBER))
            .expect("member row")
            .status
    }

    #[test]
    fn a_catch_up_response_naming_no_member_on_a_helper_channel_is_refused() {
        run_async(async {
            let mut rig = rig().await;
            let message = envelope(HELPER_CHANNEL, &HELPER_KEY, |ts| {
                catch_up_response(9999, ts)
            });
            let result = rig.protocol.process(&message).await;
            assert!(result.is_err(), "expected a refusal, got {result:?}");
            assert_untouched(&rig);
        });
    }

    #[test]
    fn a_catch_up_response_naming_a_real_member_on_a_helper_channel_is_refused() {
        run_async(async {
            let mut rig = rig().await;
            let message = envelope(HELPER_CHANNEL, &HELPER_KEY, |ts| {
                catch_up_response(MEMBER, ts)
            });
            let result = rig.protocol.process(&message).await;
            assert!(result.is_err(), "expected a refusal, got {result:?}");
            assert_untouched(&rig);
        });
    }

    #[test]
    fn a_store_share_naming_a_real_member_on_a_helper_channel_is_not_hydrated() {
        run_async(async {
            let mut rig = rig().await;
            let message = envelope(HELPER_CHANNEL, &HELPER_KEY, |ts| {
                MessageBody::StoreShareRequest(derec_proto::StoreShareRequestMessage {
                    secret_id: SECRET_ID,
                    share: forged_payload(),
                    version: 2,
                    version_description: String::new(),
                    share_algorithm: 0,
                    keep_list: Vec::new(),
                    replica_id: Some(MEMBER),
                    reply_to_transports: Vec::new(),
                    timestamp: Some(ts),
                })
            });
            let events = rig.protocol.process(&message).await;
            assert!(
                !matches!(&events, Ok(e) if e.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ReplicaSecretInstalled { .. }
                        | DeRecEvent::ReplicaSecretReceived { .. }
                ))),
                "{events:?}"
            );
            assert_untouched(&rig);
        });
    }

    #[test]
    fn an_unpair_naming_a_real_member_on_a_helper_channel_does_not_flag_it() {
        run_async(async {
            let mut rig = rig().await;
            let message = envelope(HELPER_CHANNEL, &HELPER_KEY, |ts| {
                MessageBody::UnpairRequest(derec_proto::UnpairRequestMessage {
                    memo: String::new(),
                    timestamp: Some(ts),
                    reply_to_transports: Vec::new(),
                    replica_id: Some(MEMBER),
                })
            });
            let _ = rig.protocol.process(&message).await;
            assert_eq!(member_status(&rig), ChannelStatus::Paired);
        });
    }

    #[test]
    fn a_discovery_response_naming_a_member_on_a_helper_channel_is_refused() {
        run_async(async {
            let mut rig = rig().await;
            let message = envelope(HELPER_CHANNEL, &HELPER_KEY, |ts| {
                MessageBody::GetSecretIdsVersionsResponse(
                    derec_proto::GetSecretIdsVersionsResponseMessage {
                        result: Some(DeRecResult {
                            status: StatusEnum::Ok as i32,
                            memo: String::new(),
                        }),
                        secret_list: Vec::new(),
                        timestamp: Some(ts),
                        replica_id: Some(MEMBER),
                    },
                )
            });
            let result = rig.protocol.process(&message).await;
            assert!(result.is_err(), "expected a refusal, got {result:?}");
        });
    }

    /// The gate must not cost the legitimate path: the same response from the
    /// member, on the group channel, is hydrated.
    #[test]
    fn a_catch_up_response_from_the_member_on_its_channel_is_hydrated() {
        run_async(async {
            let mut rig = rig().await;
            let message = envelope(GROUP_CHANNEL, &GROUP_KEY, |ts| {
                catch_up_response(MEMBER, ts)
            });
            let events = rig.protocol.process(&message).await.expect("processed");
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ReplicaSecretReceived { .. })),
                "{events:?}"
            );
        });
    }
}
