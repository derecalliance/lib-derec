// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Every request a party receives over an authenticated channel gets exactly
//! one response.
//!
//! With `auto_respond_on_failure` on, the library answers a failure itself.
//! With it off, the application gets [`DeRecEvent::RequestFailed`] carrying a
//! [`PendingAction::RespondToFailure`], and `reject` sends the one response.
//! Either way the failure is reported in `Ok(events)`, so the rest of the
//! batch survives.

#[path = "support/protocol_doubles.rs"]
mod protocol_doubles;

use derec_library::derec_message::{DeRecMessageBuilder, current_timestamp};
use derec_library::protocol::types::{
    ChannelQuery, ChannelRecord, ChannelStatus, HelperChannel, ReplicaInfo, ReplicaMember,
    ReplicaRole, ReplicaSecretPayload, Replicas, Secret, SecretValue, Share,
};
use derec_library::protocol::{
    AutoAcceptPolicy, DeRecChannelStore as _, DeRecEvent, DeRecProtocol, DeRecProtocolBuilder,
    DeRecSecretStore as _, DeRecShareStore as _, PendingActionKind,
};
use derec_library::types::{ChannelId, ReplicaId, SharedKey};
use derec_proto::{DeRecMessage, MessageBody, SenderKind, StatusEnum, TransportProtocol};
use prost::Message as _;
use protocol_doubles::{
    FlakyChannelStore, FlakyUserSecretStore, InMemSecretStore, InMemStateStore, RecordingTransport,
    RefusingShareStore, run_async,
};

const SECRET_ID: u64 = 0x5EC2_E700;
const CHANNEL: ChannelId = ChannelId(6060);
const KEY: SharedKey = [0x11; 32];
const OWNER_URI: &str = "https://owner.example.com/derec";
const TRACE: u64 = 0x7_ACE;
const GENERIC_MEMO: &str = "request could not be processed";

const GROUP: ChannelId = ChannelId(7070);
const GROUP_KEY: SharedKey = [0x42; 32];
const SOURCE_ID: u64 = 1001;
const SELF_ID: u64 = 1002;
const SOURCE_URI: &str = "https://source.example.com/derec";
const SELF_URI: &str = "https://self.example.com/derec";

type Proto = DeRecProtocol<
    FlakyChannelStore,
    RefusingShareStore,
    InMemSecretStore,
    FlakyUserSecretStore,
    InMemStateStore,
    RecordingTransport,
>;

fn endpoint(uri: &str) -> TransportProtocol {
    TransportProtocol {
        uri: uri.to_owned(),
        protocol: derec_proto::Protocol::Https as i32,
    }
}

/// Shared handles onto every double a built protocol owns.
#[derive(Clone, Default)]
struct Rig {
    channels: FlakyChannelStore,
    shares: RefusingShareStore,
    secrets: InMemSecretStore,
    user_secrets: FlakyUserSecretStore,
    transport: RecordingTransport,
}

impl Rig {
    fn build(&self, respond: bool, policy: AutoAcceptPolicy, replica: bool) -> Proto {
        let builder = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(self.channels.clone())
            .with_share_store(self.shares.clone())
            .with_secret_store(self.secrets.clone())
            .with_user_secret_store(self.user_secrets.clone())
            .with_transport(self.transport.clone())
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://self.example.com/derec"])
            .with_threshold(2)
            .with_auto_accept(policy)
            .with_auto_respond_on_failure(respond);
        let builder = if replica {
            builder.with_replica_id(SELF_ID)
        } else {
            builder
        };
        builder.build().expect("test protocol builds")
    }

    fn sends(&self) -> Vec<Vec<u8>> {
        self.transport.sent_envelopes()
    }

    async fn seed_helper_channel(&self, peer_role: SenderKind) {
        let mut channels = self.channels.inner.clone();
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: CHANNEL,
                    transports: vec![endpoint(OWNER_URI)],
                    communication_info: std::collections::HashMap::new(),
                    peer_role,
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                    weight: 1,
                }),
            )
            .await
            .expect("seed helper channel");
        let mut secrets = self.secrets.clone();
        secrets
            .save(SECRET_ID, CHANNEL, SecretValue::SharedKey(KEY))
            .await
            .expect("seed channel key");
    }

    async fn seed_member(
        &self,
        replica_id: u64,
        role: ReplicaRole,
        uri: &str,
        status: ChannelStatus,
    ) {
        let mut channels = self.channels.inner.clone();
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: GROUP,
                    replica_id: ReplicaId(replica_id),
                    transports: vec![endpoint(uri)],
                    communication_info: std::collections::HashMap::new(),
                    role,
                    status,
                    created_at: now_secs(),
                }),
            )
            .await
            .expect("seed member");
    }

    async fn seed_group(&self, self_status: ChannelStatus) {
        self.seed_member(
            SOURCE_ID,
            ReplicaRole::Source,
            SOURCE_URI,
            ChannelStatus::Paired,
        )
        .await;
        self.seed_member(SELF_ID, ReplicaRole::Destination, SELF_URI, self_status)
            .await;
        let mut secrets = self.secrets.clone();
        secrets
            .save(SECRET_ID, GROUP, SecretValue::SharedKey(GROUP_KEY))
            .await
            .expect("seed group key");
    }

    fn shares_held(&self) -> usize {
        self.shares.inner.data.lock().unwrap().len()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// The inner message's own timestamp, which the envelope must repeat.
fn timestamp_slot(body: &mut MessageBody) -> &mut Option<prost_types::Timestamp> {
    match body {
        MessageBody::PairRequest(m) => &mut m.timestamp,
        MessageBody::PairResponse(m) => &mut m.timestamp,
        MessageBody::UnpairRequest(m) => &mut m.timestamp,
        MessageBody::UnpairResponse(m) => &mut m.timestamp,
        MessageBody::StoreShareRequest(m) => &mut m.timestamp,
        MessageBody::StoreShareResponse(m) => &mut m.timestamp,
        MessageBody::VerifyShareRequest(m) => &mut m.timestamp,
        MessageBody::VerifyShareResponse(m) => &mut m.timestamp,
        MessageBody::GetSecretIdsVersionsRequest(m) => &mut m.timestamp,
        MessageBody::GetSecretIdsVersionsResponse(m) => &mut m.timestamp,
        MessageBody::GetShareRequest(m) => &mut m.timestamp,
        MessageBody::GetShareResponse(m) => &mut m.timestamp,
        MessageBody::ErrorResponse(m) => &mut m.timestamp,
        MessageBody::UpdateChannelInfoRequest(m) => &mut m.timestamp,
        MessageBody::UpdateChannelInfoResponse(m) => &mut m.timestamp,
        MessageBody::PrePairRequest(m) => &mut m.timestamp,
        MessageBody::PrePairResponse(m) => &mut m.timestamp,
    }
}

/// Stamp the inner message with the time it is being sent, so the envelope
/// can carry the same value.
fn set_timestamp(body: &mut MessageBody, ts: prost_types::Timestamp) {
    *timestamp_slot(body) = Some(ts);
}

fn wire(channel_id: ChannelId, key: &SharedKey, mut body: MessageBody) -> Vec<u8> {
    let timestamp = current_timestamp();
    set_timestamp(&mut body, timestamp);
    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .trace_id(TRACE)
        .message_body(body)
        .encrypt(key)
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec()
}

/// A share the helper-side validation accepts.
fn valid_store_share() -> derec_proto::StoreShareRequestMessage {
    use derec_library::primitives::sharing::request;
    let split = request::split(
        &[(CHANNEL, 1), (ChannelId(42), 1)],
        SECRET_ID,
        1,
        b"a secret the owner protects",
        2,
    )
    .expect("split");
    let committed = split.shares.get(&CHANNEL).expect("share for the channel");
    let produced =
        request::produce(CHANNEL, 1, SECRET_ID, committed, 0, "", &KEY, &[]).expect("produce");
    request::extract(&produced.envelope, &KEY)
        .expect("extract")
        .request
}

fn roster(members: &[(u64, ReplicaRole, &str)]) -> Secret {
    Secret {
        helpers: Vec::new(),
        secrets: Vec::new(),
        replicas: Some(Replicas {
            channel_id: GROUP.0,
            members: members
                .iter()
                .map(|(replica_id, role, uri)| ReplicaInfo {
                    replica_id: *replica_id,
                    transports: vec![endpoint(uri)],
                    role: *role as i32,
                    communication_info: std::collections::HashMap::new(),
                })
                .collect(),
            shared_key: GROUP_KEY.to_vec(),
        }),
        threshold: None,
    }
}

fn replica_sync(secret: Secret) -> MessageBody {
    let payload = ReplicaSecretPayload {
        secret: Some(secret),
        shares: Vec::new(),
        shared_key: Vec::new(),
        version: 1,
        author_replica_id: None,
    };
    MessageBody::StoreShareRequest(derec_proto::StoreShareRequestMessage {
        secret_id: SECRET_ID,
        share: payload.encode_to_vec(),
        version: 1,
        replica_id: Some(SOURCE_ID),
        ..Default::default()
    })
}

fn full_roster() -> Secret {
    roster(&[
        (SOURCE_ID, ReplicaRole::Source, SOURCE_URI),
        (SELF_ID, ReplicaRole::Destination, SELF_URI),
    ])
}

/// The response type, status and memo of a sent envelope.
fn response(bytes: &[u8], key: &SharedKey) -> (&'static str, i32, String) {
    let envelope = DeRecMessage::decode(bytes).expect("a DeRec envelope");
    assert_eq!(
        envelope.trace_id, TRACE,
        "the response echoes the request's trace id"
    );
    let inner = derec_library::derec_message::extract_inner_message(&envelope.message, key)
        .expect("the requester can decrypt the response");
    let (name, result) = match inner {
        MessageBody::StoreShareResponse(r) => ("StoreShareResponse", r.result),
        MessageBody::VerifyShareResponse(r) => ("VerifyShareResponse", r.result),
        MessageBody::GetSecretIdsVersionsResponse(r) => ("GetSecretIdsVersionsResponse", r.result),
        MessageBody::GetShareResponse(r) => ("GetShareResponse", r.result),
        MessageBody::UnpairResponse(r) => ("UnpairResponse", r.result),
        MessageBody::UpdateChannelInfoResponse(r) => ("UpdateChannelInfoResponse", r.result),
        other => panic!("expected a response body, got {other:?}"),
    };
    let result = result.expect("a response carries a result");
    (name, result.status, result.memo)
}

fn request_failures(events: &[DeRecEvent]) -> Vec<&DeRecEvent> {
    events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::RequestFailed { .. }))
        .collect()
}

/// One request type, the store failure that hits it before its response is
/// sent, and the response it is owed.
#[derive(Clone, Copy, Debug)]
enum Req {
    StoreShare,
    VerifyShare,
    Discovery,
    GetShare,
    Unpair,
    UpdateChannelInfo,
    ReplicaStoreShare,
    ReplicaDiscovery,
    ReplicaGetShare,
}

impl Req {
    fn replica(self) -> bool {
        matches!(
            self,
            Req::ReplicaStoreShare | Req::ReplicaDiscovery | Req::ReplicaGetShare
        )
    }

    fn kind(self) -> PendingActionKind {
        match self {
            Req::StoreShare | Req::ReplicaStoreShare => PendingActionKind::StoreShare,
            Req::VerifyShare => PendingActionKind::VerifyShare,
            Req::Discovery | Req::ReplicaDiscovery => PendingActionKind::Discovery,
            Req::GetShare | Req::ReplicaGetShare => PendingActionKind::GetShare,
            Req::Unpair => PendingActionKind::Unpair,
            Req::UpdateChannelInfo => PendingActionKind::UpdateChannelInfo,
        }
    }

    fn response_type(self) -> &'static str {
        match self {
            Req::StoreShare | Req::ReplicaStoreShare => "StoreShareResponse",
            Req::VerifyShare => "VerifyShareResponse",
            Req::Discovery | Req::ReplicaDiscovery => "GetSecretIdsVersionsResponse",
            Req::GetShare | Req::ReplicaGetShare => "GetShareResponse",
            Req::Unpair => "UnpairResponse",
            Req::UpdateChannelInfo => "UpdateChannelInfoResponse",
        }
    }

    fn arrival(self) -> (ChannelId, SharedKey, &'static str) {
        if self.replica() {
            (GROUP, GROUP_KEY, SOURCE_URI)
        } else {
            (CHANNEL, KEY, OWNER_URI)
        }
    }

    fn policy(self) -> AutoAcceptPolicy {
        let mut policy = AutoAcceptPolicy::default();
        match self {
            Req::StoreShare => policy.store_share = true,
            Req::VerifyShare => policy.verify_share = true,
            Req::Discovery => policy.discovery = true,
            Req::GetShare => policy.get_share = true,
            Req::Unpair => policy.unpair = true,
            Req::UpdateChannelInfo => policy.update_channel_info = true,
            _ => {}
        }
        policy
    }

    fn body(self) -> MessageBody {
        match self {
            Req::StoreShare => MessageBody::StoreShareRequest(valid_store_share()),
            Req::VerifyShare => {
                MessageBody::VerifyShareRequest(derec_proto::VerifyShareRequestMessage {
                    secret_id: SECRET_ID,
                    version: 1,
                    nonce: 7,
                    ..Default::default()
                })
            }
            Req::Discovery => MessageBody::GetSecretIdsVersionsRequest(Default::default()),
            Req::GetShare => MessageBody::GetShareRequest(derec_proto::GetShareRequestMessage {
                secret_id: SECRET_ID,
                version: 1,
                ..Default::default()
            }),
            // The reply-to is what leaves the request answerable while the
            // channel store itself is failing.
            Req::Unpair => MessageBody::UnpairRequest(derec_proto::UnpairRequestMessage {
                memo: "leaving".to_owned(),
                reply_to_transports: vec![endpoint(OWNER_URI)],
                ..Default::default()
            }),
            Req::UpdateChannelInfo => MessageBody::UpdateChannelInfoRequest(
                derec_proto::UpdateChannelInfoRequestMessage {
                    supported_transports: vec![endpoint(OWNER_URI)],
                    ..Default::default()
                },
            ),
            Req::ReplicaStoreShare => replica_sync(full_roster()),
            Req::ReplicaDiscovery => MessageBody::GetSecretIdsVersionsRequest(
                derec_proto::GetSecretIdsVersionsRequestMessage {
                    replica_id: Some(SOURCE_ID),
                    ..Default::default()
                },
            ),
            Req::ReplicaGetShare => {
                MessageBody::GetShareRequest(derec_proto::GetShareRequestMessage {
                    secret_id: SECRET_ID,
                    version: 1,
                    replica_id: Some(SOURCE_ID),
                    ..Default::default()
                })
            }
        }
    }

    async fn seed(self, rig: &Rig) {
        if self.replica() {
            rig.seed_group(ChannelStatus::Paired).await;
            return;
        }
        rig.seed_helper_channel(SenderKind::Owner).await;
        if matches!(self, Req::VerifyShare) {
            let stored = derec_proto::StoreShareRequestMessage {
                secret_id: SECRET_ID,
                version: 1,
                share: b"a committed share".to_vec(),
                ..Default::default()
            };
            let mut shares = rig.shares.inner.clone();
            shares
                .save(
                    SECRET_ID,
                    CHANNEL,
                    Share {
                        secret_id: SECRET_ID,
                        version: 1,
                        bytes: stored.encode_to_vec(),
                        subshares: None,
                        threshold: None,
                    },
                )
                .await
                .expect("seed stored share");
        }
    }

    /// Make the store this request needs before its response fail.
    fn inject(self, rig: &Rig) {
        match self {
            Req::StoreShare => rig.shares.set_backend_error(true),
            Req::VerifyShare => rig.shares.set_verification_backend_error(true),
            Req::Discovery | Req::GetShare => rig.shares.set_load_backend_error(true),
            Req::Unpair => rig.channels.set_fail_load(true),
            Req::UpdateChannelInfo => rig.channels.set_fail_save(true),
            Req::ReplicaStoreShare | Req::ReplicaDiscovery | Req::ReplicaGetShare => {
                rig.user_secrets.set_fail_load(true)
            }
        }
    }
}

/// Drive `req` into a store failure before its response and check the
/// outcome the mode promises.
async fn run_store_failure(req: Req, respond: bool, auto: bool) {
    let label = format!("{req:?} respond={respond} auto={auto}");
    let rig = Rig::default();
    req.seed(&rig).await;
    let policy = if auto {
        req.policy()
    } else {
        AutoAcceptPolicy::default()
    };
    let mut protocol = rig.build(respond, policy, req.replica());
    let (arrival, key, peer_uri) = req.arrival();
    let bytes = wire(arrival, &key, req.body());

    let events =
        if auto || req.replica() {
            req.inject(&rig);
            protocol.process(&bytes).await.unwrap_or_else(|e| {
                panic!("{label}: an answerable failure never fails process: {e}")
            })
        } else {
            let raised = protocol
                .process(&bytes)
                .await
                .unwrap_or_else(|e| panic!("{label}: the request raises an action: {e}"));
            let action = raised
                .into_iter()
                .find_map(|e| match e {
                    DeRecEvent::ActionRequired { action, .. } => Some(action),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{label}: expected ActionRequired"));
            assert!(
                rig.sends().is_empty(),
                "{label}: nothing is sent before accept"
            );
            req.inject(&rig);
            protocol.accept(action).await.unwrap_or_else(|e| {
                panic!("{label}: an answerable failure never fails accept: {e}")
            })
        };

    if auto && !req.replica() {
        assert!(
            events.iter().any(|e| matches!(
                e,
                DeRecEvent::AutoAccepted { action_kind, .. } if *action_kind == req.kind()
            )),
            "{label}: AutoAccepted survives the failure: {events:?}"
        );
    }

    let failures = request_failures(&events);
    assert_eq!(failures.len(), 1, "{label}: one RequestFailed: {events:?}");
    let DeRecEvent::RequestFailed {
        channel_id,
        action_kind,
        responded,
        status,
        memo: event_memo,
        error_code,
        message,
        action,
    } = failures[0]
    else {
        unreachable!()
    };
    assert_eq!(*channel_id, arrival, "{label}");
    assert_eq!(*action_kind, req.kind(), "{label}");
    assert_eq!(*status, StatusEnum::Fail as i32, "{label}");
    assert_eq!(event_memo, GENERIC_MEMO, "{label}");
    assert_eq!(error_code, "store_error", "{label}");
    assert!(!message.is_empty(), "{label}");

    if respond {
        assert!(*responded, "{label}: the library answered");
        assert!(
            action.is_none(),
            "{label}: an answered failure carries no token"
        );
        let sent = rig.sends();
        assert_eq!(sent.len(), 1, "{label}: exactly one response");
        assert_eq!(
            rig.transport.sent_uris(),
            vec![peer_uri.to_owned()],
            "{label}"
        );
        let (name, sent_status, memo) = response(&sent[0], &key);
        assert_eq!(name, req.response_type(), "{label}");
        assert_eq!(sent_status, StatusEnum::Fail as i32, "{label}");
        assert_eq!(
            memo, GENERIC_MEMO,
            "{label}: an unknown failure sends the generic memo"
        );
        assert!(
            !memo.contains(message.as_str()),
            "{label}: the error text stays local"
        );
    } else {
        assert!(!*responded, "{label}");
        assert!(rig.sends().is_empty(), "{label}: nothing is sent when off");
        let token = action.clone().unwrap_or_else(|| panic!("{label}: a token"));
        assert_eq!(token.kind(), PendingActionKind::Failed, "{label}");
        protocol
            .reject(token, StatusEnum::Fail, "declined by the application")
            .await
            .unwrap_or_else(|e| panic!("{label}: the token answers the request: {e}"));
        let sent = rig.sends();
        assert_eq!(sent.len(), 1, "{label}: reject sends exactly one response");
        assert_eq!(
            rig.transport.sent_uris(),
            vec![peer_uri.to_owned()],
            "{label}"
        );
        let (name, sent_status, memo) = response(&sent[0], &key);
        assert_eq!(name, req.response_type(), "{label}");
        assert_eq!(sent_status, StatusEnum::Fail as i32, "{label}");
        assert_eq!(memo, "declined by the application", "{label}");
    }
}

fn matrix(req: Req, autos: &[bool]) {
    for respond in [true, false] {
        for auto in autos {
            run_async(run_store_failure(req, respond, *auto));
        }
    }
}

#[test]
fn helper_store_share_store_failure_is_answered_once() {
    matrix(Req::StoreShare, &[true, false]);
}

#[test]
fn helper_verify_share_store_failure_is_answered_once() {
    matrix(Req::VerifyShare, &[true, false]);
}

#[test]
fn helper_discovery_store_failure_is_answered_once() {
    matrix(Req::Discovery, &[true, false]);
}

#[test]
fn helper_get_share_store_failure_is_answered_once() {
    matrix(Req::GetShare, &[true, false]);
}

/// Only the manual path has a store step before the unpair response that a
/// reply-to keeps answerable: the re-check of the persisted action.
#[test]
fn helper_unpair_store_failure_is_answered_once() {
    matrix(Req::Unpair, &[false]);
}

#[test]
fn helper_update_channel_info_store_failure_is_answered_once() {
    matrix(Req::UpdateChannelInfo, &[true, false]);
}

/// Replica-bound requests raise no action, so there is no manual path.
#[test]
fn replica_store_share_store_failure_is_answered_once() {
    matrix(Req::ReplicaStoreShare, &[true]);
}

#[test]
fn replica_discovery_store_failure_is_answered_once() {
    matrix(Req::ReplicaDiscovery, &[true]);
}

#[test]
fn replica_get_share_store_failure_is_answered_once() {
    matrix(Req::ReplicaGetShare, &[true]);
}

/// With no reply target resolvable before any send, even an `on` device
/// hands the application a token rather than dropping the obligation.
#[test]
fn an_unresolvable_target_yields_a_token_even_when_on() {
    run_async(async {
        let rig = Rig::default();
        rig.seed_helper_channel(SenderKind::Owner).await;
        let mut protocol = rig.build(true, AutoAcceptPolicy::default(), false);
        let body = MessageBody::UnpairRequest(derec_proto::UnpairRequestMessage::default());
        let raised = protocol
            .process(&wire(CHANNEL, &KEY, body))
            .await
            .expect("raises the action");
        let action = raised
            .into_iter()
            .find_map(|e| match e {
                DeRecEvent::ActionRequired { action, .. } => Some(action),
                _ => None,
            })
            .expect("ActionRequired");
        rig.channels.set_fail_load(true);

        let events = protocol.accept(action).await.expect("answerable, so Ok");
        assert!(rig.sends().is_empty(), "no target, so nothing was sent");
        assert!(
            matches!(
                request_failures(&events).as_slice(),
                [DeRecEvent::RequestFailed {
                    responded: false,
                    action: Some(_),
                    ..
                }]
            ),
            "{events:?}"
        );
    });
}

/// Unpair's acknowledgement goes out before the local state is dropped. A
/// drop failure after it is reported, never answered a second time.
#[test]
fn an_unpair_drop_failure_after_the_ack_is_reported_not_reanswered() {
    for respond in [true, false] {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            rig.shares.set_remove_channel_backend_error(true);
            let mut protocol = rig.build(respond, Req::Unpair.policy(), false);

            let events = protocol
                .process(&wire(CHANNEL, &KEY, Req::Unpair.body()))
                .await
                .expect("a post-send failure never fails process");

            let sent = rig.sends();
            assert_eq!(sent.len(), 1, "only the acknowledgement: {events:?}");
            let (name, status, _) = response(&sent[0], &KEY);
            assert_eq!(name, "UnpairResponse");
            assert_eq!(status, StatusEnum::Ok as i32);

            let unpaired = events
                .iter()
                .position(
                    |e| matches!(e, DeRecEvent::Unpaired { channel_id } if *channel_id == CHANNEL),
                )
                .expect("Unpaired is reported");
            let failed = events
                .iter()
                .position(|e| {
                    matches!(
                        e,
                        DeRecEvent::RequestFailed {
                            responded: true,
                            action: None,
                            action_kind: PendingActionKind::Unpair,
                            ..
                        }
                    )
                })
                .expect("the failure is reported as answered");
            assert!(unpaired < failed, "committed state first: {events:?}");
        });
    }
}

/// A member removed by the roster acknowledges, then tears down. A teardown
/// failure after the acknowledgement is reported, never answered again.
#[test]
fn a_replica_tear_down_failure_after_the_ack_is_reported_not_reanswered() {
    for respond in [true, false] {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_group(ChannelStatus::Unpairing).await;
            rig.user_secrets.set_fail_remove(true);
            let mut protocol = rig.build(respond, AutoAcceptPolicy::default(), true);

            let body = replica_sync(roster(&[(SOURCE_ID, ReplicaRole::Source, SOURCE_URI)]));
            let events = protocol
                .process(&wire(GROUP, &GROUP_KEY, body))
                .await
                .expect("a post-send failure never fails process");

            let sent = rig.sends();
            assert_eq!(sent.len(), 1, "only the acknowledgement: {events:?}");
            let (name, status, _) = response(&sent[0], &GROUP_KEY);
            assert_eq!(name, "StoreShareResponse");
            assert_eq!(status, StatusEnum::Ok as i32);

            let removed = events
                .iter()
                .position(|e| matches!(e, DeRecEvent::SelfRemovedFromGroup { .. }))
                .expect("SelfRemovedFromGroup is reported");
            let failed = events
                .iter()
                .position(|e| {
                    matches!(
                        e,
                        DeRecEvent::RequestFailed {
                            responded: true,
                            action: None,
                            ..
                        }
                    )
                })
                .expect("the failure is reported as answered");
            assert!(removed < failed, "committed state first: {events:?}");
        });
    }
}

/// The pairing responder answers before it drops its transient material. A
/// cleanup failure after the answer still completes the pairing and is
/// reported as answered.
#[test]
fn a_pair_cleanup_failure_after_the_answer_is_reported_not_reanswered() {
    run_async(async {
        let helper = Rig::default();
        let mut helper_protocol = helper.build(
            true,
            AutoAcceptPolicy {
                pairing: true,
                ..Default::default()
            },
            false,
        );
        let contact = helper_protocol
            .create_contact(
                Some(ChannelId(9191)),
                derec_proto::ContactMode::InlineKeys,
                None,
            )
            .await
            .expect("contact");

        let owner = Rig::default();
        let mut owner_protocol = owner.build(false, AutoAcceptPolicy::default(), false);
        owner_protocol
            .start(derec_library::protocol::DeRecFlow::Pairing {
                kind: SenderKind::Owner,
                contact,
                peer_communication_info: std::collections::HashMap::new(),
            })
            .await
            .expect("pairing starts");
        let request = owner.sends().pop().expect("the pair request");

        helper.channels.set_fail_remove(true);
        let events = helper_protocol
            .process(&request)
            .await
            .expect("a post-send failure never fails process");

        assert_eq!(
            helper.sends().len(),
            1,
            "only the pair response: {events:?}"
        );
        let completed = events
            .iter()
            .position(|e| matches!(e, DeRecEvent::PairingCompleted { .. }))
            .expect("PairingCompleted is reported");
        let failed = events
            .iter()
            .position(|e| {
                matches!(
                    e,
                    DeRecEvent::RequestFailed {
                        responded: true,
                        action: None,
                        action_kind: PendingActionKind::Pairing,
                        ..
                    }
                )
            })
            .expect("the failure is reported as answered");
        assert!(completed < failed, "committed state first: {events:?}");
        let (
            DeRecEvent::PairingCompleted {
                channel_id: paired, ..
            },
            DeRecEvent::RequestFailed {
                channel_id: failed_on,
                status,
                memo,
                ..
            },
        ) = (&events[completed], &events[failed])
        else {
            unreachable!()
        };
        assert_eq!(failed_on, paired, "both name the long-term channel");
        assert_eq!(*status, StatusEnum::Ok as i32, "the PairResponse sent");
        assert_eq!(memo, "", "an OK PairResponse carries no memo");
    });
}

/// A refusal whose send fails is attempted once, and the refusal is still
/// reported.
#[test]
fn a_refusal_send_failure_keeps_the_refusal_and_is_not_retried() {
    for respond in [true, false] {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            rig.transport.set_fail_after_record(true);
            let mut protocol = rig.build(respond, AutoAcceptPolicy::default(), false);
            let mut invalid = valid_store_share();
            invalid.share = vec![0xFF; 8];

            let events = protocol
                .process(&wire(
                    CHANNEL,
                    &KEY,
                    MessageBody::StoreShareRequest(invalid),
                ))
                .await
                .expect("a refusal never fails process");

            assert_eq!(rig.sends().len(), 1, "one attempt: {events:?}");
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ShareRefused { .. })),
                "{events:?}"
            );
            assert!(
                matches!(
                    request_failures(&events).as_slice(),
                    [DeRecEvent::RequestFailed {
                        responded: true,
                        action: None,
                        ..
                    }]
                ),
                "{events:?}"
            );
        });
    }
}

#[test]
fn a_replica_refusal_send_failure_keeps_the_refusal_and_is_not_retried() {
    for respond in [true, false] {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_group(ChannelStatus::Paired).await;
            rig.transport.set_fail_after_record(true);
            let mut protocol = rig.build(respond, AutoAcceptPolicy::default(), true);
            let body = MessageBody::StoreShareRequest(derec_proto::StoreShareRequestMessage {
                secret_id: SECRET_ID,
                share: vec![0xFF; 8],
                version: 1,
                replica_id: Some(SOURCE_ID),
                ..Default::default()
            });

            let events = protocol
                .process(&wire(GROUP, &GROUP_KEY, body))
                .await
                .expect("a refusal never fails process");

            assert_eq!(rig.sends().len(), 1, "one attempt: {events:?}");
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ReplicaSecretRefused { .. })),
                "{events:?}"
            );
            assert!(
                matches!(
                    request_failures(&events).as_slice(),
                    [DeRecEvent::RequestFailed {
                        responded: true,
                        ..
                    }]
                ),
                "{events:?}"
            );
        });
    }
}

/// A persisted action whose channel is no longer paired has nothing to
/// answer on: `accept` refuses it, and nothing is stored or sent.
#[test]
fn a_stale_store_share_action_on_an_unpaired_channel_is_refused() {
    for respond in [true, false] {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            let mut protocol = rig.build(respond, AutoAcceptPolicy::default(), false);
            let raised = protocol
                .process(&wire(CHANNEL, &KEY, Req::StoreShare.body()))
                .await
                .expect("raises the action");
            let action = raised
                .into_iter()
                .find_map(|e| match e {
                    DeRecEvent::ActionRequired { action, .. } => Some(action),
                    _ => None,
                })
                .expect("ActionRequired");

            let mut channels = rig.channels.inner.clone();
            channels
                .remove(
                    SECRET_ID,
                    ChannelQuery::Helper {
                        channel_id: CHANNEL,
                    },
                )
                .await
                .expect("unpair the channel");

            let err = protocol
                .accept(action)
                .await
                .expect_err("a stale action is refused");
            assert!(
                matches!(err, derec_library::Error::InvalidInput(_)),
                "{err:?}"
            );
            assert_eq!(rig.shares_held(), 0, "no share is stored");
            assert!(rig.sends().is_empty(), "nothing is sent");
        });
    }
}

/// A persisted action whose channel's peer no longer holds the role the flow
/// needs is answered `REJECTED`, a known failure.
#[test]
fn a_stale_action_whose_role_changed_is_answered_rejected() {
    run_async(async {
        let rig = Rig::default();
        rig.seed_helper_channel(SenderKind::Owner).await;
        let mut protocol = rig.build(true, AutoAcceptPolicy::default(), false);
        let raised = protocol
            .process(&wire(CHANNEL, &KEY, Req::StoreShare.body()))
            .await
            .expect("raises the action");
        let action = raised
            .into_iter()
            .find_map(|e| match e {
                DeRecEvent::ActionRequired { action, .. } => Some(action),
                _ => None,
            })
            .expect("ActionRequired");
        rig.seed_helper_channel(SenderKind::Helper).await;

        let events = protocol.accept(action).await.expect("answered, so Ok");
        assert_eq!(rig.shares_held(), 0, "no share is stored");
        let sent = rig.sends();
        assert_eq!(sent.len(), 1);
        let (name, status, memo) = response(&sent[0], &KEY);
        assert_eq!(name, "StoreShareResponse");
        assert_eq!(status, StatusEnum::Rejected as i32);
        assert_ne!(memo, GENERIC_MEMO, "a known failure keeps its own memo");
        assert!(
            matches!(
                request_failures(&events).as_slice(),
                [DeRecEvent::RequestFailed { responded: true, status: s, .. }]
                    if *s == StatusEnum::Rejected as i32
            ),
            "{events:?}"
        );
    });
}

/// A failure before a response exists is unanswerable, and a response body
/// is never answered. Neither mode sends anything for these.
#[test]
fn exempt_messages_are_never_answered() {
    for respond in [true, false] {
        run_async(async move {
            let policy = AutoAcceptPolicy::all();

            // Undecryptable: right channel, wrong key.
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            let mut protocol = rig.build(respond, policy, false);
            let _ = protocol
                .process(&wire(CHANNEL, &[0x99; 32], Req::Discovery.body()))
                .await;
            assert!(rig.sends().is_empty(), "undecryptable, respond={respond}");

            // Expired.
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            let mut protocol = rig.build(respond, policy, false);
            let stale = prost_types::Timestamp {
                seconds: now_secs() as i64 - 24 * 60 * 60,
                nanos: 0,
            };
            let mut body = Req::Discovery.body();
            set_timestamp(&mut body, stale);
            let expired = DeRecMessageBuilder::channel()
                .channel_id(CHANNEL)
                .timestamp(stale)
                .trace_id(TRACE)
                .message_body(body)
                .encrypt(&KEY)
                .expect("encrypt")
                .build()
                .expect("build")
                .encode_to_vec();
            let events = protocol.process(&expired).await.expect("ignored");
            assert!(request_failures(&events).is_empty());
            assert!(rig.sends().is_empty(), "expired, respond={respond}");

            // Timestamp mismatch between envelope and body.
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            let mut protocol = rig.build(respond, policy, false);
            let now = current_timestamp();
            let mut body = Req::Discovery.body();
            set_timestamp(
                &mut body,
                prost_types::Timestamp {
                    seconds: now.seconds - 1,
                    nanos: now.nanos,
                },
            );
            let mismatched = DeRecMessageBuilder::channel()
                .channel_id(CHANNEL)
                .timestamp(now)
                .trace_id(TRACE)
                .message_body(body)
                .encrypt(&KEY)
                .expect("encrypt")
                .build()
                .expect("build")
                .encode_to_vec();
            let events = protocol.process(&mismatched).await.expect("ignored");
            assert!(request_failures(&events).is_empty());
            assert!(rig.sends().is_empty(), "mismatch, respond={respond}");

            // Pending verification.
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            rig.channels
                .inner
                .helper_rows
                .lock()
                .unwrap()
                .values_mut()
                .for_each(|h| h.status = ChannelStatus::Pending);
            let mut protocol = rig.build(respond, policy, false);
            let events = protocol
                .process(&wire(CHANNEL, &KEY, Req::Discovery.body()))
                .await
                .expect("ignored");
            assert!(request_failures(&events).is_empty());
            assert!(rig.sends().is_empty(), "pending, respond={respond}");

            // Every response body, none of which this device asked for.
            for body in [
                MessageBody::StoreShareResponse(Default::default()),
                MessageBody::VerifyShareResponse(Default::default()),
                MessageBody::GetSecretIdsVersionsResponse(Default::default()),
                MessageBody::GetShareResponse(Default::default()),
                MessageBody::UnpairResponse(Default::default()),
                MessageBody::UpdateChannelInfoResponse(Default::default()),
                MessageBody::ErrorResponse(Default::default()),
            ] {
                let rig = Rig::default();
                rig.seed_helper_channel(SenderKind::Owner).await;
                let mut protocol = rig.build(respond, policy, false);
                let label = format!("{body:?}");
                let events = protocol.process(&wire(CHANNEL, &KEY, body)).await;
                assert!(
                    rig.sends().is_empty(),
                    "response body {label}, respond={respond}"
                );
                if let Ok(events) = events {
                    assert!(request_failures(&events).is_empty(), "{label}");
                }
            }

            // A PairRequest that fails before it is accepted: a replica
            // pairing to a device with no replica identity.
            let rig = Rig::default();
            let mut protocol = rig.build(respond, policy, false);
            let contact = protocol
                .create_contact(
                    Some(ChannelId(9292)),
                    derec_proto::ContactMode::InlineKeys,
                    None,
                )
                .await
                .expect("contact");
            let joiner = Rig::default();
            let mut joiner_protocol = joiner.build(false, AutoAcceptPolicy::default(), true);
            joiner_protocol
                .start(derec_library::protocol::DeRecFlow::Pairing {
                    kind: SenderKind::ReplicaSource,
                    contact,
                    peer_communication_info: std::collections::HashMap::new(),
                })
                .await
                .expect("pairing starts");
            let request = joiner.sends().pop().expect("the pair request");
            let _ = protocol.process(&request).await;
            assert!(rig.sends().is_empty(), "pair request, respond={respond}");

            // A replica UnpairRequest naming no member.
            let rig = Rig::default();
            rig.seed_group(ChannelStatus::Paired).await;
            let mut protocol = rig.build(respond, policy, true);
            let body = MessageBody::UnpairRequest(derec_proto::UnpairRequestMessage {
                replica_id: Some(0xBAD),
                ..Default::default()
            });
            let _ = protocol.process(&wire(GROUP, &GROUP_KEY, body)).await;
            assert!(rig.sends().is_empty(), "replica unpair, respond={respond}");

            // A PrePair request whose nonce does not match the contact.
            let rig = Rig::default();
            let mut protocol = rig.build(respond, policy, false);
            let contact = protocol
                .create_contact(
                    Some(ChannelId(8181)),
                    derec_proto::ContactMode::NoKeys,
                    Some(5),
                )
                .await
                .expect("contact");
            let pre_pair = DeRecMessage {
                channel_id: contact.channel_id,
                timestamp: Some(current_timestamp()),
                message: MessageBody::PrePairRequest(derec_proto::PrePairRequestMessage {
                    nonce: 6,
                    supported_transports: vec![endpoint(OWNER_URI)],
                    timestamp: Some(current_timestamp()),
                })
                .encode_to_vec(),
                ..Default::default()
            }
            .encode_to_vec();
            let _ = protocol.process(&pre_pair).await;
            assert!(rig.sends().is_empty(), "pre-pair, respond={respond}");
        });
    }
}

/// A replica-bound request refused at the reply-to gate is answered on the
/// member's recorded endpoints, never through a helper lookup, and its
/// token stays answerable.
#[test]
fn a_replica_request_with_a_refused_reply_to_is_answered_on_the_member() {
    for respond in [true, false] {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_group(ChannelStatus::Paired).await;
            let mut protocol = rig.build(respond, AutoAcceptPolicy::default(), true);
            let body = MessageBody::GetShareRequest(derec_proto::GetShareRequestMessage {
                secret_id: SECRET_ID,
                version: 1,
                replica_id: Some(SOURCE_ID),
                reply_to_transports: vec![TransportProtocol {
                    uri: "http://192.168.1.42:8080".to_owned(),
                    protocol: derec_proto::Protocol::Https as i32,
                }],
                ..Default::default()
            });

            let events = protocol
                .process(&wire(GROUP, &GROUP_KEY, body))
                .await
                .expect("an answerable failure never fails process");
            let failures = request_failures(&events);
            let [
                DeRecEvent::RequestFailed {
                    responded, action, ..
                },
            ] = failures.as_slice()
            else {
                panic!("one RequestFailed: {events:?}");
            };

            if respond {
                assert!(*responded);
            } else {
                assert!(rig.sends().is_empty());
                protocol
                    .reject(
                        action.clone().expect("a token"),
                        StatusEnum::UnsupportedTransportProtocol,
                        "a transport endpoint in the request was refused",
                    )
                    .await
                    .expect("the token answers the request");
            }
            let sent = rig.sends();
            assert_eq!(sent.len(), 1, "exactly one response, respond={respond}");
            assert_eq!(rig.transport.sent_uris(), vec![SOURCE_URI.to_owned()]);
            let (name, status, memo) = response(&sent[0], &GROUP_KEY);
            assert_eq!(name, "GetShareResponse");
            assert_eq!(status, StatusEnum::UnsupportedTransportProtocol as i32);
            assert_eq!(memo, "a transport endpoint in the request was refused");
        });
    }
}

/// The ephemeral pairing channel an admission handover arrives on, and its
/// key.
const EPHEMERAL: ChannelId = ChannelId(7171);
const EPHEMERAL_KEY: SharedKey = [0x33; 32];

/// Process an admission handover that fails after it is recognised, before
/// `hydrate` stores the group key.
async fn failing_handover(rig: &Rig, respond: bool) -> Vec<DeRecEvent> {
    let mut channels = rig.channels.inner.clone();
    channels
        .save(
            SECRET_ID,
            ChannelRecord::Replica(ReplicaMember {
                channel_id: EPHEMERAL,
                replica_id: ReplicaId(SOURCE_ID),
                transports: vec![endpoint(SOURCE_URI)],
                communication_info: std::collections::HashMap::new(),
                role: ReplicaRole::Source,
                status: ChannelStatus::Paired,
                created_at: now_secs(),
            }),
        )
        .await
        .expect("seed the admitter");
    let mut secrets = rig.secrets.clone();
    secrets
        .save(SECRET_ID, EPHEMERAL, SecretValue::SharedKey(EPHEMERAL_KEY))
        .await
        .expect("seed the ephemeral key");
    rig.user_secrets.set_fail_load(true);
    let mut protocol = rig.build(respond, AutoAcceptPolicy::default(), true);

    let payload = ReplicaSecretPayload {
        secret: Some(full_roster()),
        shares: Vec::new(),
        shared_key: GROUP_KEY.to_vec(),
        version: 1,
        author_replica_id: None,
    };
    let body = MessageBody::StoreShareRequest(derec_proto::StoreShareRequestMessage {
        secret_id: SECRET_ID,
        share: payload.encode_to_vec(),
        version: 1,
        replica_id: Some(SOURCE_ID),
        ..Default::default()
    });
    protocol
        .process(&wire(EPHEMERAL, &EPHEMERAL_KEY, body))
        .await
        .expect("an answerable failure never fails process")
}

/// An admission handover arrives on the ephemeral pairing channel, whose key
/// the admitter dropped when it sent the copy. A failure after the handover
/// is recognised is answered on the group channel under the group key.
#[test]
fn a_handover_failure_is_answered_on_the_group_channel() {
    run_async(async {
        let rig = Rig::default();
        let events = failing_handover(&rig, true).await;
        assert!(
            matches!(
                request_failures(&events).as_slice(),
                [DeRecEvent::RequestFailed {
                    responded: true,
                    ..
                }]
            ),
            "{events:?}"
        );

        let sent = rig.sends();
        assert_eq!(sent.len(), 1);
        let envelope = DeRecMessage::decode(sent[0].as_slice()).expect("an envelope");
        assert_eq!(
            envelope.channel_id, GROUP.0,
            "answered on the group channel"
        );
        assert!(
            derec_library::derec_message::extract_inner_message(&envelope.message, &EPHEMERAL_KEY)
                .is_err(),
            "never under the dropped ephemeral key"
        );
        let (name, status, memo) = response(&sent[0], &GROUP_KEY);
        assert_eq!(name, "StoreShareResponse");
        assert_eq!(status, StatusEnum::Fail as i32);
        assert_eq!(memo, GENERIC_MEMO);
    });
}

/// With `auto_respond_on_failure` off, a handover failure before the group
/// key is stored has no key `reject` could load: no token is issued, and
/// nothing is sent.
#[test]
fn a_handover_failure_before_the_group_key_is_stored_issues_no_token() {
    run_async(async {
        let rig = Rig::default();
        let events = failing_handover(&rig, false).await;
        let failures = request_failures(&events);
        let [
            DeRecEvent::RequestFailed {
                channel_id,
                responded,
                status,
                action,
                ..
            },
        ] = failures.as_slice()
        else {
            panic!("one RequestFailed: {events:?}");
        };
        assert_eq!(*channel_id, EPHEMERAL);
        assert!(!*responded);
        assert_eq!(*status, StatusEnum::Fail as i32);
        assert!(action.is_none(), "no token reject could answer: {action:?}");
        assert!(rig.sends().is_empty());
    });
}

/// A refusal that fails before its answer could be handed to the transport
/// keeps its own status and memo, and its event: the router answers with
/// them, or hands the application a token carrying them.
#[test]
fn a_refusal_failing_before_its_send_keeps_its_status_and_event() {
    for respond in [true, false] {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            let mut protocol = rig.build(respond, AutoAcceptPolicy::default(), false);
            let mut invalid = valid_store_share();
            invalid.share = vec![0xFF; 8];
            // The pending-verification gate and the sharing handler read the
            // channel; the refusal's endpoint lookup is the third read.
            rig.channels.fail_one_load_after(2);

            let events = protocol
                .process(&wire(
                    CHANNEL,
                    &KEY,
                    MessageBody::StoreShareRequest(invalid),
                ))
                .await
                .expect("a refusal never fails process");

            let (refused, refused_memo) = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::ShareRefused { status, memo, .. } => Some((*status, memo.clone())),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("the refusal is kept: {events:?}"));
            let failures = request_failures(&events);
            let [
                DeRecEvent::RequestFailed {
                    responded,
                    status,
                    action,
                    ..
                },
            ] = failures.as_slice()
            else {
                panic!("one RequestFailed: {events:?}");
            };
            assert_eq!(*status, refused, "the refusal's own status");
            assert_eq!(*responded, respond);

            if !respond {
                assert!(rig.sends().is_empty());
                protocol
                    .reject(
                        action.clone().expect("a token"),
                        StatusEnum::try_from(refused).expect("a status"),
                        &refused_memo,
                    )
                    .await
                    .expect("the token answers the request");
            }
            let sent = rig.sends();
            assert_eq!(sent.len(), 1, "exactly one response, respond={respond}");
            let (name, status, memo) = response(&sent[0], &KEY);
            assert_eq!(name, "StoreShareResponse");
            assert_eq!(status, refused);
            assert_eq!(memo, refused_memo);
        });
    }
}

/// An update naming neither field breaks a protocol rule, so it is answered
/// with that rule rather than the generic memo.
#[test]
fn an_empty_update_is_answered_with_its_rule() {
    run_async(async {
        let rig = Rig::default();
        rig.seed_helper_channel(SenderKind::Owner).await;
        let mut protocol = rig.build(true, AutoAcceptPolicy::default(), false);
        let body = MessageBody::UpdateChannelInfoRequest(Default::default());

        let events = protocol
            .process(&wire(CHANNEL, &KEY, body))
            .await
            .expect("an answerable failure never fails process");
        assert_eq!(request_failures(&events).len(), 1, "{events:?}");
        let sent = rig.sends();
        assert_eq!(sent.len(), 1);
        let (name, status, memo) = response(&sent[0], &KEY);
        assert_eq!(name, "UpdateChannelInfoResponse");
        assert_eq!(status, StatusEnum::Fail as i32);
        assert_eq!(
            memo,
            "UpdateChannelInfo requires at least one of communication_info or supported_transports"
        );
    });
}

const UNDECODABLE_MEMO: &str = "message body could not be decoded";

/// A channel message that decrypts under `key` but whose plaintext is not a
/// `MessageBody`.
fn undecodable(channel_id: ChannelId, key: &SharedKey) -> Vec<u8> {
    let mut envelope =
        DeRecMessage::decode(wire(channel_id, key, Req::Discovery.body()).as_slice())
            .expect("a DeRec envelope");
    envelope.message =
        derec_cryptography::channel::encrypt_message(b"not a message body", key, &[7u8; 32])
            .expect("encrypt");
    envelope.encode_to_vec()
}

/// The envelope and `ErrorResponseMessage` of a sent envelope.
fn error_response(
    bytes: &[u8],
    key: &SharedKey,
) -> (DeRecMessage, derec_proto::ErrorResponseMessage) {
    let envelope = DeRecMessage::decode(bytes).expect("a DeRec envelope");
    let inner = derec_library::derec_message::extract_inner_message(&envelope.message, key)
        .expect("the requester can decrypt the response");
    match inner {
        MessageBody::ErrorResponse(r) => (envelope, r),
        other => panic!("expected an ErrorResponse, got {other:?}"),
    }
}

fn assert_format_error(bytes: &[u8]) {
    let (envelope, response) = error_response(bytes, &KEY);
    assert_eq!(envelope.channel_id, CHANNEL.0);
    assert_eq!(envelope.trace_id, TRACE, "the inbound trace id is echoed");
    let result = response.result.expect("an ErrorResponse carries a result");
    assert_eq!(result.status, StatusEnum::FormatError as i32);
    assert_eq!(result.memo, UNDECODABLE_MEMO);
    assert!(response.timestamp.is_some(), "the response is stamped");
    assert_eq!(
        envelope.timestamp, response.timestamp,
        "the envelope carries the body's timestamp"
    );
}

/// A body that decrypts under the channel key but cannot be decoded is
/// answered with one `ErrorResponse`, which the peer reports and never
/// answers.
#[test]
fn an_undecodable_body_is_answered_with_a_format_error() {
    run_async(async {
        let rig = Rig::default();
        rig.seed_helper_channel(SenderKind::Owner).await;
        let mut protocol = rig.build(true, AutoAcceptPolicy::all(), false);

        let events = protocol
            .process(&undecodable(CHANNEL, &KEY))
            .await
            .expect("an answerable failure never fails process");

        let failures = request_failures(&events);
        assert!(
            matches!(
                failures.as_slice(),
                [DeRecEvent::RequestFailed {
                    channel_id: CHANNEL,
                    action_kind: PendingActionKind::Failed,
                    responded: true,
                    status: s,
                    action: None,
                    ..
                }] if *s == StatusEnum::FormatError as i32
            ),
            "{events:?}"
        );
        let sent = rig.sends();
        assert_eq!(sent.len(), 1, "exactly one response");
        assert_format_error(&sent[0]);

        let peer = Rig::default();
        peer.seed_helper_channel(SenderKind::Helper).await;
        let mut peer_protocol = peer.build(true, AutoAcceptPolicy::all(), false);
        let events = peer_protocol
            .process(&sent[0])
            .await
            .expect("an ErrorResponse is reported");
        assert!(
            matches!(
                events.as_slice(),
                [DeRecEvent::ErrorResponseReceived { channel_id: CHANNEL, status, memo }]
                    if *status == StatusEnum::FormatError as i32 && memo == UNDECODABLE_MEMO
            ),
            "{events:?}"
        );
        assert!(
            peer.sends().is_empty(),
            "an ErrorResponse is never answered"
        );
    });
}

/// With the failure response off, an undecodable body yields a token, and
/// rejecting it sends one `ErrorResponse` with the application's status and
/// memo.
#[test]
fn an_undecodable_body_yields_a_token_when_off() {
    run_async(async {
        let rig = Rig::default();
        rig.seed_helper_channel(SenderKind::Owner).await;
        let mut protocol = rig.build(false, AutoAcceptPolicy::all(), false);

        let events = protocol
            .process(&undecodable(CHANNEL, &KEY))
            .await
            .expect("an answerable failure never fails process");
        assert!(rig.sends().is_empty(), "nothing is sent before reject");

        let failures = request_failures(&events);
        let [
            DeRecEvent::RequestFailed {
                channel_id: CHANNEL,
                action_kind: PendingActionKind::Failed,
                responded: false,
                status,
                action: Some(token),
                ..
            },
        ] = failures.as_slice()
        else {
            panic!("expected one RequestFailed with a token, got {events:?}");
        };
        assert_eq!(*status, StatusEnum::FormatError as i32);
        assert_eq!(token.kind(), PendingActionKind::Failed);

        protocol
            .reject(token.clone(), StatusEnum::Rejected, "not accepted here")
            .await
            .expect("the token is answerable");
        let sent = rig.sends();
        assert_eq!(sent.len(), 1, "exactly one response");
        let (envelope, response) = error_response(&sent[0], &KEY);
        assert_eq!(envelope.trace_id, TRACE);
        let result = response.result.expect("result");
        assert_eq!(result.status, StatusEnum::Rejected as i32);
        assert_eq!(result.memo, "not accepted here");
        assert_eq!(envelope.timestamp, response.timestamp);
    });
}

/// A message that does not decrypt under the channel key has no
/// authenticated sender, so it fails `process` and is never answered.
#[test]
fn an_undecryptable_body_fails_and_is_never_answered() {
    for respond in [true, false] {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            let mut protocol = rig.build(respond, AutoAcceptPolicy::all(), false);

            let result = protocol.process(&undecodable(CHANNEL, &[0x99; 32])).await;
            assert!(result.is_err(), "respond={respond}: {result:?}");
            assert!(rig.sends().is_empty(), "respond={respond}");
        });
    }
}

/// An `ErrorResponse` is reported once it passes the timestamp binding, and
/// never answered, whatever the mode: two peers can never trade them.
#[test]
fn a_received_error_response_is_reported_and_never_answered() {
    for respond in [true, false] {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Helper).await;
            let mut protocol = rig.build(respond, AutoAcceptPolicy::all(), false);
            let body = || {
                MessageBody::ErrorResponse(derec_proto::ErrorResponseMessage {
                    result: Some(derec_proto::DeRecResult {
                        status: StatusEnum::FormatError as i32,
                        memo: UNDECODABLE_MEMO.to_owned(),
                    }),
                    timestamp: None,
                })
            };

            let events = protocol
                .process(&wire(CHANNEL, &KEY, body()))
                .await
                .expect("reported");
            assert!(
                matches!(
                    events.as_slice(),
                    [DeRecEvent::ErrorResponseReceived { channel_id: CHANNEL, status, memo }]
                        if *status == StatusEnum::FormatError as i32 && memo == UNDECODABLE_MEMO
                ),
                "respond={respond}: {events:?}"
            );
            assert!(rig.sends().is_empty(), "respond={respond}");

            let now = current_timestamp();
            let mut stale = body();
            set_timestamp(
                &mut stale,
                prost_types::Timestamp {
                    seconds: now.seconds - 1,
                    nanos: now.nanos,
                },
            );
            let mismatched = DeRecMessageBuilder::channel()
                .channel_id(CHANNEL)
                .timestamp(now)
                .trace_id(TRACE)
                .message_body(stale)
                .encrypt(&KEY)
                .expect("encrypt")
                .build()
                .expect("build")
                .encode_to_vec();
            let events = protocol.process(&mismatched).await.expect("ignored");
            assert!(
                matches!(
                    events.as_slice(),
                    [DeRecEvent::MessageIgnored {
                        reason: derec_library::protocol::IgnoreReason::TimestampMismatch,
                        ..
                    }]
                ),
                "respond={respond}: {events:?}"
            );
            assert!(rig.sends().is_empty(), "respond={respond}");
        });
    }
}

/// A pairing request arriving under a paired channel's key is a request the
/// channel cannot carry: it is answered like an undecodable body.
#[test]
fn a_pairing_request_under_a_channel_key_is_answered_with_a_format_error() {
    let bodies = || {
        [
            MessageBody::PairRequest(Default::default()),
            MessageBody::PrePairRequest(Default::default()),
        ]
    };
    for body in bodies() {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            let mut protocol = rig.build(true, AutoAcceptPolicy::all(), false);
            let label = format!("{body:?}");

            let events = protocol
                .process(&wire(CHANNEL, &KEY, body))
                .await
                .expect("an answerable failure never fails process");
            assert!(
                matches!(
                    request_failures(&events).as_slice(),
                    [DeRecEvent::RequestFailed {
                        action_kind: PendingActionKind::Failed,
                        responded: true,
                        ..
                    }]
                ),
                "{label}: {events:?}"
            );
            let sent = rig.sends();
            assert_eq!(sent.len(), 1, "{label}");
            assert_format_error(&sent[0]);
        });
    }
    for body in bodies() {
        run_async(async move {
            let rig = Rig::default();
            rig.seed_helper_channel(SenderKind::Owner).await;
            let mut protocol = rig.build(false, AutoAcceptPolicy::all(), false);
            let label = format!("{body:?}");

            let events = protocol
                .process(&wire(CHANNEL, &KEY, body))
                .await
                .expect("an answerable failure never fails process");
            assert!(rig.sends().is_empty(), "{label}");
            let failures = request_failures(&events);
            let [
                DeRecEvent::RequestFailed {
                    action: Some(token),
                    ..
                },
            ] = failures.as_slice()
            else {
                panic!("{label}: expected a token, got {events:?}");
            };
            protocol
                .reject(token.clone(), StatusEnum::FormatError, UNDECODABLE_MEMO)
                .await
                .expect("the token is answerable");
            let sent = rig.sends();
            assert_eq!(sent.len(), 1, "{label}");
            assert_format_error(&sent[0]);
        });
    }
}

/// The pair request a responder refuses, and the refusal it sent.
async fn refused_pairing(
    responder: &Rig,
    responder_protocol: &mut Proto,
    joiner: &Rig,
    joiner_protocol: &mut Proto,
    kind: SenderKind,
) -> (Vec<DeRecEvent>, Vec<Vec<u8>>, ChannelId) {
    let contact = responder_protocol
        .create_contact(
            Some(ChannelId(9393)),
            derec_proto::ContactMode::InlineKeys,
            None,
        )
        .await
        .expect("contact");
    joiner_protocol
        .start(derec_library::protocol::DeRecFlow::Pairing {
            kind,
            contact,
            peer_communication_info: std::collections::HashMap::new(),
        })
        .await
        .expect("pairing starts");
    let request = joiner.sends().pop().expect("the pair request");
    let events = responder_protocol
        .process(&request)
        .await
        .expect("a pairing refusal is reported, not an error");
    (events, responder.sends(), ChannelId(9393))
}

/// A pair request whose parameter range does not overlap this device's is
/// refused with a `PairResponse` and reported as `PairingRefused`.
#[test]
fn a_parameter_range_refusal_is_reported_as_pairing_refused() {
    for respond in [true, false] {
        run_async(async move {
            let range = |min_share_size, max_share_size| derec_proto::ParameterRange {
                min_share_size,
                max_share_size,
                ..Default::default()
            };
            let build = |rig: &Rig, range| -> Proto {
                DeRecProtocolBuilder::new(SECRET_ID)
                    .with_channel_store(rig.channels.clone())
                    .with_share_store(rig.shares.clone())
                    .with_secret_store(rig.secrets.clone())
                    .with_user_secret_store(rig.user_secrets.clone())
                    .with_transport(rig.transport.clone())
                    .with_state_store(InMemStateStore)
                    .with_own_transports(["https://self.example.com/derec"])
                    .with_threshold(2)
                    .with_auto_accept(AutoAcceptPolicy::all())
                    .with_auto_respond_on_failure(respond)
                    .with_parameter_range(range)
                    .build()
                    .expect("test protocol builds")
            };
            let responder = Rig::default();
            let mut responder_protocol = build(&responder, range(1_000_000_000, 5_000_000_000));
            let joiner = Rig::default();
            let mut joiner_protocol = build(&joiner, range(10_000_000, 500_000_000));

            let (events, sent, channel) = refused_pairing(
                &responder,
                &mut responder_protocol,
                &joiner,
                &mut joiner_protocol,
                SenderKind::Helper,
            )
            .await;
            let [
                DeRecEvent::PairingRefused {
                    channel_id,
                    status,
                    memo,
                    error_code,
                    message,
                },
            ] = events.as_slice()
            else {
                panic!("respond={respond}: expected PairingRefused, got {events:?}");
            };
            assert_eq!(*channel_id, channel);
            assert_eq!(*status, StatusEnum::IncompatibleParameterRange as i32);
            let expected_memo = "`shareSize` range [10000000, 500000000] does not overlap \
                 the accepted range [1000000000, 5000000000]";
            assert_eq!(memo, expected_memo);
            assert_eq!(error_code, "incompatible_parameter_range");
            let expected_message = derec_library::Error::from(
                derec_library::primitives::pairing::PairingError::IncompatibleParameterRange {
                    field: "shareSize",
                    local_min: 1_000_000_000,
                    local_max: 5_000_000_000,
                    peer_min: 10_000_000,
                    peer_max: 500_000_000,
                },
            )
            .to_string();
            assert_eq!(message, &expected_message);
            assert_eq!(sent.len(), 1, "the refusal is sent: respond={respond}");

            let err = joiner_protocol
                .process(&sent[0])
                .await
                .expect_err("the joiner reads the refusal");
            assert_eq!(
                err.source.as_non_ok_status(),
                Some((StatusEnum::IncompatibleParameterRange as i32, expected_memo)),
                "{err:?}"
            );
            assert!(err.source.to_string().contains(expected_memo), "{err}");
        });
    }
}

/// A pairing refusal handed to the transport is reported as
/// `PairingRefused` even when dropping the pairing secret afterwards fails:
/// the requester was answered, and the cleanup failure is reported after it.
#[test]
fn a_pairing_refusal_whose_cleanup_fails_is_still_reported() {
    for respond in [true, false] {
        run_async(async move {
            let responder = Rig::default();
            responder.seed_group(ChannelStatus::Paired).await;
            let mut responder_protocol = responder.build(respond, AutoAcceptPolicy::all(), true);
            let joiner = Rig::default();
            let mut joiner_protocol = joiner.build(respond, AutoAcceptPolicy::default(), true);
            responder
                .secrets
                .set_fail_remove(Some(derec_library::protocol::SecretKind::PairingSecret));

            let (events, sent, channel) = refused_pairing(
                &responder,
                &mut responder_protocol,
                &joiner,
                &mut joiner_protocol,
                SenderKind::ReplicaSource,
            )
            .await;
            let [
                DeRecEvent::PairingRefused {
                    channel_id,
                    status,
                    memo: refused_memo,
                    ..
                },
                DeRecEvent::RequestFailed {
                    channel_id: failed_channel,
                    action_kind,
                    responded,
                    status: failed_status,
                    memo: failed_memo,
                    action,
                    ..
                },
            ] = events.as_slice()
            else {
                panic!(
                    "respond={respond}: expected PairingRefused then RequestFailed, got {events:?}"
                );
            };
            assert_eq!(failed_memo, refused_memo, "the refusal's memo was sent");
            assert_eq!(*channel_id, channel);
            assert_eq!(*status, StatusEnum::ReplicaIdConflict as i32);
            assert_eq!(*failed_channel, channel);
            assert_eq!(*action_kind, PendingActionKind::Pairing);
            assert!(*responded);
            assert_eq!(*failed_status, StatusEnum::ReplicaIdConflict as i32);
            assert!(action.is_none());
            assert_eq!(sent.len(), 1, "the refusal is sent once: respond={respond}");
        });
    }
}

/// A replica pair request announcing an id this group already holds is
/// refused with a `PairResponse` and reported as `PairingRefused`.
#[test]
fn a_replica_id_conflict_is_reported_as_pairing_refused() {
    for respond in [true, false] {
        run_async(async move {
            let responder = Rig::default();
            responder.seed_group(ChannelStatus::Paired).await;
            let mut responder_protocol = responder.build(respond, AutoAcceptPolicy::all(), true);
            let joiner = Rig::default();
            let mut joiner_protocol = joiner.build(respond, AutoAcceptPolicy::default(), true);

            let (events, sent, channel) = refused_pairing(
                &responder,
                &mut responder_protocol,
                &joiner,
                &mut joiner_protocol,
                SenderKind::ReplicaSource,
            )
            .await;
            let [
                DeRecEvent::PairingRefused {
                    channel_id,
                    status,
                    memo,
                    error_code,
                    message,
                },
            ] = events.as_slice()
            else {
                panic!("respond={respond}: expected PairingRefused, got {events:?}");
            };
            assert_eq!(*channel_id, channel);
            assert_eq!(*status, StatusEnum::ReplicaIdConflict as i32);
            assert_eq!(memo, "replica id already in use by a member of this group");
            assert_eq!(error_code, "replica_id_conflict");
            assert_eq!(
                message,
                &derec_library::Error::ReplicaIdConflict {
                    replica_id: SELF_ID
                }
                .to_string()
            );
            assert_eq!(sent.len(), 1, "the refusal is sent: respond={respond}");

            let err = joiner_protocol
                .process(&sent[0])
                .await
                .expect_err("the joiner reads the refusal");
            assert_eq!(
                err.source.as_non_ok_status().map(|(s, _)| s),
                Some(StatusEnum::ReplicaIdConflict as i32),
                "{err:?}"
            );
        });
    }
}

/// A message on a group channel that names no member has no sender to
/// answer: it is reported without a token and nothing is sent, in both modes.
#[test]
fn an_unidentified_sender_on_a_group_channel_is_reported_without_a_token() {
    for respond in [true, false] {
        for wire_bytes in [
            undecodable(GROUP, &GROUP_KEY),
            wire(
                GROUP,
                &GROUP_KEY,
                MessageBody::PairRequest(Default::default()),
            ),
        ] {
            run_async(async move {
                let rig = Rig::default();
                rig.seed_group(ChannelStatus::Paired).await;
                let mut protocol = rig.build(respond, AutoAcceptPolicy::all(), true);

                let events = protocol
                    .process(&wire_bytes)
                    .await
                    .expect("an unanswerable request is reported, not an error");
                assert!(
                    matches!(
                        request_failures(&events).as_slice(),
                        [DeRecEvent::RequestFailed {
                            channel_id: GROUP,
                            action_kind: PendingActionKind::Failed,
                            responded: false,
                            action: None,
                            ..
                        }]
                    ),
                    "respond={respond}: {events:?}"
                );
                assert!(rig.sends().is_empty(), "respond={respond}");
            });
        }
    }
}

/// A failure whose answer `RequestFailed` must let the application reproduce.
#[derive(Clone, Copy, Debug)]
enum Answerable {
    /// The peer no longer holds the role the flow needs: `REJECTED` with its
    /// own memo.
    RoleMismatch,
    /// A store backend failure: `FAIL` with the generic memo.
    StoreFailure,
    /// A body that decrypts but does not decode: `FORMAT_ERROR`.
    Undecodable,
    /// A refusal whose answer failed before the send: the refusal's own
    /// status and memo.
    CarriedRefusal,
    /// A request breaking a protocol rule the flow names.
    EmptyUpdate,
}

/// Drive `case` into its failure and return the call's events.
async fn fail(case: Answerable, rig: &Rig, protocol: &mut Proto) -> Vec<DeRecEvent> {
    match case {
        Answerable::RoleMismatch => {
            let raised = protocol
                .process(&wire(CHANNEL, &KEY, Req::StoreShare.body()))
                .await
                .expect("raises the action");
            let action = raised
                .into_iter()
                .find_map(|e| match e {
                    DeRecEvent::ActionRequired { action, .. } => Some(action),
                    _ => None,
                })
                .expect("ActionRequired");
            rig.seed_helper_channel(SenderKind::Helper).await;
            protocol.accept(action).await.expect("answerable, so Ok")
        }
        Answerable::StoreFailure => {
            Req::StoreShare.inject(rig);
            protocol
                .process(&wire(CHANNEL, &KEY, Req::StoreShare.body()))
                .await
                .expect("answerable, so Ok")
        }
        Answerable::Undecodable => protocol
            .process(&undecodable(CHANNEL, &KEY))
            .await
            .expect("answerable, so Ok"),
        Answerable::CarriedRefusal => {
            let mut invalid = valid_store_share();
            invalid.share = vec![0xFF; 8];
            rig.channels.fail_one_load_after(2);
            protocol
                .process(&wire(
                    CHANNEL,
                    &KEY,
                    MessageBody::StoreShareRequest(invalid),
                ))
                .await
                .expect("answerable, so Ok")
        }
        Answerable::EmptyUpdate => protocol
            .process(&wire(
                CHANNEL,
                &KEY,
                MessageBody::UpdateChannelInfoRequest(Default::default()),
            ))
            .await
            .expect("answerable, so Ok"),
    }
}

/// A sent response with every timestamp cleared: the envelope (ciphertext
/// dropped) and the encoded inner body.
fn without_timestamps(bytes: &[u8]) -> (DeRecMessage, Vec<u8>) {
    let mut envelope = DeRecMessage::decode(bytes).expect("a DeRec envelope");
    let mut inner = derec_library::derec_message::extract_inner_message(&envelope.message, &KEY)
        .expect("the requester can decrypt the response");
    assert!(
        timestamp_slot(&mut inner).is_some(),
        "the response is stamped"
    );
    set_timestamp(&mut inner, prost_types::Timestamp::default());
    envelope.timestamp = None;
    envelope.message = Vec::new();
    (envelope, inner.encode_to_vec())
}

/// The one `RequestFailed` of `events`: its status, memo and token.
fn the_failure(
    events: &[DeRecEvent],
) -> (i32, String, Option<derec_library::protocol::PendingAction>) {
    match request_failures(events).as_slice() {
        [
            DeRecEvent::RequestFailed {
                status,
                memo,
                action,
                ..
            },
        ] => (*status, memo.clone(), action.clone()),
        _ => panic!("one RequestFailed: {events:?}"),
    }
}

/// Answering a token with the `status` and `memo` its `RequestFailed`
/// carries sends exactly what `auto_respond_on_failure` would have sent,
/// apart from the send time.
#[test]
fn answering_a_token_with_its_event_memo_matches_the_auto_response() {
    for case in [
        Answerable::RoleMismatch,
        Answerable::StoreFailure,
        Answerable::Undecodable,
        Answerable::CarriedRefusal,
        Answerable::EmptyUpdate,
    ] {
        run_async(async move {
            let on = Rig::default();
            on.seed_helper_channel(SenderKind::Owner).await;
            let policy = if matches!(case, Answerable::StoreFailure) {
                Req::StoreShare.policy()
            } else {
                AutoAcceptPolicy::default()
            };
            let mut protocol = on.build(true, policy, false);
            let events = fail(case, &on, &mut protocol).await;
            let (on_status, on_memo, token) = the_failure(&events);
            assert!(token.is_none(), "{case:?}: answered, so no token");
            let auto = on.sends();
            assert_eq!(auto.len(), 1, "{case:?}: the library answered once");
            let (_, sent_status, sent_memo) = match case {
                Answerable::Undecodable => {
                    let (_, r) = error_response(&auto[0], &KEY);
                    let r = r.result.expect("a result");
                    ("ErrorResponse", r.status, r.memo)
                }
                _ => response(&auto[0], &KEY),
            };
            assert_eq!(on_status, sent_status, "{case:?}: the status sent");
            assert_eq!(on_memo, sent_memo, "{case:?}: the memo sent");

            let off = Rig::default();
            off.seed_helper_channel(SenderKind::Owner).await;
            let mut protocol = off.build(false, policy, false);
            let events = fail(case, &off, &mut protocol).await;
            let (status, memo, token) = the_failure(&events);
            assert_eq!(
                (status, memo.as_str()),
                (on_status, on_memo.as_str()),
                "{case:?}: the event carries what auto-respond sends"
            );
            assert!(off.sends().is_empty(), "{case:?}: nothing sent when off");
            protocol
                .reject(
                    token.unwrap_or_else(|| panic!("{case:?}: a token")),
                    StatusEnum::try_from(status).expect("a status"),
                    &memo,
                )
                .await
                .expect("the token answers the request");
            let answered = off.sends();
            assert_eq!(answered.len(), 1, "{case:?}: reject answered once");
            assert_eq!(
                off.transport.sent_uris(),
                on.transport.sent_uris(),
                "{case:?}: the same endpoints"
            );
            assert_eq!(
                without_timestamps(&answered[0]),
                without_timestamps(&auto[0]),
                "{case:?}: the same response"
            );
        });
    }
}
