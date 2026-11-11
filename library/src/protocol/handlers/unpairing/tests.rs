// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::Error;
use crate::derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message};
use crate::protocol::builder::DeRecProtocolBuilder;
use crate::protocol::tests::{
    InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
    InMemUserSecretStore, RecordingTransport, run_async,
};
use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel, SecretValue, Share};
use crate::protocol::{
    AutoAcceptPolicy, DeRecChannelStore as _, DeRecEvent, DeRecFlow, DeRecProtocol,
    DeRecSecretStore as _, DeRecShareStore as _, StateItem, StateKey, UnpairAck,
};
use crate::types::{ChannelId, ChannelKey, SharedKey};
use crate::utils::now_secs;
use derec_proto::{
    DeRecMessage, DeRecResult, MessageBody, Protocol, SenderKind, StatusEnum, TransportProtocol,
    UnpairRequestMessage, UnpairResponseMessage,
};
use prost::Message as _;
use std::collections::HashMap;

const SECRET_ID: u64 = 0x0B1D;
/// The owner's channel from before it lost its devices.
const OLD: ChannelId = ChannelId(10);
const OLD_KEY: SharedKey = SharedKey::new([1u8; 32]);
/// The channel the owner re-paired on to recover.
const NEW: ChannelId = ChannelId(20);
const NEW_KEY: SharedKey = SharedKey::new([2u8; 32]);
/// A channel of some other owner, never linked to `NEW`.
const UNLINKED: ChannelId = ChannelId(30);
const UNLINKED_KEY: SharedKey = SharedKey::new([3u8; 32]);

type TestProtocol = DeRecProtocol<
    InMemChannelStore,
    InMemShareStore,
    InMemSecretStore,
    InMemUserSecretStore,
    InMemPersistedStateStore,
    RecordingTransport,
>;

struct HelperRig {
    channels: InMemChannelStore,
    shares: InMemShareStore,
    secrets: InMemSecretStore,
    transport: RecordingTransport,
    protocol: TestProtocol,
}

fn endpoint(uri: &str) -> TransportProtocol {
    TransportProtocol {
        uri: uri.to_owned(),
        protocol: Protocol::Https as i32,
    }
}

async fn seed_owner_channel(
    channels: &mut InMemChannelStore,
    secrets: &mut InMemSecretStore,
    channel_id: ChannelId,
    key: SharedKey,
) {
    channels
        .save(
            SECRET_ID,
            ChannelRecord::Helper(HelperChannel {
                channel_id,
                transports: vec![endpoint("https://owner.example")],
                communication_info: HashMap::new(),
                peer_role: SenderKind::Owner,
                status: ChannelStatus::Paired,
                created_at: now_secs(),
                weight: 1,
            }),
        )
        .await
        .expect("seed owner channel");
    secrets
        .save(SECRET_ID, channel_id, SecretValue::SharedKey(key))
        .await
        .expect("seed owner key");
}

async fn seed_share(shares: &mut InMemShareStore, channel_id: ChannelId, version: u32) {
    shares
        .save(
            SECRET_ID,
            channel_id,
            Share {
                secret_id: SECRET_ID,
                version,
                bytes: vec![version as u8],
                subshares: None,
                threshold: None,
            },
        )
        .await
        .expect("seed share");
}

/// A helper holding an owner's share on `OLD`, re-paired with it on `NEW`
/// and linked. `NEW` holds a share only when `stored_on_new`.
async fn helper_rig(stored_on_new: bool) -> HelperRig {
    let mut channels = InMemChannelStore::default();
    let mut secrets = InMemSecretStore::default();
    let mut shares = InMemShareStore::default();
    seed_owner_channel(&mut channels, &mut secrets, OLD, OLD_KEY).await;
    seed_owner_channel(&mut channels, &mut secrets, NEW, NEW_KEY).await;
    seed_owner_channel(&mut channels, &mut secrets, UNLINKED, UNLINKED_KEY).await;
    channels
        .link_channel(SECRET_ID, OLD, NEW)
        .await
        .expect("link channels");
    seed_share(&mut shares, OLD, 1).await;
    seed_share(&mut shares, UNLINKED, 1).await;
    if stored_on_new {
        seed_share(&mut shares, NEW, 2).await;
    }

    let transport = RecordingTransport::default();
    let protocol = DeRecProtocolBuilder::new(SECRET_ID)
        .with_channel_store(channels.clone())
        .with_share_store(shares.clone())
        .with_secret_store(secrets.clone())
        .with_user_secret_store(InMemUserSecretStore::default())
        .with_transport(transport.clone())
        .with_state_store(InMemPersistedStateStore::default())
        .with_own_transports(["https://helper.example"])
        .with_auto_accept(AutoAcceptPolicy::all())
        .with_auto_respond_on_failure(true)
        .build()
        .expect("test protocol builds");
    HelperRig {
        channels,
        shares,
        secrets,
        transport,
        protocol,
    }
}

fn unpair_request(
    on: ChannelId,
    key: &SharedKey,
    channel_id: u64,
    replica_id: Option<u64>,
) -> Vec<u8> {
    let ts = current_timestamp();
    DeRecMessageBuilder::channel()
        .channel_id(on)
        .timestamp(ts)
        .message_body(MessageBody::UnpairRequest(UnpairRequestMessage {
            memo: String::new(),
            timestamp: Some(ts),
            reply_to_transports: Vec::new(),
            replica_id,
            channel_id,
        }))
        .encrypt(&ChannelKey::new(0, key.clone()))
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec()
}

/// The last unpair response the helper sent, opened under `key`.
fn sent_response(transport: &RecordingTransport, key: &SharedKey) -> (u64, UnpairResponseMessage) {
    let sent = transport.sent_envelopes();
    let envelope =
        DeRecMessage::decode(sent.last().expect("a response is sent").as_slice()).expect("decode");
    match extract_inner_message(&envelope.message, key) {
        Ok(MessageBody::UnpairResponse(response)) => (envelope.channel_id, response),
        other => panic!("expected an unpair response, got {other:?}"),
    }
}

fn status_of(response: &UnpairResponseMessage) -> i32 {
    response.result.as_ref().expect("result").status
}

fn holds_channel(rig: &HelperRig, channel_id: ChannelId) -> bool {
    rig.channels
        .helper_rows
        .lock()
        .unwrap()
        .contains_key(&(SECRET_ID, channel_id.0))
}

fn holds_share(rig: &HelperRig, channel_id: ChannelId) -> bool {
    rig.shares
        .data
        .lock()
        .unwrap()
        .keys()
        .any(|(s, c, _)| *s == SECRET_ID && *c == channel_id.0)
}

fn holds_key(rig: &HelperRig, channel_id: ChannelId) -> bool {
    rig.secrets
        .data
        .lock()
        .unwrap()
        .keys()
        .any(|(s, c, _)| *s == SECRET_ID && *c == channel_id.0)
}

fn unpaired(events: &[DeRecEvent]) -> Vec<ChannelId> {
    events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::Unpaired { channel_id } => Some(*channel_id),
            _ => None,
        })
        .collect()
}

/// An unpair naming the channel it travels on is the ordinary unpair: that
/// channel goes, and the response names it.
#[test]
fn an_unpair_naming_its_own_channel_is_a_normal_unpair() {
    run_async(async {
        let mut rig = helper_rig(true).await;

        let events = rig
            .protocol
            .process(&unpair_request(NEW, &NEW_KEY, NEW.0, None))
            .await
            .expect("processed");

        assert_eq!(unpaired(&events), vec![NEW]);
        assert!(!holds_channel(&rig, NEW));
        assert!(holds_channel(&rig, OLD));
        let (on, response) = sent_response(&rig.transport, &NEW_KEY);
        assert_eq!((on, response.channel_id), (NEW.0, NEW.0));
        assert_eq!(status_of(&response), StatusEnum::Ok as i32);
    });
}

/// A linked unpair drops the named old channel — record, key and shares —
/// and keeps the channel it arrived on, answering there.
#[test]
fn linked_unpair_drops_the_target_and_keeps_the_arrival_channel() {
    run_async(async {
        let mut rig = helper_rig(true).await;

        let events = rig
            .protocol
            .process(&unpair_request(NEW, &NEW_KEY, OLD.0, None))
            .await
            .expect("processed");

        assert_eq!(unpaired(&events), vec![OLD]);
        assert!(!holds_channel(&rig, OLD));
        assert!(!holds_key(&rig, OLD));
        assert!(!holds_share(&rig, OLD));
        assert!(holds_channel(&rig, NEW));
        assert!(holds_key(&rig, NEW));
        assert!(holds_share(&rig, NEW));
        let (on, response) = sent_response(&rig.transport, &NEW_KEY);
        assert_eq!((on, response.channel_id), (NEW.0, OLD.0));
        assert_eq!(status_of(&response), StatusEnum::Ok as i32);
    });
}

/// Only a channel linked to the arrival channel can be named: anything else
/// would let one owner unpair another's channel.
#[test]
fn linked_unpair_of_an_unlinked_channel_is_refused() {
    run_async(async {
        let mut rig = helper_rig(true).await;

        let events = rig
            .protocol
            .process(&unpair_request(NEW, &NEW_KEY, UNLINKED.0, None))
            .await
            .expect("processed");

        assert!(unpaired(&events).is_empty());
        assert!(holds_channel(&rig, UNLINKED));
        assert!(holds_share(&rig, UNLINKED));
        let (_, response) = sent_response(&rig.transport, &NEW_KEY);
        assert_eq!(response.channel_id, UNLINKED.0);
        assert_eq!(status_of(&response), StatusEnum::Fail as i32);
    });
}

/// A linked unpair is owner-originated only, so it never names a member: one
/// that does is taken for a replica removal, and refused as one on a helper
/// channel.
#[test]
fn linked_unpair_with_a_replica_id_is_refused() {
    run_async(async {
        let mut rig = helper_rig(true).await;

        let outcome = rig
            .protocol
            .process(&unpair_request(NEW, &NEW_KEY, OLD.0, Some(7)))
            .await;

        assert!(outcome.is_err());
        assert!(holds_channel(&rig, OLD));
        assert!(holds_share(&rig, OLD));
    });
}

/// Until a round is stored on the arrival channel, the old channel may hold
/// this helper's only share for the owner, so it is not dropped.
#[test]
fn linked_unpair_before_a_share_is_stored_on_the_arrival_channel_is_refused() {
    run_async(async {
        let mut rig = helper_rig(false).await;

        let events = rig
            .protocol
            .process(&unpair_request(NEW, &NEW_KEY, OLD.0, None))
            .await
            .expect("processed");

        assert!(unpaired(&events).is_empty());
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, DeRecEvent::ActionRequired { .. }))
        );
        assert!(holds_channel(&rig, OLD));
        assert!(holds_share(&rig, OLD));
        let (_, response) = sent_response(&rig.transport, &NEW_KEY);
        assert_eq!(status_of(&response), StatusEnum::Fail as i32);
    });
}

/// A linked unpair retires an older channel, never a newer one: a device
/// still holding the old channel's key cannot drop the channel the owner
/// recovered on, which holds a newer version than the old one.
#[test]
fn linked_unpair_naming_a_newer_channel_is_refused() {
    run_async(async {
        let mut rig = helper_rig(true).await;

        let events = rig
            .protocol
            .process(&unpair_request(OLD, &OLD_KEY, NEW.0, None))
            .await
            .expect("processed");

        assert!(unpaired(&events).is_empty());
        assert!(holds_channel(&rig, NEW));
        assert!(holds_share(&rig, NEW));
        let (_, response) = sent_response(&rig.transport, &OLD_KEY);
        assert_eq!(status_of(&response), StatusEnum::Fail as i32);
    });
}

/// A retried linked unpair is answered the same way once the named channel
/// is gone, whether or not the store kept the link along with it.
#[test]
fn a_repeated_linked_unpair_is_answered_ok() {
    run_async(async {
        let mut rig = helper_rig(true).await;
        rig.protocol
            .process(&unpair_request(NEW, &NEW_KEY, OLD.0, None))
            .await
            .expect("first processed");
        // A store may drop a channel's links with the channel itself.
        rig.channels.links.lock().unwrap().clear();

        let events = rig
            .protocol
            .process(&unpair_request(NEW, &NEW_KEY, OLD.0, None))
            .await
            .expect("second processed");

        assert_eq!(unpaired(&events), vec![OLD]);
        let (_, response) = sent_response(&rig.transport, &NEW_KEY);
        assert_eq!(status_of(&response), StatusEnum::Ok as i32);
    });
}

/// `0` is never a channel id, so an unpair naming it (or omitting the field,
/// which decodes the same) is malformed and drops nothing.
#[test]
fn an_unpair_naming_channel_zero_is_malformed() {
    run_async(async {
        let mut rig = helper_rig(true).await;

        let events = rig
            .protocol
            .process(&unpair_request(NEW, &NEW_KEY, 0, None))
            .await
            .expect("processed");

        assert!(unpaired(&events).is_empty());
        assert!(holds_channel(&rig, NEW));
        assert!(holds_channel(&rig, OLD));
        let (_, response) = sent_response(&rig.transport, &NEW_KEY);
        assert_eq!(status_of(&response), StatusEnum::FormatError as i32);
    });
}

// ---------------- Owner side ----------------

/// A second old channel, for two linked unpairs in flight on `NEW`.
const OLDER: ChannelId = ChannelId(11);

struct OwnerRig {
    channels: InMemChannelStore,
    state: InMemPersistedStateStore,
    transport: RecordingTransport,
    protocol: TestProtocol,
}

async fn seed_helper_channel(
    channels: &mut InMemChannelStore,
    secrets: &mut InMemSecretStore,
    channel_id: ChannelId,
    key: SharedKey,
    peer_role: SenderKind,
) {
    channels
        .save(
            SECRET_ID,
            ChannelRecord::Helper(HelperChannel {
                channel_id,
                transports: vec![endpoint("https://helper.example")],
                communication_info: HashMap::new(),
                peer_role,
                status: ChannelStatus::Paired,
                created_at: now_secs(),
                weight: 1,
            }),
        )
        .await
        .expect("seed helper channel");
    secrets
        .save(SECRET_ID, channel_id, SecretValue::SharedKey(key))
        .await
        .expect("seed helper key");
}

/// A restored owner paired with its helper on `NEW` only; `OLD` and `OLDER`
/// are channels it no longer holds. On `UNLINKED` this device is the helper.
async fn owner_rig(ack: UnpairAck) -> OwnerRig {
    let mut channels = InMemChannelStore::default();
    let mut secrets = InMemSecretStore::default();
    seed_helper_channel(
        &mut channels,
        &mut secrets,
        NEW,
        NEW_KEY,
        SenderKind::Helper,
    )
    .await;
    seed_helper_channel(
        &mut channels,
        &mut secrets,
        UNLINKED,
        UNLINKED_KEY,
        SenderKind::Owner,
    )
    .await;

    let state = InMemPersistedStateStore::default();
    let transport = RecordingTransport::default();
    let protocol = DeRecProtocolBuilder::new(SECRET_ID)
        .with_channel_store(channels.clone())
        .with_share_store(InMemShareStore::default())
        .with_secret_store(secrets)
        .with_user_secret_store(InMemUserSecretStore::default())
        .with_transport(transport.clone())
        .with_state_store(state.clone())
        .with_own_transports(["https://owner.example"])
        .with_unpair_ack(ack)
        .build()
        .expect("test protocol builds");
    OwnerRig {
        channels,
        state,
        transport,
        protocol,
    }
}

fn linked_unpair(channel_id: ChannelId, target: ChannelId) -> DeRecFlow {
    DeRecFlow::Unpair {
        channel_id,
        memo: None,
        linked_channel_id: Some(target),
    }
}

/// The last unpair request the owner sent, with the channel it travelled on.
fn sent_request(transport: &RecordingTransport, key: &SharedKey) -> (u64, UnpairRequestMessage) {
    let sent = transport.sent_envelopes();
    let envelope =
        DeRecMessage::decode(sent.last().expect("a request is sent").as_slice()).expect("decode");
    match extract_inner_message(&envelope.message, key) {
        Ok(MessageBody::UnpairRequest(request)) => (envelope.channel_id, request),
        other => panic!("expected an unpair request, got {other:?}"),
    }
}

fn unpair_response(
    on: ChannelId,
    key: &SharedKey,
    named: ChannelId,
    status: StatusEnum,
) -> Vec<u8> {
    let ts = current_timestamp();
    DeRecMessageBuilder::channel()
        .channel_id(on)
        .timestamp(ts)
        .message_body(MessageBody::UnpairResponse(UnpairResponseMessage {
            result: Some(DeRecResult {
                status: status as i32,
                memo: String::new(),
            }),
            timestamp: Some(ts),
            channel_id: named.0,
        }))
        .encrypt(&ChannelKey::new(0, key.clone()))
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec()
}

fn pending_on(rig: &OwnerRig, channel_id: ChannelId) -> bool {
    rig.state
        .data
        .lock()
        .unwrap()
        .contains_key(&(SECRET_ID, StateKey::PendingUnpair { channel_id }))
}

fn status_on(rig: &OwnerRig, channel_id: ChannelId) -> Option<ChannelStatus> {
    rig.channels
        .helper_rows
        .lock()
        .unwrap()
        .get(&(SECRET_ID, channel_id.0))
        .map(|h| h.status)
}

fn started(events: &[DeRecEvent]) -> Vec<ChannelId> {
    events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::UnpairStarted { channel_id, .. } => Some(*channel_id),
            _ => None,
        })
        .collect()
}

/// An ordinary unpair names the channel it travels on.
#[test]
fn a_normal_unpair_sends_its_own_channel_id() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;

        rig.protocol
            .start(DeRecFlow::Unpair {
                channel_id: NEW,
                memo: None,
                linked_channel_id: None,
            })
            .await
            .expect("started");

        let (on, request) = sent_request(&rig.transport, &NEW_KEY);
        assert_eq!((on, request.channel_id), (NEW.0, NEW.0));
    });
}

/// A linked unpair travels on the kept channel and is pending on the channel
/// it names; the kept channel stays usable meanwhile.
#[test]
fn linked_unpair_is_sent_on_the_channel_and_pending_on_the_target() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;

        let events = rig
            .protocol
            .start(linked_unpair(NEW, OLD))
            .await
            .expect("started");

        assert_eq!(started(&events), vec![OLD]);
        assert!(pending_on(&rig, OLD));
        assert!(!pending_on(&rig, NEW));
        assert_eq!(status_on(&rig, NEW), Some(ChannelStatus::Paired));
        let (on, request) = sent_request(&rig.transport, &NEW_KEY);
        assert_eq!((on, request.channel_id), (NEW.0, OLD.0));
    });
}

/// The helper's answer completes the unpair of the channel it names, never
/// the one it travels on.
#[test]
fn linked_unpair_response_completes_its_own_target() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;
        rig.protocol
            .start(linked_unpair(NEW, OLD))
            .await
            .expect("started");

        let events = rig
            .protocol
            .process(&unpair_response(NEW, &NEW_KEY, OLD, StatusEnum::Ok))
            .await
            .expect("processed");

        assert_eq!(unpaired(&events), vec![OLD]);
        assert!(!pending_on(&rig, OLD));
        assert_eq!(status_on(&rig, NEW), Some(ChannelStatus::Paired));
    });
}

/// Two linked unpairs on one channel are told apart by the channel each
/// answer names.
#[test]
fn two_linked_unpairs_on_one_channel_resolve_independently() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;
        rig.protocol
            .start(linked_unpair(NEW, OLD))
            .await
            .expect("first started");
        rig.protocol
            .start(linked_unpair(NEW, OLDER))
            .await
            .expect("second started");

        let events = rig
            .protocol
            .process(&unpair_response(NEW, &NEW_KEY, OLDER, StatusEnum::Ok))
            .await
            .expect("processed");

        assert_eq!(unpaired(&events), vec![OLDER]);
        assert!(!pending_on(&rig, OLDER));
        assert!(pending_on(&rig, OLD));
    });
}

/// A refusal names the channel the owner asked to unpair.
#[test]
fn linked_unpair_rejection_names_the_target() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;
        rig.protocol
            .start(linked_unpair(NEW, OLD))
            .await
            .expect("started");

        let events = rig
            .protocol
            .process(&unpair_response(NEW, &NEW_KEY, OLD, StatusEnum::Fail))
            .await
            .expect("processed");

        assert!(events.iter().any(|e| matches!(
            e,
            DeRecEvent::UnpairRejected { channel_id, .. } if *channel_id == OLD
        )));
        assert_eq!(status_on(&rig, NEW), Some(ChannelStatus::Paired));
    });
}

/// Without an acknowledgement the named channel is reported unpaired as the
/// request goes out, and the kept channel stays.
#[test]
fn linked_unpair_without_ack_reports_unpaired_at_once() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::NotRequired).await;

        let events = rig
            .protocol
            .start(linked_unpair(NEW, OLD))
            .await
            .expect("started");

        assert_eq!(started(&events), vec![OLD]);
        assert_eq!(unpaired(&events), vec![OLD]);
        assert_eq!(status_on(&rig, NEW), Some(ChannelStatus::Paired));
    });
}

/// Naming the channel itself is an ordinary unpair spelled differently, and
/// refused so the two cannot be confused.
#[test]
fn linked_unpair_of_its_own_channel_is_invalid_input() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;

        let outcome = rig.protocol.start(linked_unpair(NEW, NEW)).await;

        assert!(matches!(outcome, Err(Error::InvalidInput(_))));
        assert!(rig.transport.sent_envelopes().is_empty());
    });
}

/// Only an owner sends a linked unpair, so it must travel on a channel whose
/// peer is a helper.
#[test]
fn linked_unpair_on_a_non_helper_channel_is_refused() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;

        let outcome = rig.protocol.start(linked_unpair(UNLINKED, OLD)).await;

        assert!(matches!(outcome, Err(Error::RoleMismatch { .. })));
        assert!(rig.transport.sent_envelopes().is_empty());
    });
}

/// An unanswered linked unpair times out on the channel it names.
#[test]
fn a_linked_unpair_times_out_on_its_target() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;
        rig.protocol
            .start(linked_unpair(NEW, OLD))
            .await
            .expect("started");
        rig.state.data.lock().unwrap().insert(
            (SECRET_ID, StateKey::PendingUnpair { channel_id: OLD }),
            StateItem::PendingUnpair {
                channel_id: OLD,
                started_at: 0,
            },
        );

        let events = rig.protocol.tick().await;

        assert_eq!(unpaired(&events), vec![OLD]);
        assert_eq!(status_on(&rig, NEW), Some(ChannelStatus::Paired));
    });
}

/// Another helper's channel, so an answer can arrive somewhere it was not
/// asked for.
const OTHER: ChannelId = ChannelId(40);
const OTHER_KEY: SharedKey = SharedKey::new([4u8; 32]);

/// An answer naming a channel this device holds settles only the unpair sent
/// on that channel: another helper cannot complete or refuse it.
#[test]
fn an_answer_from_another_channel_does_not_settle_an_unpair() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;
        let mut secrets = InMemSecretStore::default();
        let mut channels = rig.channels.clone();
        seed_helper_channel(
            &mut channels,
            &mut secrets,
            OTHER,
            OTHER_KEY,
            SenderKind::Helper,
        )
        .await;
        rig.protocol
            .secret_store
            .save(SECRET_ID, OTHER, SecretValue::SharedKey(OTHER_KEY))
            .await
            .expect("seed other key");
        rig.protocol
            .start(DeRecFlow::Unpair {
                channel_id: NEW,
                memo: None,
                linked_channel_id: None,
            })
            .await
            .expect("started");

        let events = rig
            .protocol
            .process(&unpair_response(OTHER, &OTHER_KEY, NEW, StatusEnum::Ok))
            .await
            .expect("processed");

        assert!(unpaired(&events).is_empty());
        assert!(pending_on(&rig, NEW));
        assert_eq!(status_on(&rig, NEW), Some(ChannelStatus::Unpairing));
    });
}

/// `0` is never a channel id.
#[test]
fn linked_unpair_naming_channel_zero_is_invalid_input() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;

        let outcome = rig.protocol.start(linked_unpair(NEW, ChannelId(0))).await;

        assert!(matches!(outcome, Err(Error::InvalidInput(_))));
        assert!(rig.transport.sent_envelopes().is_empty());
    });
}

/// A linked unpair retires a channel this device no longer holds; naming one
/// it still uses would take that helper out of every flow on the strength of
/// another helper's answer.
#[test]
fn linked_unpair_naming_a_held_channel_is_invalid_input() {
    run_async(async {
        let mut rig = owner_rig(UnpairAck::Required).await;
        let mut secrets = InMemSecretStore::default();
        let mut channels = rig.channels.clone();
        seed_helper_channel(
            &mut channels,
            &mut secrets,
            OTHER,
            OTHER_KEY,
            SenderKind::Helper,
        )
        .await;

        let outcome = rig.protocol.start(linked_unpair(NEW, OTHER)).await;

        assert!(matches!(outcome, Err(Error::InvalidInput(_))));
        assert_eq!(status_on(&rig, OTHER), Some(ChannelStatus::Paired));
        assert!(rig.transport.sent_envelopes().is_empty());
    });
}
