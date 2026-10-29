// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::*;
use derec_proto::{
    GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, PrePairRequestMessage,
    StoreShareRequestMessage, UnpairRequestMessage, UpdateChannelInfoRequestMessage,
    VerifyShareRequestMessage,
};

fn channel_request(request: ChannelRequest) -> PendingAction {
    PendingAction::request(ChannelId(1), 0, request)
        .sealed_with(&crate::types::SharedKey::new([0; 32]))
}

fn store_share_action() -> PendingAction {
    channel_request(ChannelRequest::StoreShare(
        StoreShareRequestMessage::default(),
    ))
}

fn verify_share_action() -> PendingAction {
    channel_request(ChannelRequest::VerifyShare(
        VerifyShareRequestMessage::default(),
    ))
}

fn discovery_action() -> PendingAction {
    channel_request(ChannelRequest::Discovery(
        GetSecretIdsVersionsRequestMessage::default(),
    ))
}

fn get_share_action() -> PendingAction {
    channel_request(ChannelRequest::GetShare(GetShareRequestMessage::default()))
}

fn unpair_action() -> PendingAction {
    channel_request(ChannelRequest::Unpair(UnpairRequestMessage::default()))
}

fn update_channel_info_action() -> PendingAction {
    channel_request(ChannelRequest::UpdateChannelInfo(
        UpdateChannelInfoRequestMessage::default(),
    ))
}

fn pre_pair_action() -> PendingAction {
    PendingAction::pre_pair(ChannelId(1), 0, PrePairRequestMessage::default())
}

fn respond_to_failure_action() -> PendingAction {
    PendingAction::failure(
        ChannelId(1),
        5,
        ReplyTarget {
            channel_id: ChannelId(1),
            endpoints: Vec::new(),
        },
        FailedRequest::StoreShare(StoreShareRequestMessage {
            share: vec![0xAB; 4],
            ..Default::default()
        }),
    )
    .sealed_with(&crate::types::SharedKey::new([0; 32]))
}

#[test]
fn pending_action_kind_round_trips_each_variant() {
    assert_eq!(store_share_action().kind(), PendingActionKind::StoreShare);
    assert_eq!(verify_share_action().kind(), PendingActionKind::VerifyShare);
    assert_eq!(discovery_action().kind(), PendingActionKind::Discovery);
    assert_eq!(get_share_action().kind(), PendingActionKind::GetShare);
    assert_eq!(unpair_action().kind(), PendingActionKind::Unpair);
    assert_eq!(
        update_channel_info_action().kind(),
        PendingActionKind::UpdateChannelInfo
    );
    assert_eq!(pre_pair_action().kind(), PendingActionKind::PrePair);
    assert_eq!(
        respond_to_failure_action().kind(),
        PendingActionKind::Failed
    );
}

/// A failed request is only ever rejected, so no policy, however
/// permissive, routes it to `accept`.
#[test]
fn auto_accept_never_allows_a_failed_request() {
    assert!(!AutoAcceptPolicy::all().allows(&respond_to_failure_action()));
    assert!(!AutoAcceptPolicy::default().allows(&respond_to_failure_action()));
}

/// A copy kept before `accept` is the same token, so it can still be
/// passed to `reject`.
#[test]
fn a_cloned_action_keeps_its_trace_id_and_kind() {
    let action = respond_to_failure_action();
    let copy = action.clone();
    assert_eq!(copy.kind(), action.kind());
    assert_eq!(copy.trace_id(), 5);
}

/// The token's `Debug` output names the kind and channel, never the
/// peer-supplied request.
#[test]
fn debug_keeps_failed_request_contents_out_of_logs() {
    let rendered = format!("{:?}", respond_to_failure_action());
    assert!(rendered.contains("Failed"), "{rendered}");
    assert!(!rendered.contains("171"), "{rendered}");
    assert_eq!(
        format!(
            "{:?}",
            FailedRequest::StoreShare(StoreShareRequestMessage {
                share: vec![0xAB; 4],
                ..Default::default()
            })
        ),
        "StoreShare"
    );
}

#[test]
fn auto_accept_policy_default_is_all_false() {
    let p = AutoAcceptPolicy::default();
    assert!(!p.pairing);
    assert!(!p.pre_pair);
    assert!(!p.store_share);
    assert!(!p.verify_share);
    assert!(!p.discovery);
    assert!(!p.get_share);
    assert!(!p.unpair);
    assert!(!p.update_channel_info);
}

#[test]
fn auto_accept_policy_all_is_all_true() {
    let p = AutoAcceptPolicy::all();
    assert!(p.pairing);
    assert!(p.pre_pair);
    assert!(p.store_share);
    assert!(p.verify_share);
    assert!(p.discovery);
    assert!(p.get_share);
    assert!(p.unpair);
    assert!(p.update_channel_info);
}

#[test]
fn auto_accept_policy_allows_dispatches_per_flow() {
    let only_store = AutoAcceptPolicy {
        store_share: true,
        ..Default::default()
    };
    assert!(only_store.allows(&store_share_action()));
    assert!(!only_store.allows(&verify_share_action()));
    assert!(!only_store.allows(&discovery_action()));
    assert!(!only_store.allows(&get_share_action()));
    assert!(!only_store.allows(&unpair_action()));
    assert!(!only_store.allows(&update_channel_info_action()));
    assert!(!only_store.allows(&pre_pair_action()));

    let none = AutoAcceptPolicy::default();
    assert!(!none.allows(&store_share_action()));

    let all = AutoAcceptPolicy::all();
    assert!(all.allows(&store_share_action()));
    assert!(all.allows(&verify_share_action()));
    assert!(all.allows(&discovery_action()));
    assert!(all.allows(&get_share_action()));
    assert!(all.allows(&unpair_action()));
    assert!(all.allows(&update_channel_info_action()));
    assert!(all.allows(&pre_pair_action()));
}

#[cfg(feature = "ffi")]
mod golden {
    //! Holds `library/tests/fixtures/events_golden.json` to the wire shape.
    //!
    //! The fixture carries one sample of every [`Event`] variant with every
    //! optional field present and every value distinct from its type's default,
    //! so an SDK that drops a field, defaults one, or reads it under the wrong
    //! name cannot reproduce the sample. Each SDK decodes the fixture into its
    //! own event types and checks it got every field back.
    //!
    //! [`variant_name`] matches exhaustively, so a new variant fails to compile
    //! here until it has a sample. The samples are then held to the event list in
    //! `enums.json`, which the enum fixture keeps complete against `DeRecEvent`.
    //!
    //! When the wire shape changes on purpose, regenerate with
    //! `DEREC_BLESS_FIXTURES=1 cargo test -p derec-library --features ffi --lib events::tests::golden`
    //! and update every SDK that the change breaks.

    use std::collections::HashMap;

    use crate::protocol::events::wire::{
        DiscoveredSecret, DiscoveredVersion, Endpoint, Event, Helper, Replica, ReplicasWire,
        SecretWire, Share, UserSecret,
    };

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/events_golden.json"
    );

    fn variant_name(event: &Event) -> &'static str {
        match event {
            Event::PairingCompleted { .. } => "PairingCompleted",
            Event::ReplicaPaired { .. } => "ReplicaPaired",
            Event::ReplicaSecretReceived { .. } => "ReplicaSecretReceived",
            Event::ReplicaSecretInstalled { .. } => "ReplicaSecretInstalled",
            Event::ReplicaVersionConflict { .. } => "ReplicaVersionConflict",
            Event::ReplicaSecretRefused { .. } => "ReplicaSecretRefused",
            Event::ReplicaSecretAcked { .. } => "ReplicaSecretAcked",
            Event::ReplicaSyncRejected { .. } => "ReplicaSyncRejected",
            Event::ReplicaSyncFailed { .. } => "ReplicaSyncFailed",
            Event::ReplicaRemoved { .. } => "ReplicaRemoved",
            Event::ReplicaSourceChanged { .. } => "ReplicaSourceChanged",
            Event::SelfRemovedFromGroup { .. } => "SelfRemovedFromGroup",
            Event::ReplicaDiscoveryComplete { .. } => "ReplicaDiscoveryComplete",
            Event::ReplicaSyncComplete { .. } => "ReplicaSyncComplete",
            Event::ShareStored { .. } => "ShareStored",
            Event::ShareRefused { .. } => "ShareRefused",
            Event::ShareConfirmed { .. } => "ShareConfirmed",
            Event::ShareRejected { .. } => "ShareRejected",
            Event::SharingComplete { .. } => "SharingComplete",
            Event::ShareVerified { .. } => "ShareVerified",
            Event::ShareVerifyInvalid { .. } => "ShareVerifyInvalid",
            Event::ShareVerifyRejected { .. } => "ShareVerifyRejected",
            Event::SecretsDiscovered { .. } => "SecretsDiscovered",
            Event::RecoveryShareReceived { .. } => "RecoveryShareReceived",
            Event::RecoveryShareError { .. } => "RecoveryShareError",
            Event::RecoveryShareRefused { .. } => "RecoveryShareRefused",
            Event::RecoveryShareCorrupted { .. } => "RecoveryShareCorrupted",
            Event::SecretRecovered { .. } => "SecretRecovered",
            Event::Unpaired { .. } => "Unpaired",
            Event::UnpairRejected { .. } => "UnpairRejected",
            Event::PrePairRejected { .. } => "PrePairRejected",
            Event::ChannelInfoUpdated { .. } => "ChannelInfoUpdated",
            Event::ChannelInfoUpdateRejected { .. } => "ChannelInfoUpdateRejected",
            Event::ActionRequired { .. } => "ActionRequired",
            Event::AutoAccepted { .. } => "AutoAccepted",
            Event::RequestFailed { .. } => "RequestFailed",
            Event::ErrorResponseReceived { .. } => "ErrorResponseReceived",
            Event::PairingRefused { .. } => "PairingRefused",
            Event::NoOp => "NoOp",
            Event::MessageIgnored { .. } => "MessageIgnored",
            Event::PeerNotRestored { .. } => "PeerNotRestored",
            Event::PairingStarted { .. } => "PairingStarted",
            Event::DiscoveryStarted { .. } => "DiscoveryStarted",
            Event::DiscoveryFailed { .. } => "DiscoveryFailed",
            Event::ProtectSecretStarted { .. } => "ProtectSecretStarted",
            Event::ProtectSecretFailed { .. } => "ProtectSecretFailed",
            Event::VerifySharesStarted { .. } => "VerifySharesStarted",
            Event::VerifySharesFailed { .. } => "VerifySharesFailed",
            Event::RecoverSecretStarted { .. } => "RecoverSecretStarted",
            Event::RecoverSecretFailed { .. } => "RecoverSecretFailed",
            Event::UnpairFailed { .. } => "UnpairFailed",
            Event::UnpairStarted { .. } => "UnpairStarted",
            Event::UpdateChannelInfoStarted { .. } => "UpdateChannelInfoStarted",
            Event::UpdateChannelInfoFailed { .. } => "UpdateChannelInfoFailed",
        }
    }

    fn info(key: &str, value: &str) -> HashMap<String, String> {
        HashMap::from([(key.to_owned(), value.to_owned())])
    }

    fn endpoint(uri: &str, protocol: &'static str) -> Endpoint {
        Endpoint {
            uri: uri.to_owned(),
            protocol,
        }
    }

    fn secret() -> SecretWire {
        SecretWire {
            helpers: vec![Helper {
                channel_id: "7001".into(),
                transports: vec![endpoint("https://helper.example/derec", "https")],
                shared_key: vec![0x11, 0x12, 0x13],
                communication_info: info("name", "Helper"),
                weight: 2,
            }],
            secrets: vec![UserSecret {
                id: vec![0x21, 0x22],
                name: "wallet".into(),
                data: vec![0x31, 0x32, 0x33],
            }],
            replicas: Some(ReplicasWire {
                channel_id: "7002".into(),
                members: vec![Replica {
                    replica_id: "7003".into(),
                    transports: vec![endpoint("grpc://replica.example:443", "grpc")],
                    role: "Source".into(),
                    communication_info: info("device", "Laptop"),
                }],
                shared_key: vec![0x41, 0x42],
            }),
            threshold: Some(3),
        }
    }

    fn shares() -> Vec<Share> {
        vec![Share {
            channel_id: "7004".into(),
            committed_share: vec![0x51, 0x52],
        }]
    }

    fn samples() -> Vec<Event> {
        vec![
            Event::PairingCompleted {
                channel_id: "1001".into(),
                pairing_channel_id: "1002".into(),
                kind: 2,
                peer_communication_info: info("name", "Peer"),
            },
            Event::ReplicaPaired {
                channel_id: "1003".into(),
                peer_replica_id: "1004".into(),
            },
            Event::ReplicaSecretReceived {
                channel_id: "1005".into(),
                from_replica_id: "1006".into(),
                author_replica_id: Some("1007".into()),
                secret_id: "1008".into(),
                version: 4,
                secret: secret(),
                shares: shares(),
            },
            Event::ReplicaSecretInstalled {
                channel_id: "1009".into(),
                from_replica_id: "1010".into(),
                author_replica_id: None,
                secret_id: "1011".into(),
                version: 5,
                secret: secret(),
                shares: shares(),
            },
            Event::ReplicaVersionConflict {
                channel_id: "1012".into(),
                from_replica_id: "1013".into(),
                secret_id: "1014".into(),
                version: 6,
                held_author_replica_id: Some("1015".into()),
                incoming_author_replica_id: None,
                secret: secret(),
            },
            Event::ReplicaSecretRefused {
                channel_id: "1016".into(),
                from_replica_id: "1017".into(),
                secret_id: "1018".into(),
                version: 7,
                status: 3,
                memo: "replica refused".into(),
            },
            Event::ReplicaSecretAcked {
                channel_id: "1019".into(),
                from_replica_id: "1020".into(),
                secret_id: "1021".into(),
                version: 8,
                status: 1,
                memo: "replica acked".into(),
            },
            Event::ReplicaSyncRejected {
                replica_id: "1022".into(),
                secret_id: "1023".into(),
                version: 9,
                status: 4,
                memo: "sync rejected".into(),
            },
            Event::ReplicaSyncFailed {
                replica_id: "1024".into(),
                version: 10,
                reason: "sync failed".into(),
            },
            Event::ReplicaRemoved {
                replica_id: "1025".into(),
            },
            Event::ReplicaSourceChanged {
                replica_id: "1026".into(),
            },
            Event::SelfRemovedFromGroup { version: 11 },
            Event::ReplicaDiscoveryComplete {
                local_version: 12,
                group_version: 13,
                fetched_from: Some("1027".into()),
            },
            Event::ReplicaSyncComplete {
                version: 14,
                synced: vec!["1028".into()],
                behind: vec!["1029".into()],
            },
            Event::ShareStored {
                channel_id: "1030".into(),
                version: 15,
            },
            Event::ShareRefused {
                channel_id: "1031".into(),
                version: 16,
                status: 5,
                memo: "share refused".into(),
            },
            Event::ShareConfirmed {
                channel_id: "1032".into(),
                version: 17,
            },
            Event::ShareRejected {
                channel_id: "1033".into(),
                version: 18,
                status: 6,
                memo: "share rejected".into(),
            },
            Event::SharingComplete {
                version: 19,
                confirmed_count: 3,
                failed_count: 1,
                threshold_met: true,
            },
            Event::ShareVerified {
                channel_id: "1034".into(),
                version: 20,
                subshares: Some(2),
                threshold: Some(3),
            },
            Event::ShareVerifyInvalid {
                channel_id: "1035".into(),
                version: 21,
            },
            Event::ShareVerifyRejected {
                channel_id: "1036".into(),
                version: 22,
                status: 7,
                memo: "verify rejected".into(),
            },
            Event::SecretsDiscovered {
                channel_id: "1037".into(),
                secrets: vec![DiscoveredSecret {
                    secret_id: "1038".into(),
                    versions: vec![DiscoveredVersion {
                        version: 23,
                        description: "first".into(),
                    }],
                }],
            },
            Event::RecoveryShareReceived {
                channel_id: "1039".into(),
                shares_received: 2,
            },
            Event::RecoveryShareError {
                channel_id: "1040".into(),
                shares_received: 1,
                error: "share error".into(),
            },
            Event::RecoveryShareRefused {
                channel_id: "1041".into(),
                version: 24,
                status: 8,
                memo: "recovery refused".into(),
            },
            Event::RecoveryShareCorrupted {
                channel_id: "1042".into(),
                version: 25,
                reason: "InvalidProof".into(),
            },
            Event::SecretRecovered { secret: secret() },
            Event::Unpaired {
                channel_id: "1043".into(),
            },
            Event::UnpairRejected {
                channel_id: "1044".into(),
                status: 9,
                memo: "unpair rejected".into(),
            },
            Event::PrePairRejected {
                channel_id: "1045".into(),
                status: 10,
                memo: "prepair rejected".into(),
            },
            Event::ChannelInfoUpdated {
                channel_id: "1046".into(),
            },
            Event::ChannelInfoUpdateRejected {
                channel_id: "1047".into(),
                status: 11,
                memo: "update rejected".into(),
            },
            Event::ActionRequired {
                channel_id: "1048".into(),
                action: vec![0x61, 0x62, 0x63],
                action_kind: "StoreShare".into(),
                peer_communication_info: info("name", "Owner"),
                sender_kind: Some(1),
                version: Some(26),
                share_description: Some("backup".into()),
                share_secret_id: Some("1049".into()),
                trace_id: "1050".into(),
                share_size: Some(4096),
                unpair_memo: Some("goodbye".into()),
                updated_communication_info: Some(info("name", "Renamed")),
                updated_transports: vec![endpoint("https://moved.example/derec", "https")],
            },
            Event::AutoAccepted {
                channel_id: "1051".into(),
                action_kind: "Pairing".into(),
            },
            Event::RequestFailed {
                channel_id: "1052".into(),
                action_kind: "VerifyShare".into(),
                responded: true,
                status: 12,
                memo: "request could not be processed".into(),
                error_code: "store_error".into(),
                message: "share store unavailable".into(),
                action: Some(vec![0x71, 0x72]),
            },
            Event::ErrorResponseReceived {
                channel_id: "1053".into(),
                status: 13,
                memo: "peer error".into(),
            },
            Event::PairingRefused {
                channel_id: "1054".into(),
                status: 14,
                memo: "pairing refused".into(),
                error_code: "incompatible_parameter_range".into(),
                message: "ranges do not overlap".into(),
            },
            Event::NoOp,
            Event::MessageIgnored {
                channel_id: "1055".into(),
                reason: "StaleResponse".into(),
                trace_id: "1056".into(),
            },
            Event::PeerNotRestored {
                channel_id: "1057".into(),
                replica_id: Some("1058".into()),
                reason: "NoTransports".into(),
            },
            Event::PairingStarted {
                channel_id: "1059".into(),
                kind: 1,
                trace_id: "1060".into(),
            },
            Event::DiscoveryStarted {
                channel_id: "1061".into(),
                trace_id: "1062".into(),
            },
            Event::DiscoveryFailed {
                channel_id: "1063".into(),
                error: "discovery failed".into(),
            },
            Event::ProtectSecretStarted {
                channel_id: "1064".into(),
                version: 27,
                trace_id: "1065".into(),
                weight: 2,
            },
            Event::ProtectSecretFailed {
                channel_id: "1066".into(),
                version: 28,
                error: "protect failed".into(),
                weight: 3,
            },
            Event::VerifySharesStarted {
                channel_id: "1067".into(),
                version: 29,
                trace_id: "1068".into(),
            },
            Event::VerifySharesFailed {
                channel_id: "1069".into(),
                version: 30,
                reason: "NoProof".into(),
                error: "no proof".into(),
            },
            Event::RecoverSecretStarted {
                channel_id: "1070".into(),
                version: 31,
                trace_id: "1071".into(),
            },
            Event::RecoverSecretFailed {
                channel_id: "1072".into(),
                version: 32,
                error: "recover failed".into(),
            },
            Event::UnpairFailed {
                channel_id: "1073".into(),
                error: "unpair failed".into(),
            },
            Event::UnpairStarted {
                channel_id: "1074".into(),
                trace_id: "1075".into(),
            },
            Event::UpdateChannelInfoStarted {
                channel_id: "1076".into(),
                trace_id: "1077".into(),
            },
            Event::UpdateChannelInfoFailed {
                channel_id: "1078".into(),
                error: "update failed".into(),
            },
        ]
    }

    fn generated() -> serde_json::Value {
        let events: Vec<serde_json::Value> = samples()
            .iter()
            .map(|e| serde_json::to_value(e).expect("an event serializes"))
            .collect();
        serde_json::json!({
            "$schema_note": "One sample of every event the core emits, as the FFI delivers it (JSON) and the WASM bridge mirrors it (byte fields become Uint8Array, a null id stays null). Every optional field is present and every value differs from its type's default, except where a sample shows the null form of an optional id. Rust generates this file (library/src/protocol/events/tests.rs); every SDK decodes each entry into its own event type and checks every field survives. Do not edit by hand.",
            "events": events,
        })
    }

    #[test]
    fn the_events_golden_fixture_matches_the_wire_shape() {
        let generated = generated();
        if std::env::var_os("DEREC_BLESS_FIXTURES").is_some() {
            let text = serde_json::to_string_pretty(&generated).expect("fixture serializes") + "\n";
            std::fs::write(FIXTURE, text).expect("fixture is writable");
            return;
        }
        let checked_in: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(FIXTURE)
                .expect("events_golden.json exists; regenerate with DEREC_BLESS_FIXTURES=1"),
        )
        .expect("events_golden.json is valid JSON");
        assert_eq!(
            checked_in, generated,
            "events_golden.json is out of step with the wire shape; regenerate with \
         DEREC_BLESS_FIXTURES=1 and update the SDKs the change breaks"
        );
    }

    #[test]
    fn the_samples_cover_every_event_once() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/enums.json"))
                .expect("enums.json parses");
        let mut expected: Vec<String> = fixture["enums"]["DeRecEvent"]["variants"]
            .as_array()
            .expect("DeRecEvent variants")
            .iter()
            .map(|v| v["wire"].as_str().expect("wire name").to_owned())
            .collect();
        expected.sort();

        let samples = samples();
        let mut covered: Vec<String> = samples.iter().map(|e| variant_name(e).to_owned()).collect();
        covered.sort();
        assert_eq!(covered, expected, "every event has exactly one sample");

        for event in &samples {
            let json = serde_json::to_value(event).expect("an event serializes");
            assert_eq!(
                json["type"],
                variant_name(event),
                "the tag is the variant name"
            );
        }
    }
}
