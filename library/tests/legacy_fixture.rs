// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! `fixtures/legacy_messages.json` holds a message the 0.0.11 release
//! produced. It is accepted while the minimum protocol version admits 0.0,
//! and ignored unread once the minimum is 0.1. Every SDK smoke suite runs the
//! same two cases through its own binding.

#[path = "support/protocol_doubles.rs"]
mod protocol_doubles;

use std::collections::HashMap;
use std::time::Duration;

use derec_library::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel, Timeouts};
use derec_library::protocol::{
    DeRecChannelStore as _, DeRecEvent, DeRecProtocolBuilder, DeRecSecretStore as _, IgnoreReason,
    SecretValue,
};
use derec_library::protocol_version::ProtocolVersion;
use derec_library::types::{ChannelId, SharedKey};
use derec_proto::{Protocol, SenderKind, TransportProtocol};
use protocol_doubles::{
    InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore, InMemUserSecretStore,
    RecordingTransport, run_async,
};
use serde_json::Value;

struct Legacy {
    secret_id: u64,
    channel: ChannelId,
    key: [u8; 32],
    request: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn legacy() -> Legacy {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/legacy_messages.json"))
        .expect("fixture is JSON");
    let field = |name: &str| fixture[name].as_str().expect(name).to_owned();
    Legacy {
        secret_id: field("secret_id").parse().expect("secret_id"),
        channel: ChannelId(field("channel_id").parse().expect("channel_id")),
        key: unhex(&field("shared_key_hex"))
            .try_into()
            .expect("a 32-byte key"),
        request: unhex(&field("store_share_request_hex")),
    }
}

fn process(floor: ProtocolVersion) -> Vec<DeRecEvent> {
    let legacy = legacy();
    let mut events = Vec::new();
    run_async(async {
        let mut channels = InMemChannelStore::default();
        let mut secrets = InMemSecretStore::default();
        channels
            .save(
                legacy.secret_id,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: legacy.channel,
                    transports: vec![TransportProtocol {
                        uri: "https://owner.example/derec".to_owned(),
                        protocol: Protocol::Https.into(),
                    }],
                    communication_info: HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: 0,
                    peer_role: SenderKind::Owner,
                    weight: 1,
                }),
            )
            .await
            .expect("seed channel");
        secrets
            .save(
                legacy.secret_id,
                legacy.channel,
                SecretValue::SharedKey(SharedKey::new(legacy.key)),
            )
            .await
            .expect("seed key");
        let mut protocol = DeRecProtocolBuilder::new(legacy.secret_id)
            .with_channel_store(channels)
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets)
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(RecordingTransport::default())
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://helper.example/derec"])
            .with_timeouts(Timeouts {
                inbound_message: Duration::from_secs(1 << 40),
                ..Timeouts::default()
            })
            .with_min_protocol_version(floor)
            .build()
            .expect("protocol builds");
        events = protocol.process(&legacy.request).await.expect("processed");
    });
    events
}

#[test]
fn a_message_from_0_0_11_is_accepted_by_default() {
    let events = process(ProtocolVersion { major: 0, minor: 0 });
    assert!(
        !events.is_empty()
            && !events
                .iter()
                .any(|e| matches!(e, DeRecEvent::MessageIgnored { .. })),
        "{events:?}"
    );
}

#[test]
fn a_message_from_0_0_11_is_ignored_once_the_minimum_is_0_1() {
    let events = process(ProtocolVersion { major: 0, minor: 1 });
    assert!(
        matches!(
            events.as_slice(),
            [DeRecEvent::MessageIgnored {
                reason: IgnoreReason::ProtocolVersionTooOld,
                ..
            }]
        ),
        "{events:?}"
    );
}
