// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! `library/tests/fixtures/legacy_messages.json`: a message produced by the
//! 0.0.11 release, which every SDK feeds to its own binding to show the
//! minimum protocol version reaches the core.
//!
//! The fixture is written once, by
//! `DEREC_WRITE_LEGACY_FIXTURE=1 cargo test --test legacy_fixture`, and
//! checked in; every other run checks it still is what the release produces.

use derec_library_0_0_11 as release;
use derec_proto_0_0_11 as release_proto;
use prost::Message as _;
use serde_json::{Value, json};
use std::path::PathBuf;

const SECRET_ID: u64 = 0x5EC2E7;
const CHANNEL: u64 = 4242;
const KEY: [u8; 32] = [0x5A; 32];
const VERSION: u32 = 3;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../library/tests/fixtures/legacy_messages.json")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn produce() -> Vec<u8> {
    let channel = release::types::ChannelId(CHANNEL);
    let share = release::primitives::sharing::request::split(
        &[(channel, 1), (release::types::ChannelId(CHANNEL + 1), 1)],
        SECRET_ID,
        VERSION,
        b"the secret",
        2,
    )
    .expect("split")
    .shares
    .remove(&channel)
    .expect("share");
    release::primitives::sharing::request::produce(
        channel,
        VERSION,
        SECRET_ID,
        &share,
        0,
        "legacy",
        &KEY,
        &[],
    )
    .expect("store-share request")
    .envelope
}

#[test]
fn the_legacy_fixture_is_a_message_from_the_release() {
    if std::env::var_os("DEREC_WRITE_LEGACY_FIXTURE").is_some() {
        let fixture = json!({
            "$schema_note": "A message produced by derec-library 0.0.11, written by compat-tests/tests/legacy_fixture.rs. Seed a helper channel `channel_id` whose peer is an Owner, under `shared_key_hex`, accept messages of any age, and process `store_share_request_hex`: it is accepted with the default minimum protocol version and ignored as ProtocolVersionTooOld with the minimum at 0.1.",
            "produced_by": "derec-library 0.0.11",
            "secret_id": SECRET_ID.to_string(),
            "channel_id": CHANNEL.to_string(),
            "shared_key_hex": hex(&KEY),
            "peer_role": "Owner",
            "store_share_request_hex": hex(&produce()),
        });
        std::fs::write(
            path(),
            serde_json::to_string_pretty(&fixture).expect("json") + "\n",
        )
        .expect("write fixture");
    }

    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(path()).expect("fixture exists"))
            .expect("fixture is JSON");
    let bytes = unhex(fixture["store_share_request_hex"].as_str().expect("hex"));
    let envelope = release_proto::DeRecMessage::decode(bytes.as_slice()).expect("an envelope");
    assert_eq!(
        (
            envelope.protocol_version_major,
            envelope.protocol_version_minor
        ),
        (0, 0)
    );
    let request = release::primitives::sharing::request::extract(&bytes, &KEY)
        .expect("the release opens its own message")
        .request;
    assert_eq!((request.secret_id, request.version), (SECRET_ID, VERSION));
}
