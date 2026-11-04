// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! `fixtures/protocol_config.json` holds the canonical `DeRecProtocolConfig`
//! JSON every SDK loads: one config with every field set and one with only
//! what `build()` requires. These tests pin the Rust reading of both.

#![cfg(feature = "serde")]

use std::fs;

use derec_library::protocol::{
    AutoAcceptPolicy, DeRecProtocolConfig, ExpiredChannelsConfig, TimeoutsConfig, UnpairAck,
};
use derec_proto::Protocol;
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/protocol_config.json"
    );
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let all: Value = serde_json::from_str(&raw).expect("fixture is JSON");
    all.get(name)
        .unwrap_or_else(|| panic!("fixture has no `{name}` config"))
        .clone()
}

fn config(name: &str) -> DeRecProtocolConfig {
    serde_json::from_value(fixture(name))
        .unwrap_or_else(|e| panic!("`{name}` fixture is not a DeRecProtocolConfig: {e}"))
}

#[test]
fn full_fixture_sets_every_field() {
    let c = config("full");
    let DeRecProtocolConfig {
        threshold,
        max_subshares,
        timeouts,
        parameter_range,
        auto_accept,
        auto_respond_on_failure,
        auto_reply_to,
        unpair_ack,
        unsafe_connection,
        communication_info,
        own_transports,
        replica_id,
    } = c;

    assert_eq!(threshold, Some(3));
    assert_eq!(max_subshares, Some(12));
    assert_eq!(
        timeouts,
        Some(TimeoutsConfig {
            inbound_message_secs: Some(120),
            sharing_round_secs: Some(30),
            unpair_ack_secs: Some(45),
            get_share_response_secs: Some(900),
            expired_channels: Some(ExpiredChannelsConfig {
                enabled: true,
                timeout_in_secs: 600,
            }),
        })
    );
    let range = parameter_range.expect("parameter_range is set");
    assert_eq!(range.max_share_size, 4096);
    assert_eq!(
        range.max_unresponsive_deletion_timeout, 9_007_199_254_740_993,
        "a decimal-string bound keeps its full precision"
    );
    assert_eq!(
        auto_accept,
        Some(AutoAcceptPolicy {
            pairing: true,
            pre_pair: false,
            store_share: true,
            verify_share: true,
            discovery: false,
            get_share: false,
            unpair: true,
            update_channel_info: false,
        })
    );
    assert_eq!(auto_respond_on_failure, Some(true));
    assert_eq!(auto_reply_to, Some(true));
    assert_eq!(unpair_ack, Some(UnpairAck::NotRequired));
    assert_eq!(unsafe_connection, Some(false));
    let info = communication_info.expect("communication_info is set");
    assert_eq!(info.get("name").map(String::as_str), Some("alice"));
    assert_eq!(info.len(), 2);
    let transports = own_transports.expect("own_transports is set");
    assert_eq!(transports.len(), 2);
    assert_eq!(transports[0].uri, "https://me.example.com/derec");
    assert_eq!(transports[0].protocol, Protocol::Https);
    assert_eq!(transports[1].protocol, Protocol::Grpc);
    assert_eq!(replica_id, Some(9_007_199_254_740_993));
}

#[test]
fn minimal_fixture_sets_only_own_transports() {
    let c = config("minimal");
    let transports = c.own_transports.clone().expect("own_transports is set");
    assert_eq!(transports.len(), 1);
    assert_eq!(
        c,
        DeRecProtocolConfig {
            own_transports: Some(transports),
            ..DeRecProtocolConfig::default()
        }
    );
}

/// Each fixture serializes back to itself, so it is written in the
/// canonical shape rather than in a merely accepted one.
#[test]
fn fixtures_are_canonical() {
    for name in ["full", "minimal"] {
        let reserialized = serde_json::to_value(config(name)).expect("serializes");
        assert_eq!(reserialized, normalized(fixture(name)), "{name}");
    }
}

/// The fixture writes one parameter-range bound as a decimal string to pin
/// that form; serialization writes every bound as a number.
fn normalized(mut v: Value) -> Value {
    if let Some(range) = v.get_mut("parameter_range").and_then(Value::as_object_mut) {
        for bound in range.values_mut() {
            if let Some(s) = bound.as_str() {
                let n: i64 = s.parse().expect("decimal bound");
                *bound = Value::from(n);
            }
        }
    }
    v
}
