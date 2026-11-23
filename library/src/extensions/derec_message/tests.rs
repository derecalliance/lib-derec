// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use std::time::Duration;

use derec_proto::DeRecMessage;

use super::DeRecMessageExt as _;

const NOW: u64 = 1_000_000;
const WINDOW: Duration = Duration::from_secs(120);

/// An envelope whose timestamp is `age_secs` before [`NOW`].
fn envelope_aged(age_secs: u64) -> DeRecMessage {
    DeRecMessage {
        timestamp: Some(prost_types::Timestamp {
            seconds: (NOW - age_secs) as i64,
            nanos: 0,
        }),
        ..Default::default()
    }
}

#[test]
fn an_envelope_inside_the_window_is_not_expired() {
    assert!(!envelope_aged(60).is_expired(NOW, WINDOW));
}

#[test]
fn the_boundary_itself_is_not_expired() {
    assert!(!envelope_aged(120).is_expired(NOW, WINDOW));
}

#[test]
fn an_envelope_past_the_window_is_expired() {
    assert!(envelope_aged(121).is_expired(NOW, WINDOW));
}

/// The timestamp invariant is enforced after decryption; reading absence
/// as stale here would hide that failure behind an ignore.
#[test]
fn an_envelope_without_a_timestamp_is_not_expired() {
    let envelope = DeRecMessage {
        timestamp: None,
        ..Default::default()
    };
    assert!(!envelope.is_expired(NOW, WINDOW));
}

/// A timestamp ahead of the local clock has no age.
#[test]
fn a_future_dated_envelope_is_not_expired() {
    let envelope = DeRecMessage {
        timestamp: Some(prost_types::Timestamp {
            seconds: (NOW + 3600) as i64,
            nanos: 0,
        }),
        ..Default::default()
    };
    assert!(!envelope.is_expired(NOW, WINDOW));
}
