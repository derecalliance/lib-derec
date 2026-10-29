// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::{Seal, Sealed};
use crate::protocol::{ChannelRequest, FailedRequest, ReplyTarget};
use crate::types::{ChannelId, SharedKey};
use derec_proto::{Protocol, StoreShareRequestMessage, TransportProtocol};

const KEY: SharedKey = SharedKey::new([0x11; 32]);
const CHANNEL: ChannelId = ChannelId(7);
const TRACE: u64 = 42;

fn share(keep_version: u32) -> ChannelRequest {
    ChannelRequest::StoreShare(StoreShareRequestMessage {
        share: vec![0xAB; 16],
        version: 3,
        keep_version,
        ..Default::default()
    })
}

fn reply(uri: &str) -> ReplyTarget {
    ReplyTarget {
        channel_id: ChannelId(8),
        endpoints: vec![TransportProtocol {
            uri: uri.to_owned(),
            protocol: Protocol::Https as i32,
        }],
    }
}

/// A seal verifies under the key and for the action it was made for.
#[test]
fn a_seal_verifies_what_it_sealed() {
    let request = share(2);
    let seal = Seal::new(&KEY, CHANNEL, TRACE, Sealed::Request(&request));
    assert!(seal.verifies(&KEY, CHANNEL, TRACE, Sealed::Request(&request)));
}

/// Another key, channel or trace id does not verify: an action cannot be
/// moved to another channel or exchange.
#[test]
fn a_seal_is_bound_to_its_key_channel_and_trace_id() {
    let request = share(2);
    let seal = Seal::new(&KEY, CHANNEL, TRACE, Sealed::Request(&request));
    let other_key = SharedKey::new([0x22; 32]);
    assert!(!seal.verifies(&other_key, CHANNEL, TRACE, Sealed::Request(&request)));
    assert!(!seal.verifies(&KEY, ChannelId(8), TRACE, Sealed::Request(&request)));
    assert!(!seal.verifies(&KEY, CHANNEL, TRACE + 1, Sealed::Request(&request)));
}

/// Any change to the request — here only its `keepVersion`, which decides
/// which held versions a helper removes — does not verify.
#[test]
fn an_edited_request_does_not_verify() {
    let seal = Seal::new(&KEY, CHANNEL, TRACE, Sealed::Request(&share(2)));
    assert!(!seal.verifies(&KEY, CHANNEL, TRACE, Sealed::Request(&share(1))));
}

/// The same request bytes under another request type do not verify.
#[test]
fn a_request_cannot_change_type() {
    let unpair = ChannelRequest::Unpair(derec_proto::UnpairRequestMessage::default());
    let discovery =
        ChannelRequest::Discovery(derec_proto::GetSecretIdsVersionsRequestMessage::default());
    let seal = Seal::new(&KEY, CHANNEL, TRACE, Sealed::Request(&unpair));
    assert!(!seal.verifies(&KEY, CHANNEL, TRACE, Sealed::Request(&discovery)));
}

/// A failed request's seal covers where it is answered: another reply
/// endpoint does not verify.
#[test]
fn a_failure_seal_covers_its_reply_target() {
    let request = FailedRequest::Undecodable;
    let honest = reply("https://owner.example");
    let seal = Seal::new(
        &KEY,
        CHANNEL,
        TRACE,
        Sealed::Failure {
            reply: &honest,
            request: &request,
        },
    );
    assert!(seal.verifies(
        &KEY,
        CHANNEL,
        TRACE,
        Sealed::Failure {
            reply: &honest,
            request: &request,
        }
    ));
    assert!(!seal.verifies(
        &KEY,
        CHANNEL,
        TRACE,
        Sealed::Failure {
            reply: &reply("https://elsewhere.example"),
            request: &request,
        }
    ));
}
