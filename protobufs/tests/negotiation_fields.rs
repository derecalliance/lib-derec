// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_proto::{ContactMessage, PairRequestMessage, Protocol, StatusEnum, TransportProtocol};

fn ep(uri: &str, protocol: Protocol) -> TransportProtocol {
    TransportProtocol {
        uri: uri.to_owned(),
        protocol: protocol as i32,
    }
}

#[test]
fn contact_carries_an_offer_list() {
    let msg = ContactMessage {
        supported_transports: vec![
            ep("grpcs://a.example.com:443", Protocol::Grpc),
            ep("https://a.example.com/derec", Protocol::Https),
        ],
        ..Default::default()
    };
    assert_eq!(msg.supported_transports.len(), 2);
}

#[test]
fn pair_request_carries_an_offer_list() {
    let msg = PairRequestMessage {
        supported_transports: vec![ep("https://b.example.com/derec", Protocol::Https)],
        ..Default::default()
    };
    assert_eq!(msg.supported_transports.len(), 1);
}

/// Absent is the old-peer shape and must decode as an empty list, never
/// as an error.
#[test]
fn absent_offer_list_decodes_as_empty() {
    assert!(ContactMessage::default().supported_transports.is_empty());
    assert!(
        PairRequestMessage::default()
            .supported_transports
            .is_empty()
    );
}

#[test]
fn unsupported_transport_protocol_is_status_twelve() {
    assert_eq!(StatusEnum::UnsupportedTransportProtocol as i32, 12);
}
