// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use std::collections::HashMap;

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::{Target, UserSecret};
use derec_library::protocol::{DeRecFlow, IgnoreReason};
use derec_library::types::ChannelId;
use prost::Message as _;

use crate::db::Database;
use crate::flows::assertions::key_ring_epoch;
use crate::flows::helpers::pair_owner_helper;
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer, pump_many};

const OWNER_URI: &str = "https://owner-rotation.example.com";

/// With key rotation on, the owner advances each helper channel one epoch per
/// sharing round, and both ends persist the new epoch as a `KeyRing` row. An
/// envelope whose `sequence` is beyond the forward-jump limit is ignored as
/// `KeyUnavailable`. The recovered secret names each channel's epoch, and a
/// fresh device restored from it publishes to the helpers under the next one.
pub async fn run() {
    println!("=== [KeyRotation] epochs advance, persist and survive restore ===");

    let owner_db = Database::open_isolated().await;
    let helper_a_db = Database::open_isolated().await;
    let helper_b_db = Database::open_isolated().await;
    let mut owner = Peer::rotating(owner_db.client(), "Owner", OWNER_URI);
    let mut helper_a = Peer::new(
        helper_a_db.client(),
        "HelperA",
        "https://helper-a-rotation.example.com",
    );
    let mut helper_b = Peer::new(
        helper_b_db.client(),
        "HelperB",
        "https://helper-b-rotation.example.com",
    );
    let cid_a = pair_owner_helper(&mut owner, &mut helper_a, ChannelId(1)).await;
    let cid_b = pair_owner_helper(&mut owner, &mut helper_b, ChannelId(2)).await;
    let sid = DEFAULT_TEST_SECRET_ID;

    for round in 1..=2_u8 {
        owner
            .protocol
            .start(DeRecFlow::ProtectSecret {
                secrets: vec![UserSecret {
                    id: vec![21],
                    name: "rotating".to_owned(),
                    data: vec![round],
                }],
                description: None,
                weights: HashMap::new(),
                threshold: None,
            })
            .await
            .expect("owner start(ProtectSecret) failed");
        let events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;
        let confirmed = events
            .iter()
            .filter(|e| {
                matches!(e, DeRecEvent::ShareConfirmed { version, .. } if *version == u32::from(round))
            })
            .count();
        assert_eq!(confirmed, 2, "both helpers confirm v{round}");
    }
    for (cid, helper_db) in [(cid_a, &helper_a_db), (cid_b, &helper_b_db)] {
        assert_eq!(key_ring_epoch(&owner_db.client(), sid, cid.0).await, 2);
        assert_eq!(key_ring_epoch(&helper_db.client(), sid, cid.0).await, 2);
    }
    println!("  two rounds → owner and helpers persist KeyRing epoch 2 on both channels  ✓");

    owner
        .protocol
        .start(DeRecFlow::VerifyShares {
            secret_id: sid,
            version: 2,
            target: Target::All,
        })
        .await
        .expect("owner start(VerifyShares) failed");
    let events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;
    for cid in [cid_a, cid_b] {
        assert!(
            events.iter().any(|e| matches!(
                e,
                DeRecEvent::ShareVerified { channel_id, version: 2, .. } if *channel_id == cid
            )),
            "{cid:?} verifies v2 at epoch 2: {events:?}"
        );
    }
    println!("  verification of v2 at epoch 2 → ShareVerified on both channels  ✓");

    owner
        .protocol
        .start(DeRecFlow::VerifyShares {
            secret_id: sid,
            version: 2,
            target: Target::Single(cid_a),
        })
        .await
        .expect("owner start(VerifyShares) failed");
    let sent = owner.drain();
    assert_eq!(sent.len(), 1, "one challenge to HelperA");
    let mut forged =
        derec_proto::DeRecMessage::decode(sent[0].1.as_slice()).expect("an envelope decodes");
    assert_eq!(forged.sequence, 2, "the challenge is under K2");
    forged.sequence = 2 + 513;
    let events = helper_a
        .protocol
        .process(&forged.encode_to_vec())
        .await
        .expect("an unusable epoch is not an error");
    assert!(
        matches!(
            events.as_slice(),
            [DeRecEvent::MessageIgnored {
                channel_id,
                reason: IgnoreReason::KeyUnavailable,
                ..
            }] if *channel_id == cid_a
        ),
        "a sequence past the forward-jump limit must be MessageIgnored(KeyUnavailable), got {events:?}"
    );
    assert!(helper_a.drain().is_empty(), "nothing is answered");
    assert_eq!(key_ring_epoch(&helper_a_db.client(), sid, cid_a.0).await, 2);
    println!("  sequence 515 → MessageIgnored(KeyUnavailable), nothing sent, ring unchanged  ✓");

    owner
        .protocol
        .start(DeRecFlow::RecoverSecret {
            secret_id: sid,
            version: 2,
        })
        .await
        .expect("owner start(RecoverSecret) failed");
    let events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;
    let recovered = events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::SecretRecovered { secret } => Some(secret.clone()),
            _ => None,
        })
        .expect("expected SecretRecovered on the owner");
    assert_eq!(recovered.helpers.len(), 2);
    for helper in &recovered.helpers {
        assert_eq!(helper.key_epoch, 2, "the roster names epoch 2");
    }
    println!("  SecretRecovered names key_epoch 2 for both helpers  ✓");
    drop(owner);

    let device_db = Database::open_isolated().await;
    let mut device = Peer::rotating(device_db.client(), "Device", OWNER_URI);
    device
        .protocol
        .restore(&recovered, 2, 2)
        .await
        .expect("restore on a fresh device must succeed");
    for cid in [cid_a, cid_b] {
        assert_eq!(key_ring_epoch(&device_db.client(), sid, cid.0).await, 2);
    }
    println!("  restore on a fresh device → KeyRing epoch 2 on both channels  ✓");

    device
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: recovered.secrets.clone(),
            description: None,
            weights: HashMap::new(),
            threshold: None,
        })
        .await
        .expect("the restored device publishes");
    let events = pump_many(&mut [&mut device, &mut helper_a, &mut helper_b]).await;
    let confirmed = events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::ShareConfirmed { version: 3, .. }))
        .count();
    assert_eq!(
        confirmed, 2,
        "both helpers confirm v3 from the restored device"
    );
    for (cid, helper_db) in [(cid_a, &helper_a_db), (cid_b, &helper_b_db)] {
        assert_eq!(key_ring_epoch(&device_db.client(), sid, cid.0).await, 3);
        assert_eq!(key_ring_epoch(&helper_db.client(), sid, cid.0).await, 3);
    }
    println!("  the restored device publishes v3 → both helpers confirm, KeyRing epoch 3  ✓");
}
