// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::UserSecret;
use derec_library::protocol::{AutoAcceptPolicy, PendingActionKind};
use derec_library::types::ChannelId;

use crate::db::Database;
use crate::flows::assertions::count_shares;
use crate::flows::helpers::{pair_owner_helper, protect_secret};
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer};

pub async fn run() {
    println!("=== [AutoAccept] StoreShare auto-accepted on helpers ===");

    let owner_db = Database::open_isolated().await;
    let helper_a_db = Database::open_isolated().await;
    let helper_b_db = Database::open_isolated().await;

    let policy = AutoAcceptPolicy {
        store_share: true,
        ..Default::default()
    };

    let mut owner = Peer::new(owner_db.client(), "Owner", "https://owner.example.com");
    let mut helper_a = Peer::with_auto_accept(
        helper_a_db.client(),
        "HelperA",
        "https://helper-a.example.com",
        policy,
    );
    let mut helper_b = Peer::with_auto_accept(
        helper_b_db.client(),
        "HelperB",
        "https://helper-b.example.com",
        policy,
    );

    let cid_a = pair_owner_helper(&mut owner, &mut helper_a, ChannelId(1)).await;
    let cid_b = pair_owner_helper(&mut owner, &mut helper_b, ChannelId(2)).await;
    println!("  paired Owner↔HelperA({}), Owner↔HelperB({})", cid_a.0, cid_b.0);

    let events = protect_secret(
        &mut owner,
        &mut [&mut helper_a, &mut helper_b],
        UserSecret {
            id: vec![0xAA],
            name: "auto-accept smoke".to_owned(),
            data: b"postgres-auto-accept".to_vec(),
        },
        "v1 auto-accept",
    )
    .await;

    let auto_accepted = events
        .iter()
        .filter(|e| matches!(
            e,
            DeRecEvent::AutoAccepted {
                action_kind: PendingActionKind::StoreShare,
                ..
            }
        ))
        .count();
    assert_eq!(
        auto_accepted, 2,
        "expected AutoAccepted{{StoreShare}} from each of the two helpers; got {auto_accepted}"
    );

    let still_required = events.iter().any(|e| matches!(
        e,
        DeRecEvent::ActionRequired {
            action: derec_library::protocol::PendingAction::StoreShare { .. },
            ..
        }
    ));
    assert!(
        !still_required,
        "auto-accept should suppress ActionRequired{{StoreShare}} entirely"
    );

    let stored: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::ShareStored { version, .. } => Some(*version),
            _ => None,
        })
        .collect();
    assert_eq!(stored.len(), 2, "both helpers must persist a share; got {stored:?}");

    let confirmed = events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::ShareConfirmed { .. }))
        .count();
    assert_eq!(
        confirmed, 2,
        "owner must observe two ShareConfirmed (one per helper); got {confirmed}"
    );

    for (name, client) in [
        ("HelperA", helper_a_db.client()),
        ("HelperB", helper_b_db.client()),
    ] {
        assert_eq!(
            count_shares(&client, DEFAULT_TEST_SECRET_ID).await,
            1,
            "{name}: expected exactly one share row after the auto-accepted publish"
        );
    }
    println!("  both helpers AutoAccepted StoreShare + persisted the share row  ✓");

    println!("✓ AutoAccept flow passed.\n");
}
