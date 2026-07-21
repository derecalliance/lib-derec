// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::{Target, UserSecret};
use derec_library::protocol::DeRecFlow;
use derec_library::protocol::DeRecUserSecretStore;
use derec_library::types::ChannelId;

use crate::db::Database;
use crate::flows::assertions::{
    channel_exists, count_channels, count_shares, count_user_secrets,
};
use crate::flows::helpers::{pair_owner_helper, protect_secret};
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer, pump_many};
use crate::stores::SqliteUserSecretStore;

pub async fn run() {
    println!("=== [Persistence] state survives DeRecProtocol drop ===");

    let owner_db = Database::open_in_memory();
    let helper_a_db = Database::open_in_memory();
    let helper_b_db = Database::open_in_memory();

    let cid_a;
    let cid_b;
    let mut helper_a = Peer::new(
        helper_a_db.connection(),
        "HelperA",
        "https://helper-a.example.com",
    );
    let mut helper_b = Peer::new(
        helper_b_db.connection(),
        "HelperB",
        "https://helper-b.example.com",
    );
    {
        let mut owner = Peer::new(
            owner_db.connection(),
            "Owner-Session1",
            "https://owner.example.com",
        );
        cid_a = pair_owner_helper(&mut owner, &mut helper_a, ChannelId(1)).await;
        cid_b = pair_owner_helper(&mut owner, &mut helper_b, ChannelId(2)).await;

        protect_secret(
            &mut owner,
            &mut [&mut helper_a, &mut helper_b],
            UserSecret {
                id: vec![0x42],
                name: "persistent".to_owned(),
                data: b"survives the protocol drop".to_vec(),
            },
            "session-1 publish",
        )
        .await;

        assert_eq!(count_channels(&owner_db.connection(), DEFAULT_TEST_SECRET_ID), 2);
        assert_eq!(count_user_secrets(&owner_db.connection(), DEFAULT_TEST_SECRET_ID), 1);
        assert_eq!(count_shares(&helper_a_db.connection(), DEFAULT_TEST_SECRET_ID), 1);
        assert_eq!(count_shares(&helper_b_db.connection(), DEFAULT_TEST_SECRET_ID), 1);
        println!("  session#1: 2 channels, 1 user_secrets row, helpers each hold 1 share  ✓");

    }

    assert!(channel_exists(
        &owner_db.connection(),
        DEFAULT_TEST_SECRET_ID,
        cid_a.0
    ));
    assert!(channel_exists(
        &owner_db.connection(),
        DEFAULT_TEST_SECRET_ID,
        cid_b.0
    ));
    let preserved_snapshot = SqliteUserSecretStore::new(owner_db.connection())
        .load_latest(DEFAULT_TEST_SECRET_ID)
        .await
        .unwrap()
        .expect("user_secrets row must still exist for session #2");
    assert_eq!(preserved_snapshot.version, 1);
    println!("  session#2: rebuild owner over the same DB connection");

    let mut owner = Peer::new(
        owner_db.connection(),
        "Owner-Session2",
        "https://owner.example.com",
    );

    owner
        .protocol
        .start(DeRecFlow::Discovery {
            target: Target::Many(vec![cid_a, cid_b]),
        })
        .await
        .expect("owner.start(Discovery) must succeed with channels resurrected from SQLite");

    let discovery_events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;
    let discovered_secret_ids: Vec<u64> = discovery_events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::SecretsDiscovered { secrets, .. } => Some(secrets.clone()),
            _ => None,
        })
        .flatten()
        .map(|s| s.secret_id)
        .collect();
    assert!(
        discovered_secret_ids.contains(&DEFAULT_TEST_SECRET_ID),
        "rebuilt owner must discover the v1 secret published in session #1; \
         got {discovered_secret_ids:?}"
    );
    println!(
        "  rebuilt owner discovered the v1 secret via the resurrected channels  ✓"
    );

    println!("✓ Persistence flow passed.\n");
}
