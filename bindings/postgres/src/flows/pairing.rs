// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::{DeRecChannelStore, SecretKind};
use derec_library::types::ChannelId;
use derec_proto::SenderKind;
use std::collections::HashSet;

use crate::db::Database;
use crate::flows::assertions::{channel_exists, count_channels, count_secrets};
use crate::flows::helpers::pair_owner_helper;
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer};
use crate::stores::{PostgresChannelStore, PostgresSecretStore};

pub async fn run() {
    println!("=== [Pairing] persisted state on both sides ===");

    let owner_db = Database::open_isolated().await;
    let helper_db = Database::open_isolated().await;

    let mut owner = Peer::new(owner_db.client(), "Owner", "https://owner.example.com");
    let mut helper = Peer::new(
        helper_db.client(),
        "Helper",
        "https://helper.example.com",
    );

    let final_id = pair_owner_helper(&mut owner, &mut helper, ChannelId(1)).await;
    println!("  Owner↔Helper paired on ChannelId({})", final_id.0);

    for (name, conn) in [("owner", owner_db.client()), ("helper", helper_db.client())] {
        assert_eq!(
            count_channels(&conn, DEFAULT_TEST_SECRET_ID).await,
            1,
            "{name}: expected exactly 1 channel row after pair"
        );
        assert!(
            channel_exists(&conn, DEFAULT_TEST_SECRET_ID, final_id.0).await,
            "{name}: channel row for the paired ChannelId must exist"
        );
    }
    println!("  channels row present on both devices  ✓");

    let owner_check = PostgresChannelStore::new(owner_db.client());
    let helper_check = PostgresChannelStore::new(helper_db.client());
    let owner_channel = owner_check
        .load(DEFAULT_TEST_SECRET_ID, final_id)
        .await
        .expect("owner channel load failed")
        .expect("owner channel must exist");
    let helper_channel = helper_check
        .load(DEFAULT_TEST_SECRET_ID, final_id)
        .await
        .expect("helper channel load failed")
        .expect("helper channel must exist");
    assert_eq!(owner_channel.role, SenderKind::Owner);
    assert_eq!(helper_channel.role, SenderKind::Helper);
    println!("  Channel.role is local on each side  ✓");

    for (name, conn) in [("owner", owner_db.client()), ("helper", helper_db.client())] {
        assert!(
            count_secrets(&conn, DEFAULT_TEST_SECRET_ID).await >= 1,
            "{name}: expected at least 1 SharedKey row"
        );
    }
    let owner_secrets = PostgresSecretStore::new(owner_db.client());
    let helper_secrets = PostgresSecretStore::new(helper_db.client());
    use derec_library::protocol::{DeRecSecretStore, SecretValue};
    let SecretValue::SharedKey(owner_key) = owner_secrets
        .load(DEFAULT_TEST_SECRET_ID, final_id, SecretKind::SharedKey)
        .await
        .expect("owner SharedKey load failed")
        .expect("owner SharedKey must exist")
    else {
        panic!("owner: expected SharedKey variant");
    };
    let SecretValue::SharedKey(helper_key) = helper_secrets
        .load(DEFAULT_TEST_SECRET_ID, final_id, SecretKind::SharedKey)
        .await
        .expect("helper SharedKey load failed")
        .expect("helper SharedKey must exist")
    else {
        panic!("helper: expected SharedKey variant");
    };
    assert_eq!(
        owner_key, helper_key,
        "owner and helper must agree on the shared symmetric key"
    );
    println!("  SharedKey 32B round-trips through Postgres and matches on both sides  ✓");

    let mut link_store = PostgresChannelStore::new(owner_db.client());
    let solo = link_store
        .linked_channels(DEFAULT_TEST_SECRET_ID, final_id)
        .await
        .expect("linked_channels lookup failed");
    assert_eq!(solo, vec![final_id], "unlinked channel must return [self]");

    let a = ChannelId(900);
    let b = ChannelId(901);
    let c = ChannelId(902);
    link_store
        .link_channel(DEFAULT_TEST_SECRET_ID, a, b)
        .await
        .unwrap();
    link_store
        .link_channel(DEFAULT_TEST_SECRET_ID, b, c)
        .await
        .unwrap();
    link_store
        .link_channel(DEFAULT_TEST_SECRET_ID, a, b)
        .await
        .unwrap();
    let group: HashSet<u64> = link_store
        .linked_channels(DEFAULT_TEST_SECRET_ID, c)
        .await
        .unwrap()
        .into_iter()
        .map(|cid| cid.0)
        .collect();
    let expected: HashSet<u64> = [a.0, b.0, c.0].into_iter().collect();
    assert_eq!(
        group, expected,
        "channel-link graph must be undirected and transitive"
    );
    println!(
        "  link_channel: undirected + idempotent + transitive (a—b—c → {{a,b,c}})  ✓"
    );

    println!("✓ Pairing flow passed.\n");
}
