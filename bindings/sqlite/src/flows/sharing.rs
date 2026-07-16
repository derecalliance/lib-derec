// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::UserSecret;
use derec_library::protocol::DeRecShareStore;
use derec_library::protocol::DeRecUserSecretStore;
use derec_library::types::ChannelId;

use crate::db::Database;
use crate::flows::assertions::{count_shares, count_shares_for_channel, count_user_secrets};
use crate::flows::helpers::{pair_owner_helper, protect_secret};
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer};
use crate::stores::{SqliteShareStore, SqliteUserSecretStore};

pub async fn run() {
    println!("=== [Sharing] persisted shares + user_secrets snapshot ===");

    let owner_db = Database::open_in_memory();
    let helper_a_db = Database::open_in_memory();
    let helper_b_db = Database::open_in_memory();

    let mut owner = Peer::new(owner_db.connection(), "Owner", "https://owner.example.com");
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

    let cid_a = pair_owner_helper(&mut owner, &mut helper_a, ChannelId(1)).await;
    let cid_b = pair_owner_helper(&mut owner, &mut helper_b, ChannelId(2)).await;
    println!("  paired Owner↔HelperA({}), Owner↔HelperB({})", cid_a.0, cid_b.0);

    let payload = b"sqlite-shared-secret".to_vec();
    let events = protect_secret(
        &mut owner,
        &mut [&mut helper_a, &mut helper_b],
        UserSecret {
            id: vec![0x01],
            name: "smoke".to_owned(),
            data: payload.clone(),
        },
        "v1 publish",
    )
    .await;

    let stored: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::ShareStored { version, .. } => Some(*version),
            _ => None,
        })
        .collect();
    assert!(
        stored.iter().all(|v| *v == 1),
        "every ShareStored event must report version=1; got {stored:?}"
    );
    let confirmed: Vec<u32> = events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::ShareConfirmed { version, .. } => Some(*version),
            _ => None,
        })
        .collect();
    assert_eq!(
        confirmed.len(),
        2,
        "owner must observe exactly 2 ShareConfirmed (one per helper); got {confirmed:?}"
    );

    for (name, db, channel_id) in [
        ("HelperA", helper_a_db.connection(), cid_a.0),
        ("HelperB", helper_b_db.connection(), cid_b.0),
    ] {
        assert_eq!(
            count_shares(&db, DEFAULT_TEST_SECRET_ID),
            1,
            "{name}: expected exactly one share row after v1 publish"
        );
        assert_eq!(
            count_shares_for_channel(&db, DEFAULT_TEST_SECRET_ID, channel_id),
            1,
            "{name}: share row must live under the helper-owner channel"
        );
        let store = SqliteShareStore::new(db.clone());
        let shares = store
            .load(DEFAULT_TEST_SECRET_ID, ChannelId(channel_id), &[])
            .await
            .expect("share load failed");
        assert_eq!(shares.len(), 1, "{name}: load must return the one stored share");
        assert_eq!(
            shares[0].secret_id, DEFAULT_TEST_SECRET_ID,
            "{name}: Share.secret_id must equal the partition key"
        );
        assert_eq!(shares[0].version, 1, "{name}: stored share must be v1");

        let latest = store
            .latest_version(DEFAULT_TEST_SECRET_ID)
            .await
            .expect("latest_version failed");
        assert_eq!(
            latest,
            Some(1),
            "{name}: latest_version must report 1 after the v1 publish"
        );
    }
    println!("  helpers stored a v1 share each; latest_version=1 on both  ✓");

    assert_eq!(
        count_user_secrets(&owner_db.connection(), DEFAULT_TEST_SECRET_ID),
        1,
        "owner: expected one user_secrets row after the v1 publish"
    );
    let owner_user_secrets = SqliteUserSecretStore::new(owner_db.connection());
    let snapshot = owner_user_secrets
        .load_latest(DEFAULT_TEST_SECRET_ID)
        .await
        .expect("user_secrets load failed")
        .expect("user_secrets row must exist");
    assert_eq!(snapshot.version, 1);
    assert_eq!(snapshot.description.as_deref(), Some("v1 publish"));
    assert_eq!(snapshot.secrets.len(), 1, "v1 snapshot must hold one entry");
    assert_eq!(
        snapshot.secrets[0].data, payload,
        "user_secret payload must survive the prost round-trip through SQLite"
    );
    println!("  owner's user_secrets v1 snapshot round-trips, data bytes match  ✓");

    let payload_v2 = b"sqlite-shared-secret-v2".to_vec();
    protect_secret(
        &mut owner,
        &mut [&mut helper_a, &mut helper_b],
        UserSecret {
            id: vec![0x01],
            name: "smoke".to_owned(),
            data: payload_v2.clone(),
        },
        "v2 publish",
    )
    .await;
    for (name, db) in [
        ("HelperA", helper_a_db.connection()),
        ("HelperB", helper_b_db.connection()),
    ] {
        let store = SqliteShareStore::new(db.clone());
        let latest = store
            .latest_version(DEFAULT_TEST_SECRET_ID)
            .await
            .expect("latest_version failed");
        assert_eq!(
            latest,
            Some(2),
            "{name}: latest_version must report 2 after the v2 publish"
        );
    }
    assert_eq!(
        count_user_secrets(&owner_db.connection(), DEFAULT_TEST_SECRET_ID),
        1,
        "owner: user_secrets must remain a single row per secret_id even after v2"
    );
    let v2_snapshot = owner_user_secrets
        .load_latest(DEFAULT_TEST_SECRET_ID)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v2_snapshot.version, 2);
    assert_eq!(v2_snapshot.secrets[0].data, payload_v2);
    println!("  v2 publish: latest_version=2, user_secrets upserted in place  ✓");

    println!("✓ Sharing flow passed.\n");
}
