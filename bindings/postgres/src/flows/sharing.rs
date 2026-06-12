//! Sharing flow + Postgres persistence assertions.
//!
//! Drives a full `ProtectSecret` round between an owner and two
//! helpers, then asserts that:
//! - each helper's `shares` table has a row keyed by
//!   `(secret_id, channel_id, version)`, and `Share.secret_id` was
//!   denormalized correctly,
//! - the owner's `user_secrets` row carries the v1 snapshot and the
//!   prost-encoded payload round-trips back to the original bytes,
//! - `latest_version(secret_id)` reports the right number on the
//!   owner after each sharing round (1 after one publish, 2 after
//!   the next).
//!
//! Note: `latest_version` on the helper reflects the version space of
//! shares the helper has received, which is the owner's published
//! version verbatim.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::UserSecret;
use derec_library::protocol::DeRecShareStore;
use derec_library::protocol::DeRecUserSecretStore;
use derec_library::types::ChannelId;

use crate::db::Database;
use crate::flows::assertions::{count_shares, count_shares_for_channel, count_user_secrets};
use crate::flows::helpers::{pair_owner_helper, protect_secret};
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer};
use crate::stores::{PostgresShareStore, PostgresUserSecretStore};

pub async fn run() {
    println!("=== [Sharing] persisted shares + user_secrets snapshot ===");

    let owner_db = Database::open_isolated().await;
    let helper_a_db = Database::open_isolated().await;
    let helper_b_db = Database::open_isolated().await;

    let mut owner = Peer::new(owner_db.client(), "Owner", "https://owner.example.com");
    let mut helper_a = Peer::new(
        helper_a_db.client(),
        "HelperA",
        "https://helper-a.example.com",
    );
    let mut helper_b = Peer::new(
        helper_b_db.client(),
        "HelperB",
        "https://helper-b.example.com",
    );

    let cid_a = pair_owner_helper(&mut owner, &mut helper_a, ChannelId(1)).await;
    let cid_b = pair_owner_helper(&mut owner, &mut helper_b, ChannelId(2)).await;
    println!("  paired Owner↔HelperA({}), Owner↔HelperB({})", cid_a.0, cid_b.0);

    // ProtectSecret round #1.
    let payload = b"postgres-shared-secret".to_vec();
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

    // Helpers have stored their share rows.
    for (name, db, channel_id) in [
        ("HelperA", helper_a_db.client(), cid_a.0),
        ("HelperB", helper_b_db.client(), cid_b.0),
    ] {
        assert_eq!(
            count_shares(&db, DEFAULT_TEST_SECRET_ID).await,
            1,
            "{name}: expected exactly one share row after v1 publish"
        );
        assert_eq!(
            count_shares_for_channel(&db, DEFAULT_TEST_SECRET_ID, channel_id).await,
            1,
            "{name}: share row must live under the helper-owner channel"
        );
        // `Share.secret_id` denormalized field must match the partition key.
        let store = PostgresShareStore::new(db.clone());
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

    // Owner has the latest UserSecrets snapshot persisted, and the
    // payload bytes round-trip through Postgres.
    assert_eq!(
        count_user_secrets(&owner_db.client(), DEFAULT_TEST_SECRET_ID).await,
        1,
        "owner: expected one user_secrets row after the v1 publish"
    );
    let owner_user_secrets = PostgresUserSecretStore::new(owner_db.client());
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
        "user_secret payload must survive the prost round-trip through Postgres"
    );
    println!("  owner's user_secrets v1 snapshot round-trips, data bytes match  ✓");

    // ProtectSecret round #2 — owner publishes again with new bytes.
    // Verifies the upsert paths on `shares` (replaces v1→v2 by version)
    // and on `user_secrets` (single-row-per-secret_id discipline).
    let payload_v2 = b"postgres-shared-secret-v2".to_vec();
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
        ("HelperA", helper_a_db.client()),
        ("HelperB", helper_b_db.client()),
    ] {
        let store = PostgresShareStore::new(db.clone());
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
        count_user_secrets(&owner_db.client(), DEFAULT_TEST_SECRET_ID).await,
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
