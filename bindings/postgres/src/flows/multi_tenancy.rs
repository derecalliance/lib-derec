//! Multi-tenancy: two owner protocols bound to different `secret_id`s
//! share one Postgres database. The flow asserts that:
//! - both secrets' state coexists in the same tables;
//! - every store-trait read scoped to one `secret_id` is invisible to
//!   the other secret, regardless of channel-id collisions;
//! - `load_many` with `MissingPolicy::Fail` returns the partitioned
//!   missing-entries error rather than silently mixing tenants;
//! - removing one secret's data does not affect the other secret.

use derec_library::protocol::types::UserSecret;
use derec_library::protocol::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecUserSecretStore, MissingPolicy,
    SecretKind, SecretStoreError,
};
use derec_library::types::ChannelId;

use crate::db::Database;
use crate::flows::assertions::{
    count_channels, count_shares, count_user_secrets,
};
use crate::flows::helpers::{pair_owner_helper, protect_secret};
use crate::peer::Peer;

const SECRET_A_ID: u64 = 0xAAAA;
const SECRET_B_ID: u64 = 0xBBBB;

pub async fn run() {
    println!("=== [Multi-tenancy] secret A and secret B share one Postgres DB ===");

    let shared_db = Database::open_isolated().await;

    // Helpers run on their own devices (separate DBs) — what matters
    // for this test is that the OWNER side hosts two secrets on one DB.
    let helper_a_db = Database::open_isolated().await;
    let helper_b_db = Database::open_isolated().await;
    let helper_c_db = Database::open_isolated().await;
    let helper_d_db = Database::open_isolated().await;

    // Secret A: owner with two helpers.
    let mut owner_a = Peer::with_secret_id(
        shared_db.client(),
        "OwnerA",
        "https://owner-a.example.com",
        SECRET_A_ID,
    );
    let mut helper_a1 = Peer::with_secret_id(
        helper_a_db.client(),
        "HelperA1",
        "https://helper-a1.example.com",
        SECRET_A_ID,
    );
    let mut helper_a2 = Peer::with_secret_id(
        helper_b_db.client(),
        "HelperA2",
        "https://helper-a2.example.com",
        SECRET_A_ID,
    );

    // Secret B: separate owner protocol on the SAME DB.
    let mut owner_b = Peer::with_secret_id(
        shared_db.client(),
        "OwnerB",
        "https://owner-b.example.com",
        SECRET_B_ID,
    );
    let mut helper_b1 = Peer::with_secret_id(
        helper_c_db.client(),
        "HelperB1",
        "https://helper-b1.example.com",
        SECRET_B_ID,
    );
    let mut helper_b2 = Peer::with_secret_id(
        helper_d_db.client(),
        "HelperB2",
        "https://helper-b2.example.com",
        SECRET_B_ID,
    );

    // Distinct cids per secret so cross-secret assertions can target a
    // channel id known to exist in only one of the two partitions.
    // (The pair handshake keeps the cid the caller supplied — it is
    // not re-derived from the handshake material — so the two
    // secrets would otherwise collide on (1, 2, 1, 2).)
    let a1 = pair_owner_helper(&mut owner_a, &mut helper_a1, ChannelId(10)).await;
    let a2 = pair_owner_helper(&mut owner_a, &mut helper_a2, ChannelId(20)).await;
    let b1 = pair_owner_helper(&mut owner_b, &mut helper_b1, ChannelId(30)).await;
    let b2 = pair_owner_helper(&mut owner_b, &mut helper_b2, ChannelId(40)).await;

    // Both secrets host 2 channels each, but in one shared `channels`
    // table — the only thing distinguishing the rows is `secret_id`.
    assert_eq!(count_channels(&shared_db.client(), SECRET_A_ID).await, 2);
    assert_eq!(count_channels(&shared_db.client(), SECRET_B_ID).await, 2);
    println!("  shared `channels` table: 2 rows under each secret_id  ✓");

    // ChannelStore::channels(secret_id) must return only the matching
    // secret's channels.
    let a_chans = owner_a.protocol.channel_store.channels(SECRET_A_ID).await.unwrap();
    let b_chans = owner_b.protocol.channel_store.channels(SECRET_B_ID).await.unwrap();
    assert_eq!(a_chans.len(), 2);
    assert_eq!(b_chans.len(), 2);
    for c in &a_chans {
        assert!(
            c.id == a1 || c.id == a2,
            "secret A enumerate returned a non-A channel: {:?}",
            c.id
        );
    }
    for c in &b_chans {
        assert!(
            c.id == b1 || c.id == b2,
            "secret B enumerate returned a non-B channel: {:?}",
            c.id
        );
    }
    // Cross-secret lookup of a channel id that only exists in secret B
    // must miss when scoped to secret A's partition.
    assert!(
        owner_a
            .protocol
            .channel_store
            .load(SECRET_A_ID, b1)
            .await
            .unwrap()
            .is_none(),
        "secret A must not read secret B's channels (cid={})",
        b1.0
    );
    assert!(
        owner_b
            .protocol
            .channel_store
            .load(SECRET_B_ID, a1)
            .await
            .unwrap()
            .is_none(),
        "secret B must not read secret A's channels (cid={})",
        a1.0
    );
    println!("  ChannelStore::channels + load partition by secret_id  ✓");

    // load_many(MissingPolicy::Fail) must report the partitioned
    // miss, not silently look up the cross-tenant row.
    match owner_a
        .protocol
        .secret_store
        .load_many(SECRET_A_ID, &[b1], SecretKind::SharedKey, MissingPolicy::Fail)
        .await
    {
        Ok(v) => panic!(
            "cross-secret load_many(Fail) must error; got Ok with {} entries",
            v.len()
        ),
        Err(SecretStoreError::MissingEntries { kind, channel_ids }) => {
            assert_eq!(kind, SecretKind::SharedKey);
            assert_eq!(channel_ids, vec![b1.0]);
        }
        Err(other) => panic!(
            "unexpected error variant for cross-secret load_many: {other:?}"
        ),
    }
    println!(
        "  SecretStore::load_many(MissingPolicy::Fail) reports partitioned miss  ✓"
    );

    // Publish a different secret on each side. The Owner side
    // bookkeeping (`user_secrets`) gets a row per secret_id.
    protect_secret(
        &mut owner_a,
        &mut [&mut helper_a1, &mut helper_a2],
        UserSecret {
            id: vec![0xAA],
            name: "secret-A".to_owned(),
            data: b"secret A payload".to_vec(),
        },
        "A publish",
    )
    .await;
    protect_secret(
        &mut owner_b,
        &mut [&mut helper_b1, &mut helper_b2],
        UserSecret {
            id: vec![0xBB],
            name: "secret-B".to_owned(),
            data: b"secret B payload".to_vec(),
        },
        "B publish",
    )
    .await;
    assert_eq!(count_user_secrets(&shared_db.client(), SECRET_A_ID).await, 1);
    assert_eq!(count_user_secrets(&shared_db.client(), SECRET_B_ID).await, 1);
    // Owner-side `shares` rows live in the same shared table, also
    // partitioned by secret_id.
    assert_eq!(count_shares(&shared_db.client(), SECRET_A_ID).await, 2);
    assert_eq!(count_shares(&shared_db.client(), SECRET_B_ID).await, 2);
    println!(
        "  publish into both secrets: each has 1 user_secret + 2 owner-side share rows  ✓"
    );

    // latest_version is scoped to secret_id.
    let lv_a = owner_a.protocol.share_store.latest_version(SECRET_A_ID).await.unwrap();
    let lv_b = owner_b.protocol.share_store.latest_version(SECRET_B_ID).await.unwrap();
    assert_eq!(lv_a, Some(1));
    assert_eq!(lv_b, Some(1));
    let cross = owner_a
        .protocol
        .share_store
        .latest_version(SECRET_B_ID)
        .await
        .unwrap();
    assert_eq!(
        cross,
        Some(1),
        "the share store is one table — both secrets' latest are visible via the same handle, \
         but partitioned by argument"
    );
    println!("  latest_version scopes by argument (secret A=1, secret B=1)  ✓");

    // Remove secret A entirely; secret B must be untouched.
    owner_a
        .protocol
        .user_secret_store
        .remove(SECRET_A_ID)
        .await
        .unwrap();
    let secret_a_channels = owner_a.protocol.channel_store.channels(SECRET_A_ID).await.unwrap();
    for c in &secret_a_channels {
        owner_a
            .protocol
            .channel_store
            .remove(SECRET_A_ID, c.id)
            .await
            .unwrap();
        owner_a
            .protocol
            .secret_store
            .remove(SECRET_A_ID, c.id, SecretKind::SharedKey)
            .await
            .unwrap();
        owner_a
            .protocol
            .share_store
            .remove_channel(SECRET_A_ID, c.id)
            .await
            .unwrap();
    }
    assert_eq!(count_channels(&shared_db.client(), SECRET_A_ID).await, 0);
    assert_eq!(count_user_secrets(&shared_db.client(), SECRET_A_ID).await, 0);
    assert_eq!(count_shares(&shared_db.client(), SECRET_A_ID).await, 0);
    // Secret B's data is intact.
    assert_eq!(count_channels(&shared_db.client(), SECRET_B_ID).await, 2);
    assert_eq!(count_user_secrets(&shared_db.client(), SECRET_B_ID).await, 1);
    assert_eq!(count_shares(&shared_db.client(), SECRET_B_ID).await, 2);
    println!("  secret A fully removed; secret B's rows are unaffected  ✓");

    println!("✓ Multi-tenancy flow passed.\n");
}
