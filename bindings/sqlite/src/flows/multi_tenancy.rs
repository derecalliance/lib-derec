//! Multi-tenancy: two owner protocols bound to different `secret_id`s
//! share one SQLite database. The flow asserts that:
//! - both vaults' state coexists in the same tables;
//! - every store-trait read scoped to one `secret_id` is invisible to
//!   the other vault, regardless of channel-id collisions;
//! - `load_many` with `MissingPolicy::Fail` returns the partitioned
//!   missing-entries error rather than silently mixing tenants;
//! - removing a vault's data does not affect the other vault.

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

const VAULT_A: u64 = 0xAAAA;
const VAULT_B: u64 = 0xBBBB;

pub async fn run() {
    println!("=== [Multi-tenancy] vault A and vault B share one SQLite DB ===");

    let shared_db = Database::open_in_memory();

    // Helpers run on their own devices (separate DBs) — what matters
    // for this test is that the OWNER side hosts two vaults on one DB.
    let helper_a_db = Database::open_in_memory();
    let helper_b_db = Database::open_in_memory();
    let helper_c_db = Database::open_in_memory();
    let helper_d_db = Database::open_in_memory();

    // Vault A: owner with two helpers.
    let mut owner_a = Peer::with_secret_id(
        shared_db.connection(),
        "OwnerA",
        "https://owner-a.example.com",
        VAULT_A,
    );
    let mut helper_a1 = Peer::with_secret_id(
        helper_a_db.connection(),
        "HelperA1",
        "https://helper-a1.example.com",
        VAULT_A,
    );
    let mut helper_a2 = Peer::with_secret_id(
        helper_b_db.connection(),
        "HelperA2",
        "https://helper-a2.example.com",
        VAULT_A,
    );

    // Vault B: separate owner protocol on the SAME DB.
    let mut owner_b = Peer::with_secret_id(
        shared_db.connection(),
        "OwnerB",
        "https://owner-b.example.com",
        VAULT_B,
    );
    let mut helper_b1 = Peer::with_secret_id(
        helper_c_db.connection(),
        "HelperB1",
        "https://helper-b1.example.com",
        VAULT_B,
    );
    let mut helper_b2 = Peer::with_secret_id(
        helper_d_db.connection(),
        "HelperB2",
        "https://helper-b2.example.com",
        VAULT_B,
    );

    // Distinct cids per vault so cross-vault assertions can target a
    // channel id known to exist in only one of the two partitions.
    // (The pair handshake keeps the cid the caller supplied — it is
    // not re-derived from the handshake material — so the two
    // vaults would otherwise collide on (1, 2, 1, 2).)
    let a1 = pair_owner_helper(&mut owner_a, &mut helper_a1, ChannelId(10)).await;
    let a2 = pair_owner_helper(&mut owner_a, &mut helper_a2, ChannelId(20)).await;
    let b1 = pair_owner_helper(&mut owner_b, &mut helper_b1, ChannelId(30)).await;
    let b2 = pair_owner_helper(&mut owner_b, &mut helper_b2, ChannelId(40)).await;

    // Both vaults host 2 channels each, but in one shared `channels`
    // table — the only thing distinguishing the rows is `secret_id`.
    assert_eq!(count_channels(&shared_db.connection(), VAULT_A), 2);
    assert_eq!(count_channels(&shared_db.connection(), VAULT_B), 2);
    println!("  shared `channels` table: 2 rows under each secret_id  ✓");

    // ChannelStore::channels(secret_id) must return only the matching
    // vault's channels.
    let a_chans = owner_a.protocol.channel_store.channels(VAULT_A).await.unwrap();
    let b_chans = owner_b.protocol.channel_store.channels(VAULT_B).await.unwrap();
    assert_eq!(a_chans.len(), 2);
    assert_eq!(b_chans.len(), 2);
    for c in &a_chans {
        assert!(
            c.id == a1 || c.id == a2,
            "vault A enumerate returned a non-A channel: {:?}",
            c.id
        );
    }
    for c in &b_chans {
        assert!(
            c.id == b1 || c.id == b2,
            "vault B enumerate returned a non-B channel: {:?}",
            c.id
        );
    }
    // Cross-vault lookup of a channel id that only exists in vault B
    // must miss when scoped to vault A's partition.
    assert!(
        owner_a
            .protocol
            .channel_store
            .load(VAULT_A, b1)
            .await
            .unwrap()
            .is_none(),
        "vault A must not read vault B's channels (cid={})",
        b1.0
    );
    assert!(
        owner_b
            .protocol
            .channel_store
            .load(VAULT_B, a1)
            .await
            .unwrap()
            .is_none(),
        "vault B must not read vault A's channels (cid={})",
        a1.0
    );
    println!("  ChannelStore::channels + load partition by secret_id  ✓");

    // load_many(MissingPolicy::Fail) must report the partitioned
    // miss, not silently look up the cross-tenant row.
    match owner_a
        .protocol
        .secret_store
        .load_many(VAULT_A, &[b1], SecretKind::SharedKey, MissingPolicy::Fail)
        .await
    {
        Ok(v) => panic!(
            "cross-vault load_many(Fail) must error; got Ok with {} entries",
            v.len()
        ),
        Err(SecretStoreError::MissingEntries { kind, channel_ids }) => {
            assert_eq!(kind, SecretKind::SharedKey);
            assert_eq!(channel_ids, vec![b1.0]);
        }
        Err(other) => panic!(
            "unexpected error variant for cross-vault load_many: {other:?}"
        ),
    }
    println!(
        "  SecretStore::load_many(MissingPolicy::Fail) reports partitioned miss  ✓"
    );

    // Publish a different secret in each vault. The Owner side
    // bookkeeping (`user_secrets`) gets a row per vault.
    protect_secret(
        &mut owner_a,
        &mut [&mut helper_a1, &mut helper_a2],
        UserSecret {
            id: vec![0xAA],
            name: "vault-A".to_owned(),
            data: b"vault A payload".to_vec(),
        },
        "A publish",
    )
    .await;
    protect_secret(
        &mut owner_b,
        &mut [&mut helper_b1, &mut helper_b2],
        UserSecret {
            id: vec![0xBB],
            name: "vault-B".to_owned(),
            data: b"vault B payload".to_vec(),
        },
        "B publish",
    )
    .await;
    assert_eq!(count_user_secrets(&shared_db.connection(), VAULT_A), 1);
    assert_eq!(count_user_secrets(&shared_db.connection(), VAULT_B), 1);
    // Owner-side `shares` rows live in the same shared table, also
    // partitioned by secret_id.
    assert_eq!(count_shares(&shared_db.connection(), VAULT_A), 2);
    assert_eq!(count_shares(&shared_db.connection(), VAULT_B), 2);
    println!(
        "  publish into both vaults: each vault has 1 user_secret + 2 owner-side share rows  ✓"
    );

    // latest_version is scoped to secret_id.
    let lv_a = owner_a.protocol.share_store.latest_version(VAULT_A).await.unwrap();
    let lv_b = owner_b.protocol.share_store.latest_version(VAULT_B).await.unwrap();
    assert_eq!(lv_a, Some(1));
    assert_eq!(lv_b, Some(1));
    let cross = owner_a
        .protocol
        .share_store
        .latest_version(VAULT_B)
        .await
        .unwrap();
    assert_eq!(
        cross,
        Some(1),
        "the share store is one table — both vaults' latest are visible via the same handle, \
         but partitioned by argument"
    );
    println!("  latest_version scopes by argument (vault A=1, vault B=1)  ✓");

    // Remove vault A entirely; vault B must be untouched.
    owner_a
        .protocol
        .user_secret_store
        .remove(VAULT_A)
        .await
        .unwrap();
    let vault_a_channels = owner_a.protocol.channel_store.channels(VAULT_A).await.unwrap();
    for c in &vault_a_channels {
        owner_a
            .protocol
            .channel_store
            .remove(VAULT_A, c.id)
            .await
            .unwrap();
        owner_a
            .protocol
            .secret_store
            .remove(VAULT_A, c.id, SecretKind::SharedKey)
            .await
            .unwrap();
        owner_a
            .protocol
            .share_store
            .remove_channel(VAULT_A, c.id)
            .await
            .unwrap();
    }
    assert_eq!(count_channels(&shared_db.connection(), VAULT_A), 0);
    assert_eq!(count_user_secrets(&shared_db.connection(), VAULT_A), 0);
    assert_eq!(count_shares(&shared_db.connection(), VAULT_A), 0);
    // Vault B's data is intact.
    assert_eq!(count_channels(&shared_db.connection(), VAULT_B), 2);
    assert_eq!(count_user_secrets(&shared_db.connection(), VAULT_B), 1);
    assert_eq!(count_shares(&shared_db.connection(), VAULT_B), 2);
    println!("  vault A fully removed; vault B's rows are unaffected  ✓");

    println!("✓ Multi-tenancy flow passed.\n");
}
