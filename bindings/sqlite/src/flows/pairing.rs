//! Pair flow + SQLite persistence assertions.
//!
//! Validates that after a successful Owner↔Helper pair handshake:
//! - each side's `channels` row exists in its own backing DB,
//! - each side stores a `SharedKey` row of the same 32 bytes,
//! - `Channel.role` is the LOCAL role on each side, and
//! - `linked_channels(c)` returns `[c]` for an unlinked channel; and
//!   `link_channel(a, b)` is undirected, idempotent, and transitive.
//!
//! Each simulated peer owns its own in-memory database — a real
//! device wouldn't share a DB with the peer on the other side of the
//! network. The multi-tenancy flow is the one place where two
//! protocols deliberately share one connection.

use derec_library::protocol::{DeRecChannelStore, SecretKind};
use derec_library::types::ChannelId;
use derec_proto::SenderKind;
use std::collections::HashSet;

use crate::db::Database;
use crate::flows::assertions::{channel_exists, count_channels, count_secrets};
use crate::flows::helpers::pair_owner_helper;
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer};
use crate::stores::{SqliteChannelStore, SqliteSecretStore};

pub async fn run() {
    println!("=== [Pairing] persisted state on both sides ===");

    let owner_db = Database::open_in_memory();
    let helper_db = Database::open_in_memory();

    let mut owner = Peer::new(owner_db.connection(), "Owner", "https://owner.example.com");
    let mut helper = Peer::new(
        helper_db.connection(),
        "Helper",
        "https://helper.example.com",
    );

    let final_id = pair_owner_helper(&mut owner, &mut helper, ChannelId(1)).await;
    println!("  Owner↔Helper paired on ChannelId({})", final_id.0);

    // (a) channels row populated on each device.
    for (name, conn) in [("owner", owner_db.connection()), ("helper", helper_db.connection())] {
        assert_eq!(
            count_channels(&conn, DEFAULT_TEST_SECRET_ID),
            1,
            "{name}: expected exactly 1 channel row after pair"
        );
        assert!(
            channel_exists(&conn, DEFAULT_TEST_SECRET_ID, final_id.0),
            "{name}: channel row for the paired ChannelId must exist"
        );
    }
    println!("  channels row present on both devices  ✓");

    // (b) Channel.role records the LOCAL role on each side.
    let owner_check = SqliteChannelStore::new(owner_db.connection());
    let helper_check = SqliteChannelStore::new(helper_db.connection());
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

    // (c) Both sides stored the SharedKey, byte-identical.
    for (name, conn) in [("owner", owner_db.connection()), ("helper", helper_db.connection())] {
        assert!(
            count_secrets(&conn, DEFAULT_TEST_SECRET_ID) >= 1,
            "{name}: expected at least 1 SharedKey row"
        );
    }
    let owner_secrets = SqliteSecretStore::new(owner_db.connection());
    let helper_secrets = SqliteSecretStore::new(helper_db.connection());
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
    println!("  SharedKey 32B round-trips through SQLite and matches on both sides  ✓");

    // (d) linked_channels contract. Use the owner DB.
    let mut link_store = SqliteChannelStore::new(owner_db.connection());
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
    // Idempotent: re-linking must not error or double up.
    link_store
        .link_channel(DEFAULT_TEST_SECRET_ID, a, b)
        .await
        .unwrap();
    // Undirected + transitive: walking from c must reach a.
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
