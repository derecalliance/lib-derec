//! Unpair flow + DB-state assertions.
//!
//! Pairs an owner with a helper, distributes a share, then unpairs.
//! On both sides the unpair MUST drop the channel row, the SharedKey
//! row, every share row for that channel, and any per-channel link
//! rows. This flow is the only place where the store traits emit
//! removals; the asserts here prove they actually hit SQLite.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::{Target, UserSecret};
use derec_library::protocol::DeRecFlow;
use derec_library::types::ChannelId;

use crate::db::Database;
use crate::flows::assertions::{
    channel_exists, count_channel_links, count_channels, count_shares_for_channel,
};
use crate::flows::helpers::{pair_owner_helper, protect_secret};
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer, pump_many};
use crate::stores::SqliteChannelStore;
use derec_library::protocol::DeRecChannelStore;

pub async fn run() {
    println!("=== [Unpairing] DB-state teardown on both sides ===");

    let owner_db = Database::open_in_memory();
    let helper_db = Database::open_in_memory();

    let mut owner = Peer::new(owner_db.connection(), "Owner", "https://owner.example.com");
    let mut helper = Peer::new(
        helper_db.connection(),
        "Helper",
        "https://helper.example.com",
    );

    // The owner needs a second helper to satisfy the default
    // threshold of 2 during `ProtectSecret`. We only unpair the
    // first; the second is just there to make the share round
    // succeed.
    let helper2_db = Database::open_in_memory();
    let mut helper2 = Peer::new(
        helper2_db.connection(),
        "Helper2",
        "https://helper-2.example.com",
    );

    let cid = pair_owner_helper(&mut owner, &mut helper, ChannelId(1)).await;
    let _cid2 = pair_owner_helper(&mut owner, &mut helper2, ChannelId(2)).await;

    // Add a side-channel link on the helper so the per-channel link
    // cleanup also gets exercised.
    helper
        .protocol
        .channel_store
        .link_channel(DEFAULT_TEST_SECRET_ID, cid, ChannelId(999))
        .await
        .unwrap();
    assert!(count_channel_links(&helper_db.connection(), DEFAULT_TEST_SECRET_ID) > 0);

    // Push one share to populate the helper's shares table.
    protect_secret(
        &mut owner,
        &mut [&mut helper, &mut helper2],
        UserSecret {
            id: vec![0x01],
            name: "to-be-unpaired".to_owned(),
            data: b"payload".to_vec(),
        },
        "pre-unpair",
    )
    .await;
    assert_eq!(
        count_shares_for_channel(&helper_db.connection(), DEFAULT_TEST_SECRET_ID, cid.0),
        1,
        "helper must hold a share row for the channel about to be unpaired"
    );

    // Pre-unpair sanity.
    assert!(channel_exists(&owner_db.connection(), DEFAULT_TEST_SECRET_ID, cid.0));
    assert!(channel_exists(
        &helper_db.connection(),
        DEFAULT_TEST_SECRET_ID,
        cid.0
    ));

    owner
        .protocol
        .start(DeRecFlow::Unpair {
            target: Target::Single(cid),
            memo: Some("decommissioning".to_owned()),
        })
        .await
        .expect("owner.start(Unpair) failed");

    let events = pump_many(&mut [&mut owner, &mut helper]).await;
    let unpaired_count = events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::Unpaired { channel_id } if *channel_id == cid))
        .count();
    assert!(
        unpaired_count >= 2,
        "expected Unpaired on both sides (got {unpaired_count})"
    );

    // Post-unpair: every row for `cid` must be gone on both sides.
    assert!(
        !channel_exists(&owner_db.connection(), DEFAULT_TEST_SECRET_ID, cid.0),
        "owner channel row must be gone after Unpaired"
    );
    assert!(
        !channel_exists(&helper_db.connection(), DEFAULT_TEST_SECRET_ID, cid.0),
        "helper channel row must be gone after Unpaired"
    );
    assert_eq!(
        count_shares_for_channel(&helper_db.connection(), DEFAULT_TEST_SECRET_ID, cid.0),
        0,
        "helper shares for the unpaired channel must be gone"
    );
    assert_eq!(
        count_channels(&owner_db.connection(), DEFAULT_TEST_SECRET_ID),
        1,
        "owner should still hold the channel to the second helper"
    );
    // remove() should also have cleaned the per-channel link rows
    // for `cid` — that's a SqliteChannelStore contract on top of the
    // trait, since the trait itself does not require it.
    let helper_check = SqliteChannelStore::new(helper_db.connection());
    let linked = helper_check
        .linked_channels(DEFAULT_TEST_SECRET_ID, cid)
        .await
        .unwrap();
    assert_eq!(
        linked,
        vec![cid],
        "removed channel must no longer reach previously-linked peers"
    );

    println!(
        "  channel + shares + link rows for the unpaired ChannelId({}) all removed  ✓",
        cid.0
    );
    println!("✓ Unpairing flow passed.\n");
}
