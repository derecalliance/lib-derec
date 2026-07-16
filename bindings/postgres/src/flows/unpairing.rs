// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::UserSecret;
use derec_library::protocol::DeRecFlow;
use derec_library::types::ChannelId;

use crate::db::Database;
use crate::flows::assertions::{
    channel_exists, count_channel_links, count_channels, count_shares_for_channel,
};
use crate::flows::helpers::{pair_owner_helper, protect_secret};
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer, pump_many};
use crate::stores::PostgresChannelStore;
use derec_library::protocol::DeRecChannelStore;

pub async fn run() {
    println!("=== [Unpairing] DB-state teardown on both sides ===");

    let owner_db = Database::open_isolated().await;
    let helper_db = Database::open_isolated().await;

    let mut owner = Peer::new(owner_db.client(), "Owner", "https://owner.example.com");
    let mut helper = Peer::new(
        helper_db.client(),
        "Helper",
        "https://helper.example.com",
    );

    let helper2_db = Database::open_isolated().await;
    let mut helper2 = Peer::new(
        helper2_db.client(),
        "Helper2",
        "https://helper-2.example.com",
    );

    let cid = pair_owner_helper(&mut owner, &mut helper, ChannelId(1)).await;
    let _cid2 = pair_owner_helper(&mut owner, &mut helper2, ChannelId(2)).await;

    helper
        .protocol
        .channel_store
        .link_channel(DEFAULT_TEST_SECRET_ID, cid, ChannelId(999))
        .await
        .unwrap();
    assert!(count_channel_links(&helper_db.client(), DEFAULT_TEST_SECRET_ID).await > 0);

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
        count_shares_for_channel(&helper_db.client(), DEFAULT_TEST_SECRET_ID, cid.0).await,
        1,
        "helper must hold a share row for the channel about to be unpaired"
    );

    assert!(channel_exists(&owner_db.client(), DEFAULT_TEST_SECRET_ID, cid.0).await);
    assert!(channel_exists(&helper_db.client(), DEFAULT_TEST_SECRET_ID, cid.0).await);

    owner
        .protocol
        .start(DeRecFlow::Unpair {
            channel_id: cid,
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

    assert!(
        !channel_exists(&owner_db.client(), DEFAULT_TEST_SECRET_ID, cid.0).await,
        "owner channel row must be gone after Unpaired"
    );
    assert!(
        !channel_exists(&helper_db.client(), DEFAULT_TEST_SECRET_ID, cid.0).await,
        "helper channel row must be gone after Unpaired"
    );
    assert_eq!(
        count_shares_for_channel(&helper_db.client(), DEFAULT_TEST_SECRET_ID, cid.0).await,
        0,
        "helper shares for the unpaired channel must be gone"
    );
    assert_eq!(
        count_channels(&owner_db.client(), DEFAULT_TEST_SECRET_ID).await,
        1,
        "owner should still hold the channel to the second helper"
    );
    let helper_check = PostgresChannelStore::new(helper_db.client());
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
