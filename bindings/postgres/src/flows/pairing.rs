// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::types::{ChannelQuery, ChannelStatus};
use derec_library::protocol::{DeRecChannelStore, SecretKind};
use derec_library::types::ChannelId;
use derec_proto::{ContactMode, SenderKind};
use std::collections::HashSet;

use crate::db::Database;
use crate::flows::assertions::{channel_exists, count_channels, count_secrets};
use crate::flows::helpers::{pair_owner_helper, pair_owner_helper_with_mode};
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer};
use crate::stores::{PostgresChannelStore, PostgresSecretStore};

pub async fn run() {
    println!("=== [Pairing] persisted state on both sides ===");

    let owner_db = Database::open_isolated().await;
    let helper_db = Database::open_isolated().await;

    let mut owner = Peer::new(owner_db.client(), "Owner", "https://owner.example.com");
    let mut helper = Peer::new(helper_db.client(), "Helper", "https://helper.example.com");

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
        .load(
            DEFAULT_TEST_SECRET_ID,
            ChannelQuery::Helper {
                channel_id: final_id,
            },
        )
        .await
        .expect("owner channel load failed")
        .expect("owner channel must exist");
    let helper_channel = helper_check
        .load(
            DEFAULT_TEST_SECRET_ID,
            ChannelQuery::Helper {
                channel_id: final_id,
            },
        )
        .await
        .expect("helper channel load failed")
        .expect("helper channel must exist");
    let owner_channel = owner_channel
        .as_helper()
        .expect("an owner-helper pairing stores a helper channel");
    let helper_channel = helper_channel
        .as_helper()
        .expect("an owner-helper pairing stores a helper channel");
    assert_eq!(owner_channel.peer_role, SenderKind::Helper);
    assert_eq!(helper_channel.peer_role, SenderKind::Owner);
    println!("  Channel.peer_role names the other end on each side  ✓");

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
    println!("  link_channel: undirected + idempotent + transitive (a—b—c → {{a,b,c}})  ✓");

    every_contact_mode_pairs_and_persists().await;

    println!("✓ Pairing flow passed.\n");
}

/// All three contact modes must reach the same persisted end state, and
/// `NoKeys` must reach it only after the fingerprint is confirmed.
///
/// `HashedKeys` and `NoKeys` add a `PrePair` round-trip before the handshake
/// proper, and this backend only ever exercised `InlineKeys` — so two of the
/// three were never proven to persist anything here at all.
///
/// The rows the three modes leave behind are identical; the channel *status*
/// is not. `NoKeys` inlines neither the keys nor a commitment to them, so
/// nothing binds what the scanner received to the contact that was delivered
/// out of band. Its channel is held `Pending` — unusable for sharing — until
/// `verify_fingerprint` confirms both sides derived the same shared key.
async fn every_contact_mode_pairs_and_persists() {
    for (i, mode) in [
        ContactMode::InlineKeys,
        ContactMode::HashedKeys,
        ContactMode::NoKeys,
    ]
    .into_iter()
    .enumerate()
    {
        let owner_db = Database::open_isolated().await;
        let helper_db = Database::open_isolated().await;
        let mut owner = Peer::new(owner_db.client(), "Owner", "https://owner.example.com");
        let mut helper = Peer::new(helper_db.client(), "Helper", "https://helper.example.com");

        let transient = ChannelId(900 + i as u64);
        let channel = pair_owner_helper_with_mode(&mut owner, &mut helper, transient, mode).await;

        // Every mode rekeys onto a long-term id derived from the shared key.
        // The responder cannot pick it: the initiator re-derives the same value
        // and rejects any other, so this holds regardless of contact mode.
        assert_ne!(
            channel, transient,
            "{mode:?}: the long-term channel id must differ from the transient pairing id"
        );

        for (label, db) in [("owner", &owner_db), ("helper", &helper_db)] {
            assert!(
                channel_exists(&db.client(), DEFAULT_TEST_SECRET_ID, channel.0).await,
                "{label} must hold the paired channel after a {mode:?} handshake"
            );
            assert_eq!(
                count_secrets(&db.client(), DEFAULT_TEST_SECRET_ID).await,
                1,
                "{label} keeps exactly the shared key after a {mode:?} handshake — \
                 no transient pairing material may survive"
            );
        }

        let expected = if mode == ContactMode::NoKeys {
            ChannelStatus::Pending
        } else {
            ChannelStatus::Paired
        };
        for (label, peer) in [("owner", &mut owner), ("helper", &mut helper)] {
            assert_eq!(
                channel_status(peer, channel).await,
                expected,
                "{label} channel status after a {mode:?} handshake"
            );
        }

        if mode == ContactMode::NoKeys {
            let owner_fp = owner
                .protocol
                .get_fingerprint(channel)
                .await
                .expect("owner get_fingerprint");
            let helper_fp = helper
                .protocol
                .get_fingerprint(channel)
                .await
                .expect("helper get_fingerprint");
            assert_eq!(owner_fp, helper_fp, "both sides derive one fingerprint");

            assert!(
                owner
                    .protocol
                    .verify_fingerprint(channel, &helper_fp)
                    .await
                    .expect("owner verify_fingerprint")
            );
            assert!(
                helper
                    .protocol
                    .verify_fingerprint(channel, &owner_fp)
                    .await
                    .expect("helper verify_fingerprint")
            );

            for (label, peer) in [("owner", &mut owner), ("helper", &mut helper)] {
                assert_eq!(
                    channel_status(peer, channel).await,
                    ChannelStatus::Paired,
                    "{label} NoKeys channel must be usable once confirmed"
                );
            }
        }
    }
    println!("  InlineKeys, HashedKeys and NoKeys all persist the same end state  ✓");
    println!("  NoKeys is held Pending until the fingerprint is confirmed  ✓");
}

async fn channel_status(peer: &mut Peer, channel_id: ChannelId) -> ChannelStatus {
    peer.protocol
        .channel_store
        .load(DEFAULT_TEST_SECRET_ID, ChannelQuery::Helper { channel_id })
        .await
        .expect("channel_store.load")
        .expect("channel present")
        .status()
}
