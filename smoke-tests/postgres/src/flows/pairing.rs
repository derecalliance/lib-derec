// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::types::{
    ChannelQuery, ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, ReplicaRole,
};
use derec_library::protocol::{
    DeRecChannelStore, DeRecSecretStore, ExpiredChannelCleanup, SecretKind, SecretValue,
};
use derec_library::types::{ChannelId, ReplicaId};
use derec_proto::{ContactMode, Protocol, SenderKind, TransportProtocol};
use std::collections::{HashMap, HashSet};

use crate::db::Database;
use crate::flows::assertions::{channel_exists, count_channels, count_secrets};
use crate::flows::helpers::{pair_owner_helper, pair_owner_helper_with_mode};
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer, PeerOptions};
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
    no_keys_fingerprint_mismatch_revokes_the_pairing().await;
    expired_pending_pairing_loses_its_key().await;

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

            owner
                .protocol
                .verify_fingerprint(channel, &helper_fp)
                .await
                .expect("owner verify_fingerprint");
            helper
                .protocol
                .verify_fingerprint(channel, &owner_fp)
                .await
                .expect("helper verify_fingerprint");

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

/// A wrong `NoKeys` comparison is the MITM case — the two sides derived
/// different shared keys — so the comparing side revokes the pairing: neither
/// its channel record nor any key of it survives in the database. The peer's
/// side is untouched, since it has compared nothing.
async fn no_keys_fingerprint_mismatch_revokes_the_pairing() {
    let owner_db = Database::open_isolated().await;
    let helper_db = Database::open_isolated().await;
    let mut owner = Peer::new(owner_db.client(), "Owner", "https://owner.example.com");
    let mut helper = Peer::new(helper_db.client(), "Helper", "https://helper.example.com");

    let channel =
        pair_owner_helper_with_mode(&mut owner, &mut helper, ChannelId(910), ContactMode::NoKeys)
            .await;
    assert_eq!(
        channel_status(&mut owner, channel).await,
        ChannelStatus::Pending,
        "an unverified NoKeys channel is held Pending"
    );

    let err = owner
        .protocol
        .verify_fingerprint(channel, "0000-0000-0000-0000")
        .await
        .expect_err("a mismatched fingerprint must not verify");
    assert!(
        matches!(err, derec_library::Error::FingerprintMismatch { channel_id } if channel_id == channel),
        "expected FingerprintMismatch, got {err:?}"
    );
    println!("  NoKeys verify_fingerprint(wrong) fails with FingerprintMismatch  ✓");

    assert!(
        !channel_exists(&owner_db.client(), DEFAULT_TEST_SECRET_ID, channel.0).await,
        "a failed comparison must remove the owner's channel row"
    );
    assert_eq!(
        count_secrets(&owner_db.client(), DEFAULT_TEST_SECRET_ID).await,
        0,
        "a failed comparison must remove the owner's SharedKey and pairing material"
    );
    assert!(
        !has_shared_key(&PostgresSecretStore::new(owner_db.client()), channel).await,
        "a failed comparison must remove the owner's SharedKey"
    );
    println!("  owner channel row and SharedKey removed from the database  ✓");

    assert_eq!(
        channel_status(&mut helper, channel).await,
        ChannelStatus::Pending,
        "the helper has compared nothing, so its channel stays Pending"
    );
    assert!(
        has_shared_key(&PostgresSecretStore::new(helper_db.client()), channel).await,
        "the helper keeps its SharedKey"
    );
    println!("  helper channel row (Pending) and SharedKey untouched  ✓");
}

/// An expired `Pending` pairing goes with its channel key, for a helper and
/// for a replica peer alike; a `Paired` channel of the same age is kept.
/// The automatic sweep is disabled so only the caller-driven one runs.
async fn expired_pending_pairing_loses_its_key() {
    let db = Database::open_isolated().await;
    let mut owner = Peer::with_expired_channel_cleanup(
        db.client(),
        "Owner",
        "https://owner.example.com",
        PeerOptions {
            replica_id: Some(13),
            ..Default::default()
        },
        ExpiredChannelCleanup::Disabled,
    );
    seed_channel(&mut owner, seeded_helper(6161, ChannelStatus::Pending)).await;
    seed_channel(&mut owner, seeded_member(6162, 0xbeef)).await;
    seed_channel(&mut owner, seeded_helper(6163, ChannelStatus::Paired)).await;

    let removed = owner
        .protocol
        .remove_expired_channels(60)
        .await
        .expect("remove_expired_channels");
    assert!(
        removed.contains(&ChannelId(6161)) && removed.contains(&ChannelId(6162)),
        "both expired pending pairings must be swept, got {removed:?}"
    );
    assert!(
        !removed.contains(&ChannelId(6163)),
        "a paired channel is never swept, got {removed:?}"
    );
    println!("  remove_expired_channels(60) sweeps 6161 and 6162, keeps 6163  ✓");

    let channels = PostgresChannelStore::new(db.client());
    let secrets = PostgresSecretStore::new(db.client());
    let helper_query = |id: u64| ChannelQuery::Helper {
        channel_id: ChannelId(id),
    };
    let member_query = ChannelQuery::Replica {
        channel_id: ChannelId(6162),
        replica_id: ReplicaId(0xbeef),
    };
    for (channel_id, query) in [(6161, helper_query(6161)), (6162, member_query)] {
        assert!(
            channels
                .load(DEFAULT_TEST_SECRET_ID, query)
                .await
                .expect("channel load failed")
                .is_none(),
            "channel {channel_id}: an expired pending pairing must not leave its row"
        );
        assert!(
            !has_shared_key(&secrets, ChannelId(channel_id)).await,
            "channel {channel_id}: an expired pending pairing must not leave its key"
        );
    }
    println!("  rows and SharedKeys of 6161 and 6162 removed from the database  ✓");

    assert!(
        channels
            .load(DEFAULT_TEST_SECRET_ID, helper_query(6163))
            .await
            .expect("channel load failed")
            .is_some(),
        "the paired channel keeps its row"
    );
    assert!(
        has_shared_key(&secrets, ChannelId(6163)).await,
        "the paired channel keeps its key"
    );
    assert_eq!(
        count_secrets(&db.client(), DEFAULT_TEST_SECRET_ID).await,
        1,
        "only the paired channel's key remains"
    );
    println!("  paired channel 6163 of the same age keeps its row and SharedKey  ✓");
}

fn seeded_endpoint() -> TransportProtocol {
    TransportProtocol {
        uri: "https://peer.example.com".to_owned(),
        protocol: Protocol::Https as i32,
    }
}

fn seeded_helper(channel_id: u64, status: ChannelStatus) -> ChannelRecord {
    ChannelRecord::Helper(HelperChannel {
        channel_id: ChannelId(channel_id),
        transports: vec![seeded_endpoint()],
        communication_info: HashMap::new(),
        status,
        created_at: 1_700_000_000,
        peer_role: SenderKind::Helper,
        weight: 1,
    })
}

fn seeded_member(channel_id: u64, replica_id: u64) -> ChannelRecord {
    ChannelRecord::Replica(ReplicaMember {
        channel_id: ChannelId(channel_id),
        replica_id: ReplicaId(replica_id),
        transports: vec![seeded_endpoint()],
        communication_info: HashMap::new(),
        role: ReplicaRole::Destination,
        status: ChannelStatus::Pending,
        created_at: 1_700_000_000,
    })
}

/// Write a channel record and its SharedKey through the peer's SQL stores.
async fn seed_channel(peer: &mut Peer, record: ChannelRecord) {
    let channel_id = record.channel_id();
    peer.protocol
        .channel_store
        .save(DEFAULT_TEST_SECRET_ID, record)
        .await
        .expect("seed channel record");
    peer.protocol
        .secret_store
        .save(
            DEFAULT_TEST_SECRET_ID,
            channel_id,
            SecretValue::SharedKey(std::array::from_fn(|i| (i * 11 + 5) as u8)),
        )
        .await
        .expect("seed channel key");
}

async fn has_shared_key(secrets: &PostgresSecretStore, channel_id: ChannelId) -> bool {
    secrets
        .load(DEFAULT_TEST_SECRET_ID, channel_id, SecretKind::SharedKey)
        .await
        .expect("SharedKey load failed")
        .is_some()
}
