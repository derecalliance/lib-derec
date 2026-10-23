// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::{Target, UserSecret};
use derec_library::protocol::{DeRecFlow, DeRecShareStore, DeRecUserSecretStore};
use derec_library::types::ChannelId;
use derec_proto::{ContactMode, SenderKind};
use std::collections::HashMap;

use crate::db::{Database, SharedClient};
use crate::flows::helpers::pair_owner_helper;
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer, pump_many};
use crate::stores::{PostgresShareStore, PostgresUserSecretStore};

/// The threshold is sticky. The owner records each version's `t` on its
/// share rows and the latest `t` on its snapshot, in nullable `threshold`
/// columns; helpers record none. `ShareVerified` reports the `t` of the
/// verified version after a later round changed it, a publish the library
/// starts itself splits at the stored `t` rather than the builder's, and a
/// NULL column reads back as no threshold.
pub async fn run() {
    println!("=== [Threshold] sticky threshold per version ===");

    let owner_db = Database::open_isolated().await;
    let helper_dbs = [
        Database::open_isolated().await,
        Database::open_isolated().await,
        Database::open_isolated().await,
        Database::open_isolated().await,
    ];

    // The builder says 2.
    let mut owner = Peer::new(owner_db.client(), "Owner", "https://owner.example.com");
    let mut a = Peer::new(
        helper_dbs[0].client(),
        "HelperA",
        "https://helper-a.example.com",
    );
    let mut b = Peer::new(
        helper_dbs[1].client(),
        "HelperB",
        "https://helper-b.example.com",
    );
    let mut c = Peer::new(
        helper_dbs[2].client(),
        "HelperC",
        "https://helper-c.example.com",
    );
    let mut d = Peer::new(
        helper_dbs[3].client(),
        "HelperD",
        "https://helper-d.example.com",
    );

    let cid_a = pair_owner_helper(&mut owner, &mut a, ChannelId(1)).await;
    let cid_b = pair_owner_helper(&mut owner, &mut b, ChannelId(2)).await;
    let cid_c = pair_owner_helper(&mut owner, &mut c, ChannelId(3)).await;
    let channels = [cid_a, cid_b, cid_c];

    // v1 at the builder's t = 2, v2 at an explicit t = 3.
    publish(&mut owner, &mut [&mut a, &mut b, &mut c], b"v1", None).await;
    publish(&mut owner, &mut [&mut a, &mut b, &mut c], b"v2", Some(3)).await;

    let owner_store = PostgresShareStore::new(owner_db.client());
    for (version, expected) in [(1, 2), (2, 3)] {
        for channel_id in channels {
            let shares = owner_store
                .load(DEFAULT_TEST_SECRET_ID, channel_id, &[version])
                .await
                .expect("owner share load failed");
            assert_eq!(
                shares.iter().map(|s| s.threshold).collect::<Vec<_>>(),
                vec![Some(expected)],
                "owner's v{version} row must record t = {expected}"
            );
            assert_eq!(
                threshold_column(&owner_db.client(), channel_id, version).await,
                Some(i64::from(expected)),
                "owner's v{version} row must persist t in the threshold column"
            );
        }
    }
    println!("  owner rows record v1 t=2, v2 t=3 (column holds the value)  ✓");

    for (db, channel_id) in helper_dbs.iter().zip(channels) {
        let shares = PostgresShareStore::new(db.client())
            .load(DEFAULT_TEST_SECRET_ID, channel_id, &[1])
            .await
            .expect("helper share load failed");
        assert_eq!(
            shares.iter().map(|s| s.threshold).collect::<Vec<_>>(),
            vec![None],
            "a helper's stored share must carry no threshold"
        );
        assert_eq!(
            threshold_column(&db.client(), channel_id, 1).await,
            None,
            "a helper's threshold column must be NULL"
        );
    }
    println!("  helper rows carry no threshold (column is NULL)  ✓");

    let snapshot = PostgresUserSecretStore::new(owner_db.client())
        .load_latest(DEFAULT_TEST_SECRET_ID)
        .await
        .expect("snapshot load failed")
        .expect("a snapshot is stored");
    assert_eq!(snapshot.threshold, Some(3), "the snapshot stores t = 3");
    println!("  snapshot stores t=3  ✓");

    let verified = verify(&mut owner, &mut [&mut a, &mut b, &mut c], 1, Target::All).await;
    assert_eq!(
        verified,
        sorted(channels.iter().map(|c| (c.0, Some(2))).collect()),
        "ShareVerified must report the t v1 was split with"
    );
    println!("  ShareVerified v1 reports t=2 after v2 changed it  ✓");

    // Pairing HelperD makes the library publish v3 on its own: it splits at
    // the stored t = 3, not the builder's 2.
    let contact = owner
        .protocol
        .create_contact(Some(ChannelId(4)), ContactMode::InlineKeys, None)
        .await
        .expect("owner.create_contact failed");
    d.protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact,
            peer_communication_info: HashMap::new(),
        })
        .await
        .expect("HelperD start(Pairing) failed");
    let events = pump_many(&mut [&mut owner, &mut a, &mut b, &mut c, &mut d]).await;
    let cid_d = events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::PairingCompleted { channel_id, .. } => Some(*channel_id),
            _ => None,
        })
        .expect("HelperD pairing must complete");
    for channel_id in [cid_a, cid_b, cid_c, cid_d] {
        assert_eq!(
            threshold_column(&owner_db.client(), channel_id, 3).await,
            Some(3),
            "the library-started publish must split at the stored t = 3"
        );
    }
    println!("  the pairing publish (v3) splits at the stored t=3, not the builder's 2  ✓");

    // NULL columns read back as no threshold.
    owner_db
        .client()
        .execute(
            "UPDATE shares SET threshold = NULL \
             WHERE secret_id = $1 AND channel_id = $2 AND version = 1",
            &[&(DEFAULT_TEST_SECRET_ID as i64), &(cid_a.0 as i64)],
        )
        .await
        .expect("clearing the share threshold failed");
    let verified = verify(
        &mut owner,
        &mut [&mut a, &mut b, &mut c, &mut d],
        1,
        Target::Single(cid_a),
    )
    .await;
    assert_eq!(
        verified,
        vec![(cid_a.0, None)],
        "an owner row whose threshold column is NULL must verify with no threshold"
    );
    owner_db
        .client()
        .execute(
            "UPDATE user_secrets SET threshold = NULL WHERE secret_id = $1",
            &[&(DEFAULT_TEST_SECRET_ID as i64)],
        )
        .await
        .expect("clearing the snapshot threshold failed");
    let snapshot = PostgresUserSecretStore::new(owner_db.client())
        .load_latest(DEFAULT_TEST_SECRET_ID)
        .await
        .expect("snapshot load failed")
        .expect("a snapshot is stored");
    assert_eq!(
        snapshot.threshold, None,
        "a NULL snapshot column reads as None"
    );
    println!("  NULL share and snapshot columns read back as no threshold  ✓");

    println!("✓ Threshold flow passed.\n");
}

async fn publish(owner: &mut Peer, helpers: &mut [&mut Peer], data: &[u8], threshold: Option<u32>) {
    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: vec![0x01],
                name: "sticky".to_owned(),
                data: data.to_vec(),
            }],
            description: None,
            weights: HashMap::new(),
            threshold,
        })
        .await
        .expect("owner.start(ProtectSecret) failed");
    let mut all: Vec<&mut Peer> = vec![owner];
    all.extend(helpers.iter_mut().map(|h| &mut **h));
    pump_many(&mut all).await;
}

/// `(channel, threshold)` of every `ShareVerified` the round produced, sorted
/// by channel.
async fn verify(
    owner: &mut Peer,
    helpers: &mut [&mut Peer],
    version: u32,
    target: Target,
) -> Vec<(u64, Option<u32>)> {
    owner
        .protocol
        .start(DeRecFlow::VerifyShares {
            secret_id: DEFAULT_TEST_SECRET_ID,
            version,
            target,
        })
        .await
        .expect("owner.start(VerifyShares) failed");
    let mut all: Vec<&mut Peer> = vec![owner];
    all.extend(helpers.iter_mut().map(|h| &mut **h));
    let events = pump_many(&mut all).await;
    let mut verified: Vec<(u64, Option<u32>)> = events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::ShareVerified {
                channel_id,
                version: v,
                threshold,
                ..
            } if *v == version => Some((channel_id.0, *threshold)),
            _ => None,
        })
        .collect();
    verified.sort_unstable();
    verified
}

fn sorted(mut pairs: Vec<(u64, Option<u32>)>) -> Vec<(u64, Option<u32>)> {
    pairs.sort_unstable();
    pairs
}

async fn threshold_column(
    client: &SharedClient,
    channel_id: ChannelId,
    version: u32,
) -> Option<i64> {
    client
        .query_one(
            "SELECT threshold FROM shares \
             WHERE secret_id = $1 AND channel_id = $2 AND version = $3",
            &[
                &(DEFAULT_TEST_SECRET_ID as i64),
                &(channel_id.0 as i64),
                &i64::from(version),
            ],
        )
        .await
        .expect("share row must exist")
        .get(0)
}
