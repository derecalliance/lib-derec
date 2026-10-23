// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::{Target, UserSecret};
use derec_library::protocol::{DeRecFlow, DeRecShareStore};
use derec_library::types::ChannelId;
use std::collections::HashMap;

use crate::db::{Database, SharedClient};
use crate::flows::helpers::pair_owner_helper;
use crate::peer::{DEFAULT_TEST_SECRET_ID, Peer, PeerOptions, pump_many};
use crate::stores::PostgresShareStore;

/// The owner records each helper's subshare count on its share rows, in the
/// nullable `subshares` column; helpers record none. `ShareVerified` reports
/// the count of the verified version, which a later re-weight leaves intact,
/// and a row whose column is NULL verifies with no count.
pub async fn run() {
    println!("=== [Subshares] owner-side subshare count per share ===");

    let owner_db = Database::open_isolated().await;
    let helper_a_db = Database::open_isolated().await;
    let helper_b_db = Database::open_isolated().await;

    let mut owner = Peer::with_options(
        owner_db.client(),
        "Owner",
        "https://owner.example.com",
        PeerOptions {
            threshold: 3,
            ..Default::default()
        },
    );
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

    publish(
        &mut owner,
        &mut helper_a,
        &mut helper_b,
        &[(cid_a, 2)],
        b"v1",
    )
    .await;

    let owner_store = PostgresShareStore::new(owner_db.client());
    for (name, channel_id, expected) in [("HelperA", cid_a, 2), ("HelperB", cid_b, 1)] {
        let shares = owner_store
            .load(DEFAULT_TEST_SECRET_ID, channel_id, &[1])
            .await
            .expect("owner share load failed");
        assert_eq!(
            shares.iter().map(|s| s.subshares).collect::<Vec<_>>(),
            vec![Some(expected)],
            "owner's v1 row for {name} must record {expected} subshares"
        );
        assert_eq!(
            subshares_column(&owner_db.client(), channel_id, 1).await,
            Some(i64::from(expected)),
            "owner's v1 row for {name} must persist the count in the subshares column"
        );
    }
    println!("  owner rows record subshares A=2, B=1 (column holds the value)  ✓");

    for (name, db, channel_id) in [
        ("HelperA", helper_a_db.client(), cid_a),
        ("HelperB", helper_b_db.client(), cid_b),
    ] {
        let shares = PostgresShareStore::new(db.clone())
            .load(DEFAULT_TEST_SECRET_ID, channel_id, &[1])
            .await
            .expect("helper share load failed");
        assert_eq!(
            shares.iter().map(|s| s.subshares).collect::<Vec<_>>(),
            vec![None],
            "{name}'s stored share must carry no subshare count"
        );
        assert_eq!(
            subshares_column(&db, channel_id, 1).await,
            None,
            "{name}'s subshares column must be NULL"
        );
    }
    println!("  helper rows carry no count (column is NULL)  ✓");

    let verified = verify(&mut owner, &mut helper_a, &mut helper_b, 1, Target::All).await;
    assert_eq!(
        verified,
        sorted(vec![(cid_a.0, Some(2)), (cid_b.0, Some(1))]),
        "ShareVerified must report each helper's v1 count"
    );
    println!("  ShareVerified v1 reports A=2, B=1  ✓");

    publish(
        &mut owner,
        &mut helper_a,
        &mut helper_b,
        &[(cid_b, 2)],
        b"v2",
    )
    .await;
    for (channel_id, expected) in [(cid_a, 1), (cid_b, 2)] {
        assert_eq!(
            subshares_column(&owner_db.client(), channel_id, 2).await,
            Some(expected),
            "owner's v2 row for channel {} must record the re-weighted count",
            channel_id.0
        );
    }
    let verified = verify(&mut owner, &mut helper_a, &mut helper_b, 1, Target::All).await;
    assert_eq!(
        verified,
        sorted(vec![(cid_a.0, Some(2)), (cid_b.0, Some(1))]),
        "after re-weighting in v2, verifying v1 must still report v1's counts"
    );
    println!("  re-weighted v2 (A=1, B=2); verifying v1 still reports A=2, B=1  ✓");

    owner_db
        .client()
        .execute(
            "UPDATE shares SET subshares = NULL \
             WHERE secret_id = $1 AND channel_id = $2 AND version = 1",
            &[&(DEFAULT_TEST_SECRET_ID as i64), &(cid_a.0 as i64)],
        )
        .await
        .expect("clearing the count failed");
    let verified = verify(
        &mut owner,
        &mut helper_a,
        &mut helper_b,
        1,
        Target::Single(cid_a),
    )
    .await;
    assert_eq!(
        verified,
        vec![(cid_a.0, None)],
        "an owner row whose subshares column is NULL must verify with no count"
    );
    println!("  a NULL owner row verifies with subshares=None  ✓");

    println!("✓ Subshares flow passed.\n");
}

async fn publish(
    owner: &mut Peer,
    helper_a: &mut Peer,
    helper_b: &mut Peer,
    weights: &[(ChannelId, u32)],
    data: &[u8],
) {
    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: vec![0x01],
                name: "weighted".to_owned(),
                data: data.to_vec(),
            }],
            description: None,
            weights: weights.iter().copied().collect::<HashMap<_, _>>(),
            threshold: None,
        })
        .await
        .expect("owner.start(ProtectSecret) failed");
    pump_many(&mut [owner, helper_a, helper_b]).await;
}

/// `(channel, subshares)` of every `ShareVerified` the round produced, sorted
/// by channel.
async fn verify(
    owner: &mut Peer,
    helper_a: &mut Peer,
    helper_b: &mut Peer,
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
    let events = pump_many(&mut [owner, helper_a, helper_b]).await;
    let mut verified: Vec<(u64, Option<u32>)> = events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::ShareVerified {
                channel_id,
                version: v,
                subshares,
                ..
            } if *v == version => Some((channel_id.0, *subshares)),
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

async fn subshares_column(
    client: &SharedClient,
    channel_id: ChannelId,
    version: u32,
) -> Option<i64> {
    client
        .query_one(
            "SELECT subshares FROM shares \
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
