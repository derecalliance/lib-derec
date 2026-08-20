// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! End-to-end lifecycle over Postgres, with **no protocol state held between
//! operations**.
//!
//! Every peer here is a [`StatelessPeer`]: it owns a database, an endpoint and
//! its configuration, and builds a throwaway `DeRecProtocol` for each
//! operation. That is the deployment shape of a service running as serverless
//! functions, where nothing survives an invocation but what was written down.
//! If any flow depended on in-process state, it would fail here rather than in
//! production.
//!
//! The cast is a realistic one — one owner, seven helper devices (five paired
//! at any time) and three replica devices — driven through the sequence a real
//! user would produce over the life of an account:
//!
//! | Step | What happens |
//! |---|---|
//! | 1 | Owner pairs with five helpers |
//! | 2 | Owner protects three secrets across two versions |
//! | 3 | Owner loses its device and recovers from the helpers |
//! | 4 | Owner unpairs two helpers and pairs two replacements |
//! | 5 | Owner admits its first replica device |
//! | 6 | Owner loses its device again and recovers, roster included |
//! | 7 | Owner admits two more replica devices |
//! | 8 | Owner protects two further secrets, syncing helpers and replicas |
//! | 9 | Owner removes a replica from the group |
//! | 10 | A helper goes silent; a scheduled `tick` closes the stranded round |
//!
//! After every step each participant's **whole** row-set is asserted — all
//! seven tables at once, not just the one the step was expected to touch, so a
//! step that writes where it should not is caught rather than ignored.

use std::collections::HashMap;

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::{Secret, Target, UserSecret};
use derec_library::protocol::{DeRecChannelStore, DeRecFlow};
use derec_library::types::ChannelId;
use derec_proto::{ContactMode, SenderKind};

use crate::db::Database;
use crate::flows::assertions::{
    Tables, assert_tables, replica_ids, share_versions, snapshot, snapshot_version,
};
use crate::peer::PeerOptions;
use crate::stateless::{StatelessPeer, deliver, pump, pump_tolerating_stale};

/// The partition every peer in this scenario stores under.
const SECRET_ID: u64 = 0x0005_CE1A;
/// Five helpers, threshold three: the secret survives losing two of them.
const THRESHOLD: usize = 3;

const REPLICA_OWNER: u64 = 0x0A11_CE01;
const REPLICA_TWO: u64 = 0x0A11_CE02;
const REPLICA_THREE: u64 = 0x0A11_CE03;
const REPLICA_FOUR: u64 = 0x0A11_CE04;

/// A helper device: its database plus the peer that speaks for it.
struct HelperDevice {
    /// Held for the lifetime of the scenario: the schema is this device's
    /// entire persistent storage.
    #[allow(dead_code)]
    db: Database,
    peer: StatelessPeer,
    /// Set once paired; the channel the owner reaches it on.
    channel: Option<ChannelId>,
}

impl HelperDevice {
    async fn new(label: &str, uri: &str) -> Self {
        let db = Database::open_isolated().await;
        let peer = StatelessPeer::new(
            db.client(),
            label,
            uri,
            PeerOptions {
                secret_id: SECRET_ID,
                threshold: THRESHOLD,
                replica_id: None,
            },
        );
        Self {
            db,
            peer,
            channel: None,
        }
    }
}

/// A replica device — another device belonging to the same user, holding the
/// whole secret rather than a share.
struct ReplicaDevice {
    /// Held for the lifetime of the scenario: the schema is this device's
    /// entire persistent storage.
    #[allow(dead_code)]
    db: Database,
    peer: StatelessPeer,
    replica_id: u64,
}

impl ReplicaDevice {
    async fn new(label: &str, uri: &str, replica_id: u64) -> Self {
        let db = Database::open_isolated().await;
        let peer = StatelessPeer::new(
            db.client(),
            label,
            uri,
            PeerOptions {
                secret_id: SECRET_ID,
                threshold: THRESHOLD,
                replica_id: Some(replica_id),
            },
        );
        Self {
            db,
            peer,
            replica_id,
        }
    }
}

pub async fn run() {
    println!("=== [E2E stateless] full account lifecycle, protocol rebuilt per operation ===");

    let mut owner_db = Database::open_isolated().await;
    let mut owner = StatelessPeer::new(
        owner_db.client(),
        "Owner",
        "https://owner.example.com",
        PeerOptions {
            secret_id: SECRET_ID,
            threshold: THRESHOLD,
            replica_id: Some(REPLICA_OWNER),
        },
    );

    let mut helpers: Vec<HelperDevice> = Vec::new();
    for i in 1..=5u32 {
        helpers.push(
            HelperDevice::new(
                Box::leak(format!("Helper{i}").into_boxed_str()),
                &format!("https://helper-{i}.example.com"),
            )
            .await,
        );
    }
    // Two spare devices, paired in step 4 to replace the two dropped there.
    let mut spares: Vec<HelperDevice> = Vec::new();
    for i in 6..=7u32 {
        spares.push(
            HelperDevice::new(
                Box::leak(format!("Helper{i}").into_boxed_str()),
                &format!("https://helper-{i}.example.com"),
            )
            .await,
        );
    }

    let mut replicas: Vec<ReplicaDevice> = Vec::new();
    for (i, rid) in [REPLICA_TWO, REPLICA_THREE, REPLICA_FOUR]
        .into_iter()
        .enumerate()
    {
        replicas.push(
            ReplicaDevice::new(
                Box::leak(format!("Replica{}", i + 2).into_boxed_str()),
                &format!("https://replica-{}.example.com", i + 2),
                rid,
            )
            .await,
        );
    }

    step_1_pair_helpers(&owner, &mut helpers).await;
    let secrets = step_2_protect_secrets(&owner, &helpers).await;
    step_3_recover_after_device_loss(&mut owner, &mut owner_db, &mut helpers, &secrets).await;
    let retired = step_4_rotate_helpers(&owner, &mut helpers, &mut spares).await;
    step_5_admit_first_replica(&owner, &helpers, &mut replicas).await;
    step_6_recover_with_a_replica_in_the_roster(
        &mut owner,
        &mut owner_db,
        &mut helpers,
        &replicas[..1],
        &secrets,
    )
    .await;
    step_7_admit_remaining_replicas(&owner, &helpers, &mut replicas).await;
    let secrets = step_8_protect_more_secrets(&owner, &helpers, &replicas, secrets).await;
    step_9_remove_a_replica(&owner, &helpers, &mut replicas, &secrets).await;
    step_10_a_silent_helper_is_resolved_by_a_scheduled_tick(&mut owner, &helpers, &replicas, &secrets)
        .await;
    assert!(!retired.is_empty(), "step 4 retired two helper devices");

    let total: usize = owner.invocations()
        + helpers.iter().map(|h| h.peer.invocations()).sum::<usize>()
        + replicas.iter().map(|r| r.peer.invocations()).sum::<usize>();
    println!(
        "  {total} protocol instances built across the scenario ({} by the owner) — \
         one per operation, none reused",
        owner.invocations()
    );

    println!("✓ E2E stateless flow passed.\n");
}

// ---------------------------------------------------------------------------
// Step 4 — helper rotation
// ---------------------------------------------------------------------------

/// Drop two helpers and take on two replacements — routine hygiene when a
/// helper is decommissioned or a friend changes phone.
///
/// Unpairing is destructive on both sides but strictly per-channel: the
/// remaining helpers, and every other channel on the leaving helper, are
/// untouched.
async fn step_4_rotate_helpers(
    owner: &StatelessPeer,
    helpers: &mut Vec<HelperDevice>,
    spares: &mut Vec<HelperDevice>,
) -> Vec<HelperDevice> {
    let mut retired: Vec<HelperDevice> = Vec::new();

    for _ in 0..2 {
        let helper = helpers.pop().expect("five helpers were paired");
        let channel = helper.channel.expect("helper is paired");

        owner
            .session()
            .start(DeRecFlow::Unpair {
                channel_id: channel,
                memo: Some("rotating this helper out".to_owned()),
            })
            .await
            .unwrap_or_else(|e| panic!("[{}] start(Unpair) failed: {e}", helper.peer.label));

        let mut cast: Vec<&StatelessPeer> = vec![owner, &helper.peer];
        cast.extend(helpers.iter().map(|h| &h.peer));
        pump(&cast).await;

        retired.push(helper);
    }

    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 4 (after unpairing 2)",
        Tables {
            channels: 3,
            secrets: 3,
            shares: 3,
            user_secrets: 1,
            ..Default::default()
        },
    )
    .await;

    for (i, spare) in spares.drain(..).enumerate() {
        let mut spare = spare;
        let transient = ChannelId(3000 + i as u64);
        let channel = {
            let cast: Vec<&StatelessPeer> = std::iter::once(owner)
                .chain(helpers.iter().map(|h| &h.peer))
                .chain(std::iter::once(&spare.peer))
                .collect();
            pair_helper(owner, &spare.peer, transient, &cast).await
        };
        spare.channel = Some(channel);
        helpers.push(spare);
    }

    // Admitting a helper republishes, so the newcomer is never left holding
    // nothing. Each pairing is therefore a version:
    //   v3 goes to the 3 survivors + spare #6   → 4 rows
    //   v4 goes to those 4 + spare #7           → 5 rows
    // on top of the 3 rows the owner still held at v2.
    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 4",
        Tables {
            channels: 5,
            secrets: 5,
            shares: 3 + 4 + 5,
            user_secrets: 1,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        share_versions(&owner.client(), SECRET_ID).await,
        vec![2, 3, 4],
        "one version per admission, on top of the recovered v2"
    );

    // Each helper holds exactly the versions published since it joined: the
    // survivors have all four, spare #6 has v3 and v4, spare #7 only v4.
    let expected_shares = [4, 4, 4, 2, 1];
    for (helper, shares) in helpers.iter().zip(expected_shares) {
        assert_tables(
            &helper.peer.client(),
            SECRET_ID,
            &helper.peer.label,
            "step 4",
            Tables {
                channels: 1,
                secrets: 1,
                shares,
                ..Default::default()
            },
        )
        .await;
        assert!(
            share_versions(&helper.peer.client(), SECRET_ID)
                .await
                .contains(&4),
            "[{}] every paired helper holds the newest version",
            helper.peer.label
        );
    }

    // The retired devices kept nothing: unpair is destructive on both sides.
    for helper in retired.iter() {
        assert_tables(
            &helper.peer.client(),
            SECRET_ID,
            &helper.peer.label,
            "step 4 (retired)",
            Tables::default(),
        )
        .await;
    }
    println!(
        "  step 4: 2 helpers retired (state fully dropped) and 2 admitted at v3/v4 — \
         all 5 current helpers hold the newest version  ✓"
    );

    retired
}

// ---------------------------------------------------------------------------
// Step 5 — first replica
// ---------------------------------------------------------------------------

/// Admit a second device of the same user into a replica group.
///
/// Unlike a helper, a replica holds the **whole** secret, so admission is
/// followed by a full sync: the new device ends up able to publish on its own.
async fn step_5_admit_first_replica(
    owner: &StatelessPeer,
    helpers: &[HelperDevice],
    replicas: &mut [ReplicaDevice],
) {
    let replica = &replicas[0];
    admit_replica(owner, helpers, &[], replica, ChannelId(4000)).await;

    assert_eq!(
        replica_ids(&owner.client(), SECRET_ID).await,
        vec![REPLICA_OWNER, REPLICA_TWO],
        "the owner's roster names itself and the admitted device"
    );
    assert_eq!(
        replica_ids(&replica.peer.client(), SECRET_ID).await,
        vec![REPLICA_OWNER, REPLICA_TWO],
        "the admitted device holds the same roster"
    );
    assert_eq!(
        snapshot_version(&replica.peer.client(), SECRET_ID).await,
        snapshot_version(&owner.client(), SECRET_ID).await,
        "the replica is at the owner's version after admission"
    );
    // The owner gains a sixth `secrets` row — the group channel key — and the
    // admission publish (v5) adds one share row per helper.
    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 5",
        Tables {
            channels: 5,
            replica_members: 2,
            secrets: 6,
            shares: 12 + 5,
            user_secrets: 1,
            ..Default::default()
        },
    )
    .await;
    assert_replica(replica, "step 5", 2).await;
    assert_helpers(helpers, "step 5", 1).await;
    println!("  step 5: replica admitted — roster of 2 on both devices, replica synced  ✓");
}

// ---------------------------------------------------------------------------
// Step 6 — recovery with a replica group in place
// ---------------------------------------------------------------------------

/// Lose the owner device again, now that the protected secret carries a
/// replica roster.
///
/// The roster travels *inside* the secret, so recovering the secret must
/// restore group membership too — otherwise a recovered device would silently
/// forget its own other devices.
async fn step_6_recover_with_a_replica_in_the_roster(
    owner: &mut StatelessPeer,
    owner_db: &mut Database,
    helpers: &mut [HelperDevice],
    replicas: &[ReplicaDevice],
    expected: &[UserSecret],
) {
    let before = replica_ids(&owner.client(), SECRET_ID).await;
    assert_eq!(before.len(), 2, "precondition: a two-member group exists");

    let fresh_db = Database::open_isolated().await;
    owner.reinstall(fresh_db.client());
    *owner_db = fresh_db;

    let (version, recovered) = recover_from_helpers(owner, helpers, 5000).await;
    assert_secrets_round_tripped(&recovered, expected, "step 6");
    assert_eq!(
        recovered.replicas.as_ref().map(|g| g.members.len()),
        Some(2),
        "the recovered secret carries the roster, which is how membership survives"
    );

    assert_eq!(
        replica_ids(&owner.client(), SECRET_ID).await,
        before,
        "recovery must restore the replica roster, not just the user secrets"
    );
    assert_eq!(
        snapshot_version(&owner.client(), SECRET_ID).await,
        Some(version),
        "the recovered version becomes the owner's snapshot"
    );
    // Recovery resets the owner's share rows to one per helper at the
    // recovered version, exactly as in step 3 — but the roster came back with
    // it, so this is still a two-member group.
    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 6",
        Tables {
            channels: 5,
            replica_members: 2,
            secrets: 6,
            shares: 5,
            user_secrets: 1,
            ..Default::default()
        },
    )
    .await;
    assert_helpers(helpers, "step 6", 1).await;
    for replica in replicas.iter() {
        assert_replica(replica, "step 6", 2).await;
    }
    println!(
        "  step 6: owner recovered v{version} again — replica roster restored from the secret  ✓"
    );
}

// ---------------------------------------------------------------------------
// Step 7 — remaining replicas
// ---------------------------------------------------------------------------

async fn step_7_admit_remaining_replicas(
    owner: &StatelessPeer,
    helpers: &[HelperDevice],
    replicas: &mut [ReplicaDevice],
) {
    let (admitted, rest) = replicas.split_at(1);
    admit_replica(owner, helpers, admitted, &rest[0], ChannelId(6000)).await;
    let (admitted, rest) = replicas.split_at(2);
    admit_replica(owner, helpers, admitted, &rest[0], ChannelId(6001)).await;

    let expected = vec![REPLICA_OWNER, REPLICA_TWO, REPLICA_THREE, REPLICA_FOUR];
    assert_eq!(
        replica_ids(&owner.client(), SECRET_ID).await,
        expected,
        "the owner's roster names all four devices"
    );
    for replica in replicas.iter() {
        assert_eq!(
            replica_ids(&replica.peer.client(), SECRET_ID).await,
            expected,
            "[{}] every member converges on the same roster",
            replica.peer.label
        );
    }
    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 7",
        Tables {
            channels: 5,
            replica_members: 4,
            secrets: 6,
            shares: 5 + 5 + 5,
            user_secrets: 1,
            ..Default::default()
        },
    )
    .await;
    for replica in replicas.iter() {
        assert_replica(replica, "step 7", 4).await;
    }
    assert_helpers(helpers, "step 7", 3).await;
    println!("  step 7: two more replicas admitted — all 4 devices share one roster  ✓");
}

// ---------------------------------------------------------------------------
// Step 8 — protect more secrets
// ---------------------------------------------------------------------------

async fn step_8_protect_more_secrets(
    owner: &StatelessPeer,
    helpers: &[HelperDevice],
    replicas: &[ReplicaDevice],
    mut secrets: Vec<UserSecret>,
) -> Vec<UserSecret> {
    secrets.push(UserSecret {
        id: vec![4],
        name: "api tokens".to_owned(),
        data: b"sk-live-8f21c0b4d9".to_vec(),
    });
    secrets.push(UserSecret {
        id: vec![5],
        name: "passport scan".to_owned(),
        data: b"\x89PNG\r\n\x1a\n-not-really-a-png".to_vec(),
    });

    let refs: Vec<&ReplicaDevice> = replicas.iter().collect();
    protect(
        owner,
        helpers,
        &refs,
        secrets.clone(),
        "adding api tokens and passport scan",
    )
    .await;

    let version = snapshot_version(&owner.client(), SECRET_ID)
        .await
        .expect("owner holds a snapshot");

    for helper in helpers.iter() {
        assert!(
            share_versions(&helper.peer.client(), SECRET_ID)
                .await
                .contains(&(version as i64)),
            "[{}] every paired helper receives the new version",
            helper.peer.label
        );
    }
    for replica in replicas.iter() {
        assert_eq!(
            snapshot_version(&replica.peer.client(), SECRET_ID).await,
            Some(version),
            "[{}] every replica is carried to the new version",
            replica.peer.label
        );
    }
    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 8",
        Tables {
            channels: 5,
            replica_members: 4,
            secrets: 6,
            shares: 15 + 5,
            user_secrets: 1,
            ..Default::default()
        },
    )
    .await;
    for replica in replicas.iter() {
        assert_replica(replica, "step 8", 4).await;
    }
    assert_helpers(helpers, "step 8", 4).await;
    println!(
        "  step 8: 5 secrets published at v{version} — all 5 helpers and all 3 replicas current  ✓"
    );

    secrets
}

// ---------------------------------------------------------------------------
// Step 9 — remove a replica
// ---------------------------------------------------------------------------

/// Retire one of the user's devices from the group.
///
/// The evicted device is told to leave, then receives the roster that omits
/// it; only once it has seen both does it drop its copy of the secret. The
/// remaining members drop its row and carry on.
async fn step_9_remove_a_replica(
    owner: &StatelessPeer,
    helpers: &[HelperDevice],
    replicas: &mut Vec<ReplicaDevice>,
    secrets: &[UserSecret],
) {
    let evicted = replicas.pop().expect("three replicas were admitted");
    assert_eq!(evicted.replica_id, REPLICA_FOUR);

    owner
        .session()
        .start(DeRecFlow::RemoveReplica {
            replica_id: evicted.replica_id,
            memo: Some("retiring an old tablet".to_owned()),
        })
        .await
        .expect("owner.start(RemoveReplica) failed");

    // The publish that completes the removal has to reach the evictee too —
    // its absence from that roster is what tells it it may leave.
    let refs: Vec<&ReplicaDevice> = replicas.iter().chain(std::iter::once(&evicted)).collect();
    protect(
        owner,
        helpers,
        &refs,
        secrets.to_vec(),
        "roster without the retired tablet",
    )
    .await;

    let expected = vec![REPLICA_OWNER, REPLICA_TWO, REPLICA_THREE];
    assert_eq!(
        replica_ids(&owner.client(), SECRET_ID).await,
        expected,
        "the owner's roster drops the removed device"
    );
    for replica in replicas.iter() {
        assert_eq!(
            replica_ids(&replica.peer.client(), SECRET_ID).await,
            expected,
            "[{}] remaining members drop the removed row",
            replica.peer.label
        );
    }

    // The departing device tears its whole partition down — every table.
    assert_tables(
        &evicted.peer.client(),
        SECRET_ID,
        &evicted.peer.label,
        "step 9 (evicted)",
        Tables::default(),
    )
    .await;
    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 9",
        Tables {
            channels: 5,
            replica_members: 3,
            secrets: 6,
            shares: 20 + 5,
            user_secrets: 1,
            ..Default::default()
        },
    )
    .await;
    for replica in replicas.iter() {
        assert_replica(replica, "step 9", 3).await;
    }
    assert_helpers(helpers, "step 9", 5).await;
    println!(
        "  step 9: replica removed — roster of 3 on every remaining device, \
         evicted device holds nothing  ✓"
    );
}

/// Pair a replica device into the group and carry it to the current version.
///
/// Replica pairing needs the fingerprint confirmed out of band before the
/// member counts as paired, which is what promotes it from `Pending`.
async fn admit_replica(
    owner: &StatelessPeer,
    helpers: &[HelperDevice],
    already_admitted: &[ReplicaDevice],
    replica: &ReplicaDevice,
    transient: ChannelId,
) {
    let contact = owner
        .session()
        .create_contact(Some(transient), ContactMode::InlineKeys, None)
        .await
        .expect("owner.create_contact failed");
    replica
        .peer
        .session()
        .start(DeRecFlow::Pairing {
            kind: SenderKind::ReplicaDestination,
            contact,
            peer_communication_info: HashMap::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("[{}] start(Pairing) failed: {e}", replica.peer.label));

    let events = pump(&[owner, &replica.peer]).await;
    let channel = events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::PairingCompleted {
                channel_id,
                pairing_channel_id,
                ..
            } if *pairing_channel_id == transient => Some(*channel_id),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "[{}] no PairingCompleted for transient {transient:?}",
                replica.peer.label
            )
        });

    // Out-of-band fingerprint comparison — the user checking two screens match.
    let owner_fp = owner
        .session()
        .get_fingerprint(channel)
        .await
        .expect("owner fingerprint");
    let replica_fp = replica
        .peer
        .session()
        .get_fingerprint(channel)
        .await
        .expect("replica fingerprint");
    assert_eq!(
        owner_fp, replica_fp,
        "[{}] both devices must show the same fingerprint",
        replica.peer.label
    );
    assert!(
        owner
            .session()
            .verify_fingerprint(channel, &replica_fp)
            .await
            .expect("owner verify_fingerprint")
    );
    assert!(
        replica
            .peer
            .session()
            .verify_fingerprint(channel, &owner_fp)
            .await
            .expect("replica verify_fingerprint")
    );

    // Admission triggers the sync that carries the new member to the current
    // version. That publish is a full round: every helper and every member
    // already in the group receives it, not only the newcomer.
    let mut cast: Vec<&StatelessPeer> = vec![owner, &replica.peer];
    cast.extend(helpers.iter().map(|h| &h.peer));
    cast.extend(already_admitted.iter().map(|r| &r.peer));
    pump(&cast).await;
}

// ---------------------------------------------------------------------------
// Step 1 — pairing
// ---------------------------------------------------------------------------

async fn step_1_pair_helpers(owner: &StatelessPeer, helpers: &mut [HelperDevice]) {
    for i in 0..helpers.len() {
        let transient = ChannelId(1000 + i as u64);
        let channel = {
            let cast: Vec<&StatelessPeer> = std::iter::once(owner)
                .chain(helpers.iter().map(|h| &h.peer))
                .collect();
            pair_helper(owner, &helpers[i].peer, transient, &cast).await
        };
        helpers[i].channel = Some(channel);
    }

    // The owner holds one channel row and one key set per helper; helpers hold
    // the mirror image. Nothing has been protected yet, so no shares and no
    // snapshot anywhere.
    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 1",
        Tables {
            channels: 5,
            secrets: 5,
            ..Default::default()
        },
    )
    .await;
    for helper in helpers.iter() {
        assert_tables(
            &helper.peer.client(),
            SECRET_ID,
            &helper.peer.label,
            "step 1",
            Tables {
                channels: 1,
                secrets: 1,
                ..Default::default()
            },
        )
        .await;
    }
    println!("  step 1: owner paired 5 helpers — 5 channels + 5 key rows, 1 each helper-side  ✓");
}

// ---------------------------------------------------------------------------
// Step 2 — protect secrets
// ---------------------------------------------------------------------------

/// The user secrets this account holds, in the order they were added.
fn seed_secrets() -> Vec<UserSecret> {
    vec![
        UserSecret {
            id: vec![1],
            name: "wallet seed".to_owned(),
            data: b"abandon abandon abandon abandon about".to_vec(),
        },
        UserSecret {
            id: vec![2],
            name: "recovery codes".to_owned(),
            data: b"84920-11razz-77310-90a1b".to_vec(),
        },
        UserSecret {
            id: vec![3],
            name: "ssh key".to_owned(),
            data: b"-----BEGIN OPENSSH PRIVATE KEY-----".to_vec(),
        },
    ]
}

async fn step_2_protect_secrets(
    owner: &StatelessPeer,
    helpers: &[HelperDevice],
) -> Vec<UserSecret> {
    let all = seed_secrets();

    // A real account grows: two secrets first, then a third added later. Each
    // publish is a full version, so the second supersedes the first.
    protect(owner, helpers, &[], all[..2].to_vec(), "initial two secrets").await;
    assert_eq!(
        snapshot_version(&owner.client(), SECRET_ID).await,
        Some(1),
        "first publish is version 1"
    );

    protect(owner, helpers, &[], all.clone(), "adding the ssh key").await;
    assert_eq!(
        snapshot_version(&owner.client(), SECRET_ID).await,
        Some(2),
        "second publish supersedes at version 2"
    );

    // The owner keeps its own copy of every share it handed out, so its share
    // count is helpers × versions. Helpers keep only their own.
    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 2",
        Tables {
            channels: 5,
            secrets: 5,
            shares: 10,
            user_secrets: 1,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        share_versions(&owner.client(), SECRET_ID).await,
        vec![1, 2],
        "owner retains both published versions"
    );

    for helper in helpers.iter() {
        assert_tables(
            &helper.peer.client(),
            SECRET_ID,
            &helper.peer.label,
            "step 2",
            Tables {
                channels: 1,
                secrets: 1,
                shares: 2,
                ..Default::default()
            },
        )
        .await;
        assert_eq!(
            share_versions(&helper.peer.client(), SECRET_ID).await,
            vec![1, 2],
            "{} holds one share per version",
            helper.peer.label
        );
    }
    println!(
        "  step 2: 3 secrets across v1+v2 — each helper holds 2 shares, owner mirrors all 10  ✓"
    );

    all
}

// ---------------------------------------------------------------------------
// Step 3 — device loss and recovery
// ---------------------------------------------------------------------------

/// The owner's device is gone. A replacement, with the same identity and
/// endpoint but empty storage, re-pairs with each helper on a fresh channel,
/// discovers what they hold, recovers the latest version and commits it.
///
/// The helper-side `link_channel` is the application's job — recognising that
/// a new channel belongs to a returning owner is an out-of-band judgement the
/// protocol deliberately does not make.
async fn step_3_recover_after_device_loss(
    owner: &mut StatelessPeer,
    owner_db: &mut Database,
    helpers: &mut [HelperDevice],
    expected: &[UserSecret],
) {
    let fresh_db = Database::open_isolated().await;
    owner.reinstall(fresh_db.client());
    *owner_db = fresh_db;

    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 3 (post-wipe)",
        Tables::default(),
    )
    .await;

    let (recovered_version, recovered) = recover_from_helpers(owner, helpers, 2000).await;
    assert_eq!(recovered_version, 2, "the newest published version");
    assert_secrets_round_tripped(&recovered, expected, "step 3");

    let restored = snapshot_version(&owner.client(), SECRET_ID).await;
    assert_eq!(
        restored,
        Some(2),
        "restore() must commit the recovered version as the owner's snapshot"
    );

    // Post-recovery the owner is whole again: five re-paired channels, their
    // keys, the shares restore() re-derived, and the snapshot. The old
    // channels are gone with the old device.
    assert_tables(
        &owner.client(),
        SECRET_ID,
        "owner",
        "step 3",
        Tables {
            channels: 5,
            secrets: 5,
            shares: 5,
            user_secrets: 1,
            ..Default::default()
        },
    )
    .await;

    // Each helper is back to a single channel. During recovery it briefly held
    // two — the original plus the recovery-mode one, linked so the returning
    // owner could reach shares stored under the first — and restore scrapped
    // the recovery channel, taking its link rows with it.
    //
    // The shares are untouched throughout: recovery reads, it does not
    // re-publish, so both versions from step 2 still sit under the original
    // channel, which is exactly what the link existed to keep reachable.
    for helper in helpers.iter() {
        assert_tables(
            &helper.peer.client(),
            SECRET_ID,
            &helper.peer.label,
            "step 3",
            Tables {
                channels: 1,
                secrets: 1,
                shares: 2,
                ..Default::default()
            },
        )
        .await;
    }
    assert_eq!(
        share_versions(&owner.client(), SECRET_ID).await,
        vec![2],
        "the restored owner holds shares for the recovered version only"
    );
    println!(
        "  step 3: owner recovered v{recovered_version} from 5 helpers after a total device loss — \
         all {} secrets byte-identical  ✓",
        expected.len()
    );
}

// ---------------------------------------------------------------------------
// Shared operations
// ---------------------------------------------------------------------------

/// Drive an InlineKeys pair handshake between the owner and a helper.
///
/// `cast` must list every peer currently reachable, not just the two shaking
/// hands: admitting a helper re-publishes the current version to everyone
/// already paired, so those messages need somewhere to land.
async fn pair_helper(
    owner: &StatelessPeer,
    helper: &StatelessPeer,
    transient: ChannelId,
    cast: &[&StatelessPeer],
) -> ChannelId {
    let contact = owner
        .session()
        .create_contact(Some(transient), ContactMode::InlineKeys, None)
        .await
        .expect("owner.create_contact failed");

    helper
        .session()
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact,
            peer_communication_info: HashMap::from([("name".to_owned(), helper.label.clone())]),
        })
        .await
        .unwrap_or_else(|e| panic!("[{}] start(Pairing) failed: {e}", helper.label));

    let events = pump(cast).await;
    events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::PairingCompleted {
                channel_id,
                pairing_channel_id,
                ..
            } if *pairing_channel_id == transient => Some(*channel_id),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "[{}] no PairingCompleted for transient {transient:?}",
                helper.label
            )
        })
}

/// Publish `secrets` as a new version to every paired helper and replica.
async fn protect(
    owner: &StatelessPeer,
    helpers: &[HelperDevice],
    replicas: &[&ReplicaDevice],
    secrets: Vec<UserSecret>,
    description: &str,
) -> Vec<DeRecEvent> {
    owner
        .session()
        .start(DeRecFlow::ProtectSecret {
            secrets,
            description: Some(description.to_owned()),
        })
        .await
        .expect("owner.start(ProtectSecret) failed");

    let mut cast: Vec<&StatelessPeer> = vec![owner];
    cast.extend(helpers.iter().map(|h| &h.peer));
    cast.extend(replicas.iter().map(|r| &r.peer));
    pump(&cast).await
}

/// Re-pair with every helper on a fresh channel, link old to new helper-side,
/// discover, recover the newest version and commit it with `restore`.
///
/// Returns the version recovered and the `Secret` it carried, so callers can
/// check the payload itself round-tripped — the only assertion that actually
/// proves recovery worked rather than merely completed.
async fn recover_from_helpers(
    owner: &StatelessPeer,
    helpers: &mut [HelperDevice],
    transient_base: u64,
) -> (u32, Secret) {
    let mut recovery_channels = Vec::new();

    for (i, helper) in helpers.iter_mut().enumerate() {
        let transient = ChannelId(transient_base + i as u64);
        let contact = owner
            .session()
            .create_contact(Some(transient), ContactMode::InlineKeys, None)
            .await
            .expect("recovery create_contact failed");
        helper
            .peer
            .session()
            .start(DeRecFlow::Pairing {
                kind: SenderKind::Helper,
                contact,
                peer_communication_info: HashMap::from([(
                    "name".to_owned(),
                    "recovering-owner".to_owned(),
                )]),
            })
            .await
            .unwrap_or_else(|e| panic!("[{}] recovery start(Pairing) failed: {e}", helper.peer.label));

        let events = pump(&[owner, &helper.peer]).await;
        let rekeyed = events
            .iter()
            .find_map(|e| match e {
                DeRecEvent::PairingCompleted {
                    channel_id,
                    pairing_channel_id,
                    ..
                } if *pairing_channel_id == transient => Some(*channel_id),
                _ => None,
            })
            .unwrap_or_else(|| {
                panic!(
                    "[{}] no PairingCompleted for recovery transient {transient:?}",
                    helper.peer.label
                )
            });

        // Application-side judgement: this new channel is the same owner as
        // the old one, so shares stored under the old channel stay reachable.
        let previous = helper.channel.expect("helper was paired before the loss");
        helper
            .peer
            .session()
            .channel_store
            .link_channel(SECRET_ID, previous, rekeyed)
            .await
            .expect("helper link_channel failed");

        // `helper.channel` deliberately keeps pointing at the canonical id:
        // restore reinstates that channel from the roster and discards the
        // recovery-mode one, so it is the id the owner ends up addressing.
        recovery_channels.push(rekeyed);
    }

    let discovered = {
        owner
            .session()
            .start(DeRecFlow::Discovery {
                target: Target::Many(recovery_channels.clone()),
            })
            .await
            .expect("owner.start(Discovery) failed");
        let mut cast: Vec<&StatelessPeer> = vec![owner];
        cast.extend(helpers.iter().map(|h| &h.peer));
        let events = pump(&cast).await;
        events
            .iter()
            .filter_map(|e| match e {
                DeRecEvent::SecretsDiscovered { secrets, .. } => Some(secrets.clone()),
                _ => None,
            })
            .flatten()
            .find(|s| s.secret_id == SECRET_ID)
            .expect("discovery must surface the protected secret")
    };

    let version = discovered
        .versions
        .iter()
        .map(|v| v.version)
        .max()
        .expect("discovered secret must carry at least one version");

    owner
        .session()
        .start(DeRecFlow::RecoverSecret {
            secret_id: SECRET_ID,
            version,
        })
        .await
        .expect("owner.start(RecoverSecret) failed");
    let recovered: Secret = {
        let mut cast: Vec<&StatelessPeer> = vec![owner];
        cast.extend(helpers.iter().map(|h| &h.peer));
        let events = pump(&cast).await;
        events
            .iter()
            .find_map(|e| match e {
                DeRecEvent::SecretRecovered { secret } => Some(secret.clone()),
                _ => None,
            })
            .expect("expected SecretRecovered")
    };

    owner
        .session()
        .restore(&recovered, version)
        .await
        .expect("owner.restore() failed");

    // Restore unpairs the recovery-mode channels as scrap; those teardown
    // messages are on the wire and have to land, or the helpers would keep a
    // channel the owner has already forgotten. Each helper acknowledges, and
    // those acknowledgements arrive at an owner that has already dropped the
    // key — by design, so they are counted rather than fatal.
    {
        let mut cast: Vec<&StatelessPeer> = vec![owner];
        cast.extend(helpers.iter().map(|h| &h.peer));
        let (_, stale) = pump_tolerating_stale(&cast).await;
        assert_eq!(
            stale,
            helpers.len(),
            "exactly one stale unpair acknowledgement per scrapped recovery channel"
        );
    }

    (version, recovered)
}

/// Check that every secret the user stored came back byte-for-byte.
fn assert_secrets_round_tripped(recovered: &Secret, expected: &[UserSecret], step: &str) {
    assert_eq!(
        recovered.secrets.len(),
        expected.len(),
        "[{step}] recovered {} secrets, expected {}",
        recovered.secrets.len(),
        expected.len()
    );
    for want in expected {
        let got = recovered
            .secrets
            .iter()
            .find(|s| s.id == want.id)
            .unwrap_or_else(|| {
                panic!("[{step}] recovered secret set is missing id {:?}", want.id)
            });
        assert_eq!(got.name, want.name, "[{step}] name for id {:?}", want.id);
        assert_eq!(got.data, want.data, "[{step}] data for id {:?}", want.id);
    }
}

/// Share rows each helper holds as of step 4, in `helpers` order: the three
/// survivors carry every version, spare #6 joined at v3 and spare #7 at v4.
const HELPER_BASE_SHARES: [i64; 5] = [4, 4, 4, 2, 1];

/// Assert every helper at once. Publishing is always a full round reaching all
/// five, so each publish since step 4 adds exactly one row to each.
async fn assert_helpers(helpers: &[HelperDevice], step: &str, publishes_since_step_4: i64) {
    for (i, helper) in helpers.iter().enumerate() {
        assert_tables(
            &helper.peer.client(),
            SECRET_ID,
            &helper.peer.label,
            step,
            Tables {
                channels: 1,
                secrets: 1,
                shares: HELPER_BASE_SHARES[i] + publishes_since_step_4,
                ..Default::default()
            },
        )
        .await;
    }
}

/// Assert a replica device.
///
/// A member hydrates the **whole** roster, helper channels included — it must
/// be able to publish on its own, which means holding every helper's channel
/// and key, plus the group channel: six `secrets` rows in all. It keeps no
/// share rows, because unlike the owner it holds the secret itself rather than
/// tracking copies of what it handed out.
async fn assert_replica(replica: &ReplicaDevice, step: &str, members: i64) {
    assert_tables(
        &replica.peer.client(),
        SECRET_ID,
        &replica.peer.label,
        step,
        Tables {
            channels: 5,
            replica_members: members,
            secrets: 6,
            user_secrets: 1,
            ..Default::default()
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// Step 10 — a stranded round, resolved without any inbound message
// ---------------------------------------------------------------------------

/// The failure the rest of this scenario never produces: a helper that simply
/// stops answering.
///
/// Timeouts are otherwise only evaluated while handling an inbound message, so
/// the silence that should trigger one is also what prevents it being noticed.
/// A stateless service has no background loop either, which leaves the round
/// open forever and the application waiting on a `SharingComplete` that cannot
/// arrive.
///
/// `tick` is what the application's scheduler calls instead. This drives the
/// whole sequence for real: publish, let four of five helpers answer, confirm
/// the round is genuinely stuck, then resolve it from a timer alone.
async fn step_10_a_silent_helper_is_resolved_by_a_scheduled_tick(
    owner: &mut StatelessPeer,
    helpers: &[HelperDevice],
    replicas: &[ReplicaDevice],
    secrets: &[UserSecret],
) {
    // A one-second window, so the scheduled sweep has something to find
    // without the test waiting on a production-length timeout.
    owner.set_timeout(1);

    let silent = helpers.last().expect("helpers are paired");
    let responsive: Vec<&HelperDevice> = helpers.iter().take(helpers.len() - 1).collect();

    owner
        .session()
        .start(DeRecFlow::ProtectSecret {
            secrets: secrets.to_vec(),
            description: Some("published while one helper is offline".to_owned()),
        })
        .await
        .expect("owner.start(ProtectSecret)");

    // Deliver to everyone except the silent helper — its messages are dropped
    // on the floor, exactly as they would be for a device that is off.
    let mut dropped = 0usize;
    for (endpoint, bytes) in owner.drain() {
        if endpoint.uri == silent.peer.uri {
            dropped += 1;
            continue;
        }
        if let Some(helper) = responsive.iter().find(|h| h.peer.uri == endpoint.uri) {
            deliver(&helper.peer, &bytes).await;
        } else if let Some(replica) = replicas.iter().find(|r| r.peer.uri == endpoint.uri) {
            deliver(&replica.peer, &bytes).await;
        } else {
            panic!("no peer for {}", endpoint.uri);
        }
    }
    assert_eq!(dropped, 1, "exactly one helper was taken offline");

    // Carry every answer back, and let the rest of the group settle.
    {
        let mut cast: Vec<&StatelessPeer> = vec![owner];
        cast.extend(responsive.iter().map(|h| &h.peer));
        cast.extend(replicas.iter().map(|r| &r.peer));
        pump(&cast).await;
    }

    // The round cannot finish: one helper is still outstanding and nothing
    // further will ever arrive on its behalf.
    let stranded = snapshot(&owner.client(), SECRET_ID).await;
    assert_eq!(
        stranded.protocol_state, 1,
        "the round must still be in flight with a helper outstanding"
    );

    // Nothing arrives. Only the clock moves.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let events = owner.session().tick().await;

    assert!(
        events.iter().any(|e| matches!(
            e,
            DeRecEvent::ShareRejected { memo, .. } if memo == "timeout"
        )),
        "the silent helper is failed on the timeout; got {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, DeRecEvent::SharingComplete { .. })),
        "the round must actually close, not merely report a failure; got {events:?}"
    );

    let after = snapshot(&owner.client(), SECRET_ID).await;
    assert_eq!(
        after.protocol_state, 0,
        "a closed round leaves no in-flight row for the next invocation to trip over"
    );
    println!(
        "  step 10: a helper went silent, stranding the round — a scheduled tick failed it \
         and closed the round with no inbound message  ✓"
    );
}
