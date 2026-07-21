// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::{Secret, UserSecret};
use derec_library::protocol::{
    ChannelShare, DeRecFlow, DeRecUserSecretStore,
};
use derec_library::types::ChannelId;
use derec_proto::SenderKind;
use std::collections::HashMap;

use crate::db::Database;
use crate::peer::{Peer, PeerOptions, pump_many};

const PROTECTED_SECRET_ID: u64 = 0xABBA;
const THRESHOLD: usize = 3;

pub async fn run() {
    println!("=== [Replica sync] version progression v0 → v8 ===");

    let owner_db = Database::open_in_memory();
    let replica_a_db = Database::open_in_memory();
    let replica_b_db = Database::open_in_memory();
    let replica_c_db = Database::open_in_memory();
    let helper_1_db = Database::open_in_memory();
    let helper_2_db = Database::open_in_memory();
    let helper_3_db = Database::open_in_memory();

    let mut owner = Peer::with_options(
        owner_db.connection(),
        "Owner",
        "https://owner.example.com",
        PeerOptions {
            secret_id: PROTECTED_SECRET_ID,
            threshold: THRESHOLD,
            replica_id: Some(0x0001),
        },
    );
    let mut replica_a = Peer::with_options(
        replica_a_db.connection(),
        "ReplicaA",
        "https://replica-a.example.com",
        PeerOptions {
            secret_id: PROTECTED_SECRET_ID,
            threshold: THRESHOLD,
            replica_id: Some(0x000A),
        },
    );
    let mut replica_b = Peer::with_options(
        replica_b_db.connection(),
        "ReplicaB",
        "https://replica-b.example.com",
        PeerOptions {
            secret_id: PROTECTED_SECRET_ID,
            threshold: THRESHOLD,
            replica_id: Some(0x000B),
        },
    );
    let mut replica_c = Peer::with_options(
        replica_c_db.connection(),
        "ReplicaC",
        "https://replica-c.example.com",
        PeerOptions {
            secret_id: PROTECTED_SECRET_ID,
            threshold: THRESHOLD,
            replica_id: Some(0x000C),
        },
    );
    let mut helper_1 = Peer::with_options(
        helper_1_db.connection(),
        "Helper1",
        "https://helper-1.example.com",
        PeerOptions {
            secret_id: PROTECTED_SECRET_ID,
            threshold: THRESHOLD,
            replica_id: None,
        },
    );
    let mut helper_2 = Peer::with_options(
        helper_2_db.connection(),
        "Helper2",
        "https://helper-2.example.com",
        PeerOptions {
            secret_id: PROTECTED_SECRET_ID,
            threshold: THRESHOLD,
            replica_id: None,
        },
    );
    let mut helper_3 = Peer::with_options(
        helper_3_db.connection(),
        "Helper3",
        "https://helper-3.example.com",
        PeerOptions {
            secret_id: PROTECTED_SECRET_ID,
            threshold: THRESHOLD,
            replica_id: None,
        },
    );

    let cid_a = ChannelId(1);
    let cid_b = ChannelId(3);
    let cid_c = ChannelId(8);
    let cid_h1 = ChannelId(11);
    let cid_h2 = ChannelId(12);
    let cid_h3 = ChannelId(13);

    let mut rekeyed: std::collections::HashMap<ChannelId, ChannelId> =
        std::collections::HashMap::new();
    let capture_rekey =
        |rekeyed: &mut std::collections::HashMap<ChannelId, ChannelId>, events: &[DeRecEvent]| {
            for ev in events {
                if let DeRecEvent::PairingCompleted {
                    channel_id,
                    pairing_channel_id,
                    ..
                } = ev
                {
                    rekeyed.insert(*pairing_channel_id, *channel_id);
                }
            }
        };
    let rk = |rekeyed: &std::collections::HashMap<ChannelId, ChannelId>, cid: ChannelId| {
        *rekeyed
            .get(&cid)
            .unwrap_or_else(|| panic!("no rekeyed id for transient {cid:?}"))
    };

    assert!(
        owner
            .protocol
            .user_secret_store
            .load_latest(PROTECTED_SECRET_ID)
            .await
            .unwrap()
            .is_none(),
        "step 0: brand-new owner must have no user_secrets snapshot"
    );
    println!("  step 0: user_secret_store latest = None  ✓");

    let rek_a = pair_replica_handshake(&mut owner, &mut replica_a, cid_a).await;
    rekeyed.insert(cid_a, rek_a);
    cross_confirm_fingerprint(&mut owner, &mut replica_a, rk(&rekeyed, cid_a)).await;
    let events =
        pump_many(&mut [&mut owner, &mut replica_a, &mut replica_b, &mut replica_c]).await;
    capture_rekey(&mut rekeyed, &events);
    let received_a = find_replica_event(&events, rk(&rekeyed, cid_a))
        .expect("step 1: replica A must observe ReplicaSecretReceived");
    assert_eq!(received_a.version, 1);
    assert_eq!(received_a.secret.helpers.len(), 0);
    assert_eq!(received_a.secret.secrets.len(), 0);
    assert_eq!(received_a.secret.replicas.as_ref().unwrap().replicas.len(), 1);
    assert_eq!(received_a.shares.len(), 0);
    assert_eq!(latest_version(&owner).await, Some(1));
    println!("  step 1: pair replica A → v=1, secret(h=0,s=0,r=1,shares=0)  ✓");

    let s1 = UserSecret {
        id: vec![0x01],
        name: "secret-one".to_owned(),
        data: b"first-user-secret".to_vec(),
    };
    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![s1.clone()],
            description: Some("v=2 explicit publish".to_owned()),
        })
        .await
        .unwrap();
    let events =
        pump_many(&mut [&mut owner, &mut replica_a, &mut replica_b, &mut replica_c]).await;
    capture_rekey(&mut rekeyed, &events);
    let received_a = find_replica_event(&events, rk(&rekeyed, cid_a)).expect("step 2: A must see v=2");
    assert_eq!(received_a.version, 2);
    assert_eq!(received_a.secret.helpers.len(), 0);
    assert_eq!(received_a.secret.secrets.len(), 1);
    assert_eq!(received_a.secret.secrets[0].data, s1.data);
    assert_eq!(received_a.secret.replicas.as_ref().unwrap().replicas.len(), 1);
    assert_eq!(received_a.shares.len(), 0);
    assert_eq!(latest_version(&owner).await, Some(2));
    println!("  step 2: ProtectSecret([s1]) → v=2, secret(h=0,s=1,r=1,shares=0)  ✓");

    let rek_b = pair_replica_handshake(&mut owner, &mut replica_b, cid_b).await;
    rekeyed.insert(cid_b, rek_b);
    cross_confirm_fingerprint(&mut owner, &mut replica_b, rk(&rekeyed, cid_b)).await;
    let events =
        pump_many(&mut [&mut owner, &mut replica_a, &mut replica_b, &mut replica_c]).await;
    capture_rekey(&mut rekeyed, &events);
    let received_a = find_replica_event(&events, rk(&rekeyed, cid_a)).expect("step 3: A must see v=3");
    let received_b =
        find_replica_event(&events, rk(&rekeyed, cid_b)).expect("step 3: B must see v=3 (bootstrap)");
    for (label, received) in [("A", &received_a), ("B", &received_b)] {
        assert_eq!(received.version, 3);
        assert_eq!(received.secret.helpers.len(), 0);
        assert_eq!(received.secret.secrets.len(), 1, "{label}: bag carries s1");
        assert_eq!(received.secret.secrets[0].data, s1.data);
        assert_eq!(received.secret.replicas.as_ref().unwrap().replicas.len(), 2);
        assert_eq!(received.shares.len(), 0);
    }
    assert_eq!(latest_version(&owner).await, Some(3));
    println!("  step 3: pair replica B → v=3, secret(h=0,s=1,r=2,shares=0) on A+B  ✓");

    helper_start_pair(&mut owner, &mut helper_1, cid_h1).await;
    let events = pump_many(&mut [
        &mut owner,
        &mut replica_a,
        &mut replica_b,
        &mut replica_c,
        &mut helper_1,
        &mut helper_2,
        &mut helper_3,
    ])
    .await;
    capture_rekey(&mut rekeyed, &events);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, DeRecEvent::ShareStored { .. })),
        "step 4: no helper may store a share (1 < threshold 3)"
    );
    for (label, cid) in [("A", cid_a), ("B", cid_b)] {
        let received = find_replica_event(&events, rk(&rekeyed, cid))
            .unwrap_or_else(|| panic!("step 4: replica {label} must observe v=4"));
        assert_eq!(received.version, 4);
        assert_eq!(received.secret.helpers.len(), 1);
        assert_eq!(received.secret.secrets.len(), 1);
        assert_eq!(received.secret.replicas.as_ref().unwrap().replicas.len(), 2);
        assert_eq!(received.shares.len(), 0);
    }
    assert_eq!(latest_version(&owner).await, Some(4));
    println!("  step 4: pair helper #1 → v=4, secret(h=1,s=1,r=2,shares=0)  ✓");

    helper_start_pair(&mut owner, &mut helper_2, cid_h2).await;
    let events = pump_many(&mut [
        &mut owner,
        &mut replica_a,
        &mut replica_b,
        &mut replica_c,
        &mut helper_1,
        &mut helper_2,
        &mut helper_3,
    ])
    .await;
    capture_rekey(&mut rekeyed, &events);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, DeRecEvent::ShareStored { .. })),
        "step 5: still below threshold"
    );
    let received_b = find_replica_event(&events, rk(&rekeyed, cid_b)).expect("step 5: B must observe v=5");
    assert_eq!(received_b.version, 5);
    assert_eq!(received_b.secret.helpers.len(), 2);
    assert_eq!(received_b.shares.len(), 0);
    let _ = find_replica_event(&events, rk(&rekeyed, cid_a)).expect("step 5: A must observe v=5");
    assert_eq!(latest_version(&owner).await, Some(5));
    println!("  step 5: pair helper #2 → v=5, secret(h=2,s=1,r=2,shares=0)  ✓");

    let s2 = UserSecret {
        id: vec![0x02],
        name: "secret-two".to_owned(),
        data: b"second-user-secret".to_vec(),
    };
    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![s1.clone(), s2.clone()],
            description: Some("v=6 explicit publish".to_owned()),
        })
        .await
        .unwrap();
    let events = pump_many(&mut [
        &mut owner,
        &mut replica_a,
        &mut replica_b,
        &mut replica_c,
        &mut helper_1,
        &mut helper_2,
        &mut helper_3,
    ])
    .await;
    capture_rekey(&mut rekeyed, &events);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, DeRecEvent::ShareStored { .. })),
        "step 6: still below threshold"
    );
    let received_a = find_replica_event(&events, rk(&rekeyed, cid_a)).expect("step 6: A must see v=6");
    assert_eq!(received_a.version, 6);
    assert_eq!(received_a.secret.secrets.len(), 2);
    assert!(received_a.secret.secrets.iter().any(|us| us.data == s1.data));
    assert!(received_a.secret.secrets.iter().any(|us| us.data == s2.data));
    assert_eq!(received_a.secret.helpers.len(), 2);
    assert_eq!(received_a.shares.len(), 0);
    let _ = find_replica_event(&events, rk(&rekeyed, cid_b)).expect("step 6: B must see v=6");
    assert_eq!(latest_version(&owner).await, Some(6));
    println!("  step 6: ProtectSecret([s1, s2]) → v=6, secret(h=2,s=2,r=2,shares=0)  ✓");

    helper_start_pair(&mut owner, &mut helper_3, cid_h3).await;
    let events = pump_many(&mut [
        &mut owner,
        &mut replica_a,
        &mut replica_b,
        &mut replica_c,
        &mut helper_1,
        &mut helper_2,
        &mut helper_3,
    ])
    .await;
    capture_rekey(&mut rekeyed, &events);
    for (label, cid) in [("helper-1", cid_h1), ("helper-2", cid_h2), ("helper-3", cid_h3)] {
        let expected = rk(&rekeyed, cid);
        assert!(
            events.iter().any(|e| matches!(
                e,
                DeRecEvent::ShareStored { channel_id, version: 7, .. } if *channel_id == expected
            )),
            "step 7: {label} must emit ShareStored at v=7"
        );
    }
    for (label, cid) in [("A", cid_a), ("B", cid_b)] {
        let received = find_replica_event(&events, rk(&rekeyed, cid))
            .unwrap_or_else(|| panic!("step 7: replica {label} must observe v=7"));
        assert_eq!(received.version, 7);
        assert_eq!(received.secret.helpers.len(), 3);
        assert_eq!(received.secret.secrets.len(), 2);
        assert_eq!(received.secret.replicas.as_ref().unwrap().replicas.len(), 2);
        assert_eq!(received.shares.len(), 3);
    }
    assert_eq!(latest_version(&owner).await, Some(7));
    println!("  step 7: pair helper #3 → v=7, secret(h=3,s=2,r=2,shares=3); all 3 helpers ShareStored  ✓");

    let rek_c = pair_replica_handshake(&mut owner, &mut replica_c, cid_c).await;
    rekeyed.insert(cid_c, rek_c);
    cross_confirm_fingerprint(&mut owner, &mut replica_c, rk(&rekeyed, cid_c)).await;
    let events = pump_many(&mut [
        &mut owner,
        &mut replica_a,
        &mut replica_b,
        &mut replica_c,
        &mut helper_1,
        &mut helper_2,
        &mut helper_3,
    ])
    .await;
    capture_rekey(&mut rekeyed, &events);
    for (label, cid) in [("helper-1", cid_h1), ("helper-2", cid_h2), ("helper-3", cid_h3)] {
        let expected = rk(&rekeyed, cid);
        assert!(
            events.iter().any(|e| matches!(
                e,
                DeRecEvent::ShareStored { channel_id, version: 8, .. } if *channel_id == expected
            )),
            "step 8: {label} must emit ShareStored at v=8"
        );
    }
    let received_c = find_replica_event(&events, rk(&rekeyed, cid_c)).expect("step 8: C must observe v=8");
    assert_eq!(received_c.version, 8);
    assert_eq!(received_c.secret.helpers.len(), 3);
    assert_eq!(received_c.secret.secrets.len(), 2);
    assert_eq!(received_c.secret.replicas.as_ref().unwrap().replicas.len(), 3);
    assert_eq!(received_c.shares.len(), 3);
    for (label, cid) in [("A", cid_a), ("B", cid_b)] {
        let received = find_replica_event(&events, rk(&rekeyed, cid))
            .unwrap_or_else(|| panic!("step 8: replica {label} must observe v=8"));
        assert_eq!(received.version, 8);
        assert_eq!(received.secret.replicas.as_ref().unwrap().replicas.len(), 3);
    }
    assert_eq!(latest_version(&owner).await, Some(8));
    println!(
        "  step 8: pair replica C → v=8, secret(h=3,s=2,r=3,shares=3) on A+B+C; all helpers refreshed  ✓"
    );

    println!("✓ Replica sync version progression flow passed.\n");
}

async fn latest_version(owner: &Peer) -> Option<u32> {
    owner
        .protocol
        .user_secret_store
        .load_latest(PROTECTED_SECRET_ID)
        .await
        .unwrap()
        .map(|s| s.version)
}

async fn pair_replica_handshake(
    owner: &mut Peer,
    replica: &mut Peer,
    channel_id: ChannelId,
) -> ChannelId {
    let contact = owner
        .protocol
        .create_contact(Some(channel_id), derec_proto::ContactMode::InlineKeys, None)
        .await
        .expect("owner.create_contact failed");
    replica
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::ReplicaDestination,
            contact,
            peer_communication_info: HashMap::new(),
        })
        .await
        .expect("replica start(Pairing) failed");
    let events = pump_many(&mut [owner, replica]).await;
    events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::PairingCompleted {
                channel_id: rekeyed,
                pairing_channel_id,
                ..
            } if *pairing_channel_id == channel_id => Some(*rekeyed),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!("pair_replica_handshake: missing PairingCompleted for transient {channel_id:?}")
        })
}

async fn cross_confirm_fingerprint(
    owner: &mut Peer,
    replica: &mut Peer,
    channel_id: ChannelId,
) {
    let owner_fp = owner.protocol.get_fingerprint(channel_id).await.unwrap();
    let replica_fp = replica.protocol.get_fingerprint(channel_id).await.unwrap();
    assert_eq!(owner_fp, replica_fp);
    let ok_o = owner
        .protocol
        .verify_fingerprint(channel_id, &replica_fp)
        .await
        .unwrap();
    let ok_r = replica
        .protocol
        .verify_fingerprint(channel_id, &owner_fp)
        .await
        .unwrap();
    assert!(ok_o && ok_r);
}

async fn helper_start_pair(owner: &mut Peer, helper: &mut Peer, channel_id: ChannelId) {
    let contact = owner
        .protocol
        .create_contact(Some(channel_id), derec_proto::ContactMode::InlineKeys, None)
        .await
        .expect("owner.create_contact failed");
    helper
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact,
            peer_communication_info: HashMap::new(),
        })
        .await
        .expect("helper start(Pairing) failed");
}

struct ReceivedSecret {
    version: u32,
    secret: Secret,
    shares: Vec<ChannelShare>,
}

fn find_replica_event(events: &[DeRecEvent], channel_id: ChannelId) -> Option<ReceivedSecret> {
    events.iter().find_map(|e| match e {
        DeRecEvent::ReplicaSecretReceived {
            channel_id: cid,
            version,
            secret,
            shares,
            ..
        } if *cid == channel_id => Some(ReceivedSecret {
            version: *version,
            secret: secret.clone(),
            shares: shares.clone(),
        }),
        _ => None,
    })
}
