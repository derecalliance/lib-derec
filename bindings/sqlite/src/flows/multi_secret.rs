//! One user, multiple secrets.
//!
//! Models a single device that protects two distinct secrets — a wallet
//! seed and an email password — each backed by its own dedicated
//! pair of helpers, all sharing one SQLite database. Drives the full
//! lifecycle for each secret (pair → publish → simulate state loss →
//! re-pair → discover → recover) and asserts:
//!
//! - the owner-side DB rows for the two secrets coexist under their
//!   respective `secret_id` partitions,
//! - each helper only ever sees its own secret's payload — recovery on
//!   WALLET surfaces the wallet bytes and never the email
//!   bytes, and vice versa,
//! - state loss on one secret does not affect the other (clearing
//!   user_secret_store + dropping channel rows for WALLET
//!   leaves EMAIL queryable).
//!
//! This is the "real" multi-secret story; `multi_tenancy.rs` covers
//! the narrow trait-partitioning contract.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::{Target, UserSecret};
use derec_library::protocol::DeRecChannelStore;
use derec_library::protocol::DeRecFlow;
use derec_library::protocol::DeRecUserSecretStore;
use derec_library::types::ChannelId;
use derec_proto::SenderKind;
use std::collections::HashMap;

use crate::db::Database;
use crate::flows::assertions::{
    count_channels, count_shares, count_user_secrets,
};
use crate::flows::helpers::{pair_owner_helper, protect_secret};
use crate::peer::{Peer, pump_many};

const WALLET_SECRET_ID: u64 = 0xDEC0_DE01;
const EMAIL_SECRET_ID: u64 = 0xDEC0_DE02;

pub async fn run() {
    println!("=== [Multi-secret] one user, wallet secret + email secret ===");

    let user_db = Database::open_in_memory();
    let alice_db = Database::open_in_memory();
    let bob_db = Database::open_in_memory();
    let carol_db = Database::open_in_memory();
    let dave_db = Database::open_in_memory();

    // Same physical DB → same physical user. Two protocols, one per
    // secret — that's the architecture (one DeRecProtocol = one
    // secret). Distinct cids per secret keep the per-secret assertions
    // unambiguous when the same DB hosts both partitions.
    let mut user_wallet = Peer::with_secret_id(
        user_db.connection(),
        "User-Wallet",
        "https://user-wallet.example.com",
        WALLET_SECRET_ID,
    );
    let mut user_email = Peer::with_secret_id(
        user_db.connection(),
        "User-Email",
        "https://user-email.example.com",
        EMAIL_SECRET_ID,
    );

    // Wallet helpers (Alice + Bob), bound to WALLET_SECRET_ID.
    let mut alice = Peer::with_secret_id(
        alice_db.connection(),
        "Alice",
        "https://alice.example.com",
        WALLET_SECRET_ID,
    );
    let mut bob = Peer::with_secret_id(
        bob_db.connection(),
        "Bob",
        "https://bob.example.com",
        WALLET_SECRET_ID,
    );

    // Email helpers (Carol + Dave), bound to EMAIL_SECRET_ID.
    let mut carol = Peer::with_secret_id(
        carol_db.connection(),
        "Carol",
        "https://carol.example.com",
        EMAIL_SECRET_ID,
    );
    let mut dave = Peer::with_secret_id(
        dave_db.connection(),
        "Dave",
        "https://dave.example.com",
        EMAIL_SECRET_ID,
    );

    // ── Pair each secret with its dedicated helpers ───────────────
    let wallet_alice = pair_owner_helper(&mut user_wallet, &mut alice, ChannelId(10)).await;
    let wallet_bob = pair_owner_helper(&mut user_wallet, &mut bob, ChannelId(20)).await;
    let email_carol = pair_owner_helper(&mut user_email, &mut carol, ChannelId(30)).await;
    let email_dave = pair_owner_helper(&mut user_email, &mut dave, ChannelId(40)).await;
    println!(
        "  paired Wallet↔(Alice {}, Bob {}); Email↔(Carol {}, Dave {})",
        wallet_alice.0, wallet_bob.0, email_carol.0, email_dave.0
    );

    // Both secrets coexist on the same `channels` table under
    // distinct `secret_id` partitions.
    assert_eq!(count_channels(&user_db.connection(), WALLET_SECRET_ID), 2);
    assert_eq!(count_channels(&user_db.connection(), EMAIL_SECRET_ID), 2);
    println!("  user DB: 2 channels per secret, partitioned by secret_id  ✓");

    // ── Publish into each secret ──────────────────────────────────
    let wallet_payload = b"correct horse battery staple".to_vec();
    let email_payload = b"hunter2-but-much-longer".to_vec();
    protect_secret(
        &mut user_wallet,
        &mut [&mut alice, &mut bob],
        UserSecret {
            id: vec![0xAA, 0x01],
            name: "wallet-seed".to_owned(),
            data: wallet_payload.clone(),
        },
        "wallet v1",
    )
    .await;
    protect_secret(
        &mut user_email,
        &mut [&mut carol, &mut dave],
        UserSecret {
            id: vec![0xEE, 0x01],
            name: "email-password".to_owned(),
            data: email_payload.clone(),
        },
        "email v1",
    )
    .await;
    assert_eq!(count_user_secrets(&user_db.connection(), WALLET_SECRET_ID), 1);
    assert_eq!(count_user_secrets(&user_db.connection(), EMAIL_SECRET_ID), 1);
    assert_eq!(count_shares(&user_db.connection(), WALLET_SECRET_ID), 2);
    assert_eq!(count_shares(&user_db.connection(), EMAIL_SECRET_ID), 2);
    assert_eq!(count_shares(&alice_db.connection(), WALLET_SECRET_ID), 1);
    assert_eq!(count_shares(&bob_db.connection(), WALLET_SECRET_ID), 1);
    assert_eq!(count_shares(&carol_db.connection(), EMAIL_SECRET_ID), 1);
    assert_eq!(count_shares(&dave_db.connection(), EMAIL_SECRET_ID), 1);
    println!(
        "  publish: each secret has 1 user_secrets row + 2 owner-side shares; helpers each hold 1  ✓"
    );

    // Helpers only ever see their own secret — sanity-check the wallet
    // helpers never received an email-secret share row, and vice versa.
    assert_eq!(
        count_shares(&alice_db.connection(), EMAIL_SECRET_ID),
        0,
        "Alice (wallet helper) must not hold any email-secret shares"
    );
    assert_eq!(
        count_shares(&carol_db.connection(), WALLET_SECRET_ID),
        0,
        "Carol (email helper) must not hold any wallet-secret shares"
    );
    println!("  helpers see only their own secret's shares  ✓");

    // ── Simulate state loss + recovery on the wallet secret only ──
    // Clearing user_secret_store + dropping the owner-side channels
    // for WALLET_SECRET_ID. Email secret state stays intact — the
    // assertions below prove the email lifecycle survives the wallet
    // recovery.
    user_wallet
        .protocol
        .user_secret_store
        .remove(WALLET_SECRET_ID)
        .await
        .unwrap();

    let wallet_recovery_alice = ChannelId(110);
    let wallet_recovery_bob = ChannelId(120);
    // Capture the rotated long-term id per recovery pair so downstream
    // link graph + Discovery targets use the id that actually resolves
    // in the stores (channel-id rekey rotates the transient contact id
    // at PairingCompleted).
    let mut rekeyed_wallet_recovery: [(ChannelId, ChannelId); 2] =
        [(ChannelId(0), ChannelId(0)); 2];
    for (idx, (helper, fresh_cid, label)) in [
        (&mut alice, wallet_recovery_alice, "Alice"),
        (&mut bob, wallet_recovery_bob, "Bob"),
    ]
    .into_iter()
    .enumerate()
    {
        let contact = user_wallet
            .protocol
            .create_contact(Some(fresh_cid), derec_proto::ContactMode::InlineKeys, None)
            .await
            .unwrap_or_else(|e| panic!("wallet recovery create_contact({label}) failed: {e}"));
        helper
            .protocol
            .start(DeRecFlow::Pairing {
                kind: SenderKind::Helper,
                contact,
                peer_communication_info: HashMap::from([(
                    "name".to_owned(),
                    "wallet-recovering-user".to_owned(),
                )]),
            })
            .await
            .unwrap_or_else(|e| panic!("{label} start(Pairing recovery) failed: {e}"));
        let events = pump_many(&mut [&mut user_wallet, helper]).await;
        let rekeyed = events
            .iter()
            .find_map(|e| match e {
                DeRecEvent::PairingCompleted {
                    channel_id,
                    pairing_channel_id,
                    ..
                } if *pairing_channel_id == fresh_cid => Some(*channel_id),
                _ => None,
            })
            .unwrap_or_else(|| {
                panic!("wallet recovery ({label}): missing PairingCompleted for transient {fresh_cid:?}")
            });
        rekeyed_wallet_recovery[idx] = (fresh_cid, rekeyed);
    }
    let wallet_recovery_alice = rekeyed_wallet_recovery[0].1;
    let wallet_recovery_bob = rekeyed_wallet_recovery[1].1;

    // Each wallet helper links original ↔ recovery channel so
    // discovery walks the connected component and finds the share
    // stored under the original cid.
    alice
        .protocol
        .channel_store
        .link_channel(WALLET_SECRET_ID, wallet_alice, wallet_recovery_alice)
        .await
        .unwrap();
    bob.protocol
        .channel_store
        .link_channel(WALLET_SECRET_ID, wallet_bob, wallet_recovery_bob)
        .await
        .unwrap();
    // Owner drops the originals so recovery does not double-fan-out.
    user_wallet
        .protocol
        .channel_store
        .remove(WALLET_SECRET_ID, wallet_alice)
        .await
        .unwrap();
    user_wallet
        .protocol
        .channel_store
        .remove(WALLET_SECRET_ID, wallet_bob)
        .await
        .unwrap();
    println!("  wallet secret: re-paired on fresh channels, originals dropped  ✓");

    // Discovery + Recovery on the wallet secret.
    user_wallet
        .protocol
        .start(DeRecFlow::Discovery {
            target: Target::Many(vec![wallet_recovery_alice, wallet_recovery_bob]),
        })
        .await
        .unwrap();
    let wallet_disc = pump_many(&mut [&mut user_wallet, &mut alice, &mut bob]).await;
    let wallet_version = wallet_disc
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::SecretsDiscovered { secrets, .. } => Some(secrets.clone()),
            _ => None,
        })
        .flatten()
        .find(|s| s.secret_id == WALLET_SECRET_ID)
        .and_then(|s| s.versions.iter().map(|v| v.version).max())
        .expect("wallet discovery must surface WALLET_SECRET_ID");

    user_wallet
        .protocol
        .start(DeRecFlow::RecoverSecret {
            secret_id: WALLET_SECRET_ID,
            version: wallet_version,
        })
        .await
        .unwrap();
    let wallet_rec = pump_many(&mut [&mut user_wallet, &mut alice, &mut bob]).await;
    let wallet_recovered = wallet_rec
        .iter()
        .find_map(|e| match e {
            DeRecEvent::SecretRecovered { secret } => Some(secret.clone()),
            _ => None,
        })
        .expect("wallet secret must recover");
    let wallet_us = wallet_recovered
        .secrets
        .iter()
        .find(|s| s.id == vec![0xAAu8, 0x01])
        .expect("wallet recovery must include the wallet UserSecret");
    assert_eq!(
        wallet_us.data, wallet_payload,
        "wallet recovery must surface the wallet bytes"
    );
    assert_eq!(wallet_us.name, "wallet-seed");
    assert!(
        wallet_recovered
            .secrets
            .iter()
            .all(|s| s.data != email_payload),
        "wallet recovery must NOT leak the email bytes"
    );
    println!("  wallet secret recovered the wallet UserSecret (and only that)  ✓");

    // Email secret is untouched — its user_secret_store still holds
    // the snapshot, its channels are still in the DB, and its
    // helpers can still serve a recovery on the original channels
    // without a re-pair.
    assert_eq!(
        count_user_secrets(&user_db.connection(), EMAIL_SECRET_ID),
        1,
        "email secret's user_secrets row must survive the wallet recovery"
    );
    assert_eq!(
        count_channels(&user_db.connection(), EMAIL_SECRET_ID),
        2,
        "email secret's channels must survive the wallet recovery"
    );

    // ── Independent Discovery + Recovery on the email secret ──────
    user_email
        .protocol
        .start(DeRecFlow::Discovery {
            target: Target::Many(vec![email_carol, email_dave]),
        })
        .await
        .unwrap();
    let email_disc = pump_many(&mut [&mut user_email, &mut carol, &mut dave]).await;
    let email_version = email_disc
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::SecretsDiscovered { secrets, .. } => Some(secrets.clone()),
            _ => None,
        })
        .flatten()
        .find(|s| s.secret_id == EMAIL_SECRET_ID)
        .and_then(|s| s.versions.iter().map(|v| v.version).max())
        .expect("email discovery must surface EMAIL_SECRET_ID");

    user_email
        .protocol
        .start(DeRecFlow::RecoverSecret {
            secret_id: EMAIL_SECRET_ID,
            version: email_version,
        })
        .await
        .unwrap();
    let email_rec = pump_many(&mut [&mut user_email, &mut carol, &mut dave]).await;
    let email_recovered = email_rec
        .iter()
        .find_map(|e| match e {
            DeRecEvent::SecretRecovered { secret } => Some(secret.clone()),
            _ => None,
        })
        .expect("email secret must recover");
    let email_us = email_recovered
        .secrets
        .iter()
        .find(|s| s.id == vec![0xEEu8, 0x01])
        .expect("email recovery must include the email UserSecret");
    assert_eq!(
        email_us.data, email_payload,
        "email recovery must surface the email bytes"
    );
    assert_eq!(email_us.name, "email-password");
    assert!(
        email_recovered
            .secrets
            .iter()
            .all(|s| s.data != wallet_payload),
        "email recovery must NOT leak the wallet bytes"
    );
    println!("  email secret recovered the email bytes (and only those)  ✓");

    println!("✓ Multi-secret flow passed.\n");
}

