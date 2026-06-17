//! One user, multiple vaults.
//!
//! Models a single device that owns two distinct vaults — a wallet
//! seed and an email password — each backed by its own dedicated
//! pair of helpers, all sharing one Postgres database. Drives the full
//! lifecycle for each vault (pair → publish → simulate state loss →
//! re-pair → discover → recover) and asserts:
//!
//! - the owner-side DB rows for the two vaults coexist under their
//!   respective `secret_id` partitions,
//! - each helper only ever sees its own vault's payload — recovery in
//!   vault WALLET surfaces the wallet bytes and never the email
//!   bytes, and vice versa,
//! - state loss in one vault does not affect the other (clearing
//!   user_secret_store + dropping channel rows for vault WALLET
//!   leaves vault EMAIL queryable).
//!
//! This is the "real" multi-vault story; `multi_tenancy.rs` covers
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

const VAULT_WALLET: u64 = 0xDEC0_DE01;
const VAULT_EMAIL: u64 = 0xDEC0_DE02;

pub async fn run() {
    println!("=== [Multi-vault] one user, wallet vault + email vault ===");

    let user_db = Database::open_isolated().await;
    let alice_db = Database::open_isolated().await;
    let bob_db = Database::open_isolated().await;
    let carol_db = Database::open_isolated().await;
    let dave_db = Database::open_isolated().await;

    // Same physical DB → same physical user. Two protocols, one per
    // vault — that's the architecture (one DeRecProtocol = one
    // vault). Distinct cids per vault keep the per-vault assertions
    // unambiguous when the same DB hosts both partitions.
    let mut user_wallet = Peer::with_secret_id(
        user_db.client(),
        "User-Wallet",
        "https://user-wallet.example.com",
        VAULT_WALLET,
    );
    let mut user_email = Peer::with_secret_id(
        user_db.client(),
        "User-Email",
        "https://user-email.example.com",
        VAULT_EMAIL,
    );

    // Wallet vault helpers (Alice + Bob), bound to VAULT_WALLET.
    let mut alice = Peer::with_secret_id(
        alice_db.client(),
        "Alice",
        "https://alice.example.com",
        VAULT_WALLET,
    );
    let mut bob = Peer::with_secret_id(
        bob_db.client(),
        "Bob",
        "https://bob.example.com",
        VAULT_WALLET,
    );

    // Email vault helpers (Carol + Dave), bound to VAULT_EMAIL.
    let mut carol = Peer::with_secret_id(
        carol_db.client(),
        "Carol",
        "https://carol.example.com",
        VAULT_EMAIL,
    );
    let mut dave = Peer::with_secret_id(
        dave_db.client(),
        "Dave",
        "https://dave.example.com",
        VAULT_EMAIL,
    );

    // ── Pair each vault with its dedicated helpers ────────────────
    let wallet_alice = pair_owner_helper(&mut user_wallet, &mut alice, ChannelId(10)).await;
    let wallet_bob = pair_owner_helper(&mut user_wallet, &mut bob, ChannelId(20)).await;
    let email_carol = pair_owner_helper(&mut user_email, &mut carol, ChannelId(30)).await;
    let email_dave = pair_owner_helper(&mut user_email, &mut dave, ChannelId(40)).await;
    println!(
        "  paired Wallet↔(Alice {}, Bob {}); Email↔(Carol {}, Dave {})",
        wallet_alice.0, wallet_bob.0, email_carol.0, email_dave.0
    );

    // Both vaults coexist on the same `channels` table under
    // distinct `secret_id` partitions.
    assert_eq!(count_channels(&user_db.client(), VAULT_WALLET).await, 2);
    assert_eq!(count_channels(&user_db.client(), VAULT_EMAIL).await, 2);
    println!("  user DB: 2 channels per vault, partitioned by secret_id  ✓");

    // ── Publish into each vault ───────────────────────────────────
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
    assert_eq!(count_user_secrets(&user_db.client(), VAULT_WALLET).await, 1);
    assert_eq!(count_user_secrets(&user_db.client(), VAULT_EMAIL).await, 1);
    assert_eq!(count_shares(&user_db.client(), VAULT_WALLET).await, 2);
    assert_eq!(count_shares(&user_db.client(), VAULT_EMAIL).await, 2);
    assert_eq!(count_shares(&alice_db.client(), VAULT_WALLET).await, 1);
    assert_eq!(count_shares(&bob_db.client(), VAULT_WALLET).await, 1);
    assert_eq!(count_shares(&carol_db.client(), VAULT_EMAIL).await, 1);
    assert_eq!(count_shares(&dave_db.client(), VAULT_EMAIL).await, 1);
    println!(
        "  publish: each vault has 1 user_secrets row + 2 owner-side shares; helpers each hold 1  ✓"
    );

    // Helpers only ever see their own vault — sanity-check the wallet
    // helpers never received an email-vault share row, and vice versa.
    assert_eq!(
        count_shares(&alice_db.client(), VAULT_EMAIL).await,
        0,
        "Alice (wallet helper) must not hold any email-vault shares"
    );
    assert_eq!(
        count_shares(&carol_db.client(), VAULT_WALLET).await,
        0,
        "Carol (email helper) must not hold any wallet-vault shares"
    );
    println!("  helpers see only their own vault's shares  ✓");

    // ── Simulate state loss + recovery on the wallet vault only ───
    // Clearing user_secret_store + dropping the owner-side channels
    // for VAULT_WALLET. Email vault state stays intact — the
    // assertions below prove the email lifecycle survives the wallet
    // recovery.
    user_wallet
        .protocol
        .user_secret_store
        .remove(VAULT_WALLET)
        .await
        .unwrap();

    let wallet_recovery_alice = ChannelId(110);
    let wallet_recovery_bob = ChannelId(120);
    for (helper, fresh_cid, label) in [
        (&mut alice, wallet_recovery_alice, "Alice"),
        (&mut bob, wallet_recovery_bob, "Bob"),
    ] {
        let contact = user_wallet
            .protocol
            .create_contact(Some(fresh_cid), derec_proto::ContactMode::InlineKeys)
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
        let _ = pump_many(&mut [&mut user_wallet, helper]).await;
    }

    // Each wallet helper links original ↔ recovery channel so
    // discovery walks the connected component and finds the share
    // stored under the original cid.
    alice
        .protocol
        .channel_store
        .link_channel(VAULT_WALLET, wallet_alice, wallet_recovery_alice)
        .await
        .unwrap();
    bob.protocol
        .channel_store
        .link_channel(VAULT_WALLET, wallet_bob, wallet_recovery_bob)
        .await
        .unwrap();
    // Owner drops the originals so recovery does not double-fan-out.
    user_wallet
        .protocol
        .channel_store
        .remove(VAULT_WALLET, wallet_alice)
        .await
        .unwrap();
    user_wallet
        .protocol
        .channel_store
        .remove(VAULT_WALLET, wallet_bob)
        .await
        .unwrap();
    println!("  wallet vault: re-paired on fresh channels, originals dropped  ✓");

    // Discovery + Recovery on the wallet vault.
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
        .find(|s| s.secret_id == VAULT_WALLET)
        .and_then(|s| s.versions.iter().map(|v| v.version).max())
        .expect("wallet discovery must surface VAULT_WALLET");

    user_wallet
        .protocol
        .start(DeRecFlow::RecoverSecret {
            secret_id: VAULT_WALLET,
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
        .expect("wallet vault must recover");
    assert!(
        contains_subslice(&wallet_recovered, &wallet_payload),
        "wallet recovery must surface the wallet bytes"
    );
    assert!(
        !contains_subslice(&wallet_recovered, &email_payload),
        "wallet recovery must NOT leak the email bytes"
    );
    println!("  wallet vault recovered the wallet bytes (and only those)  ✓");

    // Email vault is untouched — its user_secret_store still holds
    // the snapshot, its channels are still in the DB, and its
    // helpers can still serve a recovery on the original channels
    // without a re-pair.
    assert_eq!(
        count_user_secrets(&user_db.client(), VAULT_EMAIL).await,
        1,
        "email vault user_secrets row must survive the wallet recovery"
    );
    assert_eq!(
        count_channels(&user_db.client(), VAULT_EMAIL).await,
        2,
        "email vault channels must survive the wallet recovery"
    );

    // ── Independent Discovery + Recovery on the email vault ───────
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
        .find(|s| s.secret_id == VAULT_EMAIL)
        .and_then(|s| s.versions.iter().map(|v| v.version).max())
        .expect("email discovery must surface VAULT_EMAIL");

    user_email
        .protocol
        .start(DeRecFlow::RecoverSecret {
            secret_id: VAULT_EMAIL,
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
        .expect("email vault must recover");
    assert!(
        contains_subslice(&email_recovered, &email_payload),
        "email recovery must surface the email bytes"
    );
    assert!(
        !contains_subslice(&email_recovered, &wallet_payload),
        "email recovery must NOT leak the wallet bytes"
    );
    println!("  email vault recovered the email bytes (and only those)  ✓");

    println!("✓ Multi-vault flow passed.\n");
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
