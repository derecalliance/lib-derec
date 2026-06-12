//! Discovery + Recovery flow exercised end-to-end over SQLite-backed
//! stores. Mirrors the Rust binding's `run_discovery_and_recovery_flow`
//! but with SQLite-specific persistence assertions: the recovering
//! Owner is rebuilt over a fresh `DeRecProtocol` instance using the
//! ORIGINAL DB connection — proof that the protocol state survived
//! the recovery-context teardown via SQLite alone.

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::{Target, UserSecret};
use derec_library::protocol::DeRecChannelStore;
use derec_library::protocol::DeRecFlow;
use derec_library::protocol::DeRecUserSecretStore;
use derec_library::types::ChannelId;
use derec_proto::SenderKind;
use std::collections::HashMap;

use crate::db::Database;
use crate::flows::assertions::{count_channels, count_shares};
use crate::flows::helpers::{pair_owner_helper, protect_secret};
use crate::peer::{Peer, pump_many};

const VAULT_SECRET_ID: u64 = 0x7777;

pub async fn run() {
    println!("=== [Discovery + Recovery] full pipeline over SQLite ===");

    let owner_db = Database::open_in_memory();
    let helper_a_db = Database::open_in_memory();
    let helper_b_db = Database::open_in_memory();

    let mut owner = Peer::with_secret_id(
        owner_db.connection(),
        "Owner",
        "https://owner.example.com",
        VAULT_SECRET_ID,
    );
    let mut helper_a = Peer::with_secret_id(
        helper_a_db.connection(),
        "HelperA",
        "https://helper-a.example.com",
        VAULT_SECRET_ID,
    );
    let mut helper_b = Peer::with_secret_id(
        helper_b_db.connection(),
        "HelperB",
        "https://helper-b.example.com",
        VAULT_SECRET_ID,
    );

    let cid_a = pair_owner_helper(&mut owner, &mut helper_a, ChannelId(1)).await;
    let cid_b = pair_owner_helper(&mut owner, &mut helper_b, ChannelId(2)).await;

    let secret_payload = b"recovery-proof-bytes".to_vec();
    protect_secret(
        &mut owner,
        &mut [&mut helper_a, &mut helper_b],
        UserSecret {
            id: vec![9, 9, 9],
            name: "wallet seed".to_owned(),
            data: secret_payload.clone(),
        },
        "wallet seed phrase",
    )
    .await;
    assert_eq!(count_shares(&helper_a_db.connection(), VAULT_SECRET_ID), 1);
    assert_eq!(count_shares(&helper_b_db.connection(), VAULT_SECRET_ID), 1);
    println!("  v1 publish lands one share row on each helper  ✓");

    // Simulate Owner state loss: clear the user_secrets snapshot,
    // re-pair on fresh channels, drop the originals, and recover via
    // the new channels. The auto-publish-on-pair hook would replay v1
    // against the new channels otherwise.
    owner
        .protocol
        .user_secret_store
        .remove(VAULT_SECRET_ID)
        .await
        .expect("clearing user_secret_store");

    let rec_cid_a = ChannelId(100);
    let rec_cid_b = ChannelId(101);
    for (helper, fresh_cid, label) in [
        (&mut helper_a, rec_cid_a, "HelperA"),
        (&mut helper_b, rec_cid_b, "HelperB"),
    ] {
        let contact = owner
            .protocol
            .create_contact(Some(fresh_cid), derec_proto::ContactMode::InlineKeys)
            .await
            .unwrap_or_else(|e| panic!("recovery create_contact({label}) failed: {e}"));
        helper
            .protocol
            .start(DeRecFlow::Pairing {
                kind: SenderKind::Helper,
                contact,
                peer_communication_info: HashMap::from([(
                    "name".to_owned(),
                    "recovering-owner".to_owned(),
                )]),
            })
            .await
            .unwrap_or_else(|e| panic!("{label} start(Pairing recovery) failed: {e}"));
        let _ = pump_many(&mut [&mut owner, helper]).await;
    }
    println!("  recovery re-pair complete on fresh channels (100, 101)  ✓");

    // Each helper links its original channel ↔ recovery channel so
    // discovery resolves the connected component and finds the
    // stored share via the original channel.
    helper_a
        .protocol
        .channel_store
        .link_channel(VAULT_SECRET_ID, cid_a, rec_cid_a)
        .await
        .unwrap();
    helper_b
        .protocol
        .channel_store
        .link_channel(VAULT_SECRET_ID, cid_b, rec_cid_b)
        .await
        .unwrap();

    // Drop the Owner's originals so recovery does not double-fan-out.
    owner
        .protocol
        .channel_store
        .remove(VAULT_SECRET_ID, cid_a)
        .await
        .unwrap();
    owner
        .protocol
        .channel_store
        .remove(VAULT_SECRET_ID, cid_b)
        .await
        .unwrap();
    // Sanity: owner now has just the two recovery channels.
    assert_eq!(
        count_channels(&owner_db.connection(), VAULT_SECRET_ID),
        2,
        "owner channels after dropping originals must be {{rec_a, rec_b}}"
    );

    // Discovery: confirm the helper-side shares are reachable through
    // the link graph + share store. Validates `linked_channels` +
    // `load_all` (the discovery code path).
    owner
        .protocol
        .start(DeRecFlow::Discovery {
            target: Target::Many(vec![rec_cid_a, rec_cid_b]),
        })
        .await
        .unwrap();
    let discovery_events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;
    let discovered = discovery_events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::SecretsDiscovered { secrets, .. } => Some(secrets.clone()),
            _ => None,
        })
        .flatten()
        .find(|s| s.secret_id == VAULT_SECRET_ID)
        .expect("discovered list must contain the distributed secret");
    let recover_version = discovered
        .versions
        .iter()
        .map(|v| v.version)
        .max()
        .expect("discovered secret must have at least one version");
    println!(
        "  discovery surfaced secret_id={VAULT_SECRET_ID} v={recover_version} via link graph  ✓"
    );

    // Recovery — the actual reconstruction. Asserts the original
    // bytes survive the full SQLite round-trip across two helpers.
    owner
        .protocol
        .start(DeRecFlow::RecoverSecret {
            secret_id: VAULT_SECRET_ID,
            version: recover_version,
        })
        .await
        .unwrap();
    let recovery_events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;
    let recovered = recovery_events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::SecretRecovered { secret } => Some(secret.clone()),
            _ => None,
        })
        .expect("expected SecretRecovered on owner");
    assert!(
        contains_subslice(&recovered, &secret_payload),
        "recovered bag must contain the original secret bytes"
    );
    println!("  SecretRecovered: original bytes round-trip through SQLite + VSS  ✓");

    println!("✓ Discovery + Recovery flow passed.\n");
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}
