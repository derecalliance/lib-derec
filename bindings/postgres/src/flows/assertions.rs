// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::db::{SharedClient, u64_to_sql};

pub async fn count_channels(client: &SharedClient, secret_id: u64) -> i64 {
    client
        .query_one(
            "SELECT COUNT(*) FROM channels WHERE secret_id = $1",
            &[&u64_to_sql(secret_id)],
        )
        .await
        .expect("count_channels failed")
        .get(0)
}

pub async fn channel_exists(client: &SharedClient, secret_id: u64, channel_id: u64) -> bool {
    let row = client
        .query_opt(
            "SELECT 1 FROM channels WHERE secret_id = $1 AND channel_id = $2",
            &[&u64_to_sql(secret_id), &u64_to_sql(channel_id)],
        )
        .await
        .expect("channel_exists failed");
    row.is_some()
}

pub async fn count_secrets(client: &SharedClient, secret_id: u64) -> i64 {
    client
        .query_one(
            "SELECT COUNT(*) FROM secrets WHERE secret_id = $1",
            &[&u64_to_sql(secret_id)],
        )
        .await
        .expect("count_secrets failed")
        .get(0)
}

pub async fn count_shares(client: &SharedClient, secret_id: u64) -> i64 {
    client
        .query_one(
            "SELECT COUNT(*) FROM shares WHERE secret_id = $1",
            &[&u64_to_sql(secret_id)],
        )
        .await
        .expect("count_shares failed")
        .get(0)
}

pub async fn count_shares_for_channel(
    client: &SharedClient,
    secret_id: u64,
    channel_id: u64,
) -> i64 {
    client
        .query_one(
            "SELECT COUNT(*) FROM shares WHERE secret_id = $1 AND channel_id = $2",
            &[&u64_to_sql(secret_id), &u64_to_sql(channel_id)],
        )
        .await
        .expect("count_shares_for_channel failed")
        .get(0)
}

pub async fn count_channel_links(client: &SharedClient, secret_id: u64) -> i64 {
    client
        .query_one(
            "SELECT COUNT(*) FROM channel_links WHERE secret_id = $1",
            &[&u64_to_sql(secret_id)],
        )
        .await
        .expect("count_channel_links failed")
        .get(0)
}

pub async fn count_user_secrets(client: &SharedClient, secret_id: u64) -> i64 {
    client
        .query_one(
            "SELECT COUNT(*) FROM user_secrets WHERE secret_id = $1",
            &[&u64_to_sql(secret_id)],
        )
        .await
        .expect("count_user_secrets failed")
        .get(0)
}

/// Rows in `protocol_state` of kind `0` — `StateKind::PendingVerification`.
/// Reads the table directly so the assertion is about what is in the
/// database, not what the protocol reports.
pub async fn count_pending_verifications(client: &SharedClient, secret_id: u64) -> i64 {
    client
        .query_one(
            "SELECT COUNT(*) FROM protocol_state WHERE secret_id = $1 AND kind = 0",
            &[&u64_to_sql(secret_id)],
        )
        .await
        .expect("count pending verifications failed")
        .get(0)
}

/// Row counts for every table a peer writes, under one `secret_id`.
///
/// The e2e test asserts one of these after every step. Counting all seven
/// together is what makes an assertion meaningful: checking only the table a
/// step was expected to touch cannot catch a step that also wrote somewhere it
/// should not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tables {
    pub channels: i64,
    pub replica_members: i64,
    pub channel_links: i64,
    pub secrets: i64,
    pub shares: i64,
    pub user_secrets: i64,
    /// In-flight orchestrator state. Expected to be `0` whenever the wire is
    /// quiet: every started flow has either completed or timed out, and a
    /// non-zero count between steps means a flow leaked a row.
    pub protocol_state: i64,
}

async fn count_in(client: &SharedClient, table: &str, secret_id: u64) -> i64 {
    client
        .query_one(
            &format!("SELECT COUNT(*) FROM {table} WHERE secret_id = $1"),
            &[&u64_to_sql(secret_id)],
        )
        .await
        .unwrap_or_else(|e| panic!("counting {table} failed: {e}"))
        .get(0)
}

pub async fn snapshot(client: &SharedClient, secret_id: u64) -> Tables {
    Tables {
        channels: count_in(client, "channels", secret_id).await,
        replica_members: count_in(client, "replica_members", secret_id).await,
        channel_links: count_in(client, "channel_links", secret_id).await,
        secrets: count_in(client, "secrets", secret_id).await,
        shares: count_in(client, "shares", secret_id).await,
        user_secrets: count_in(client, "user_secrets", secret_id).await,
        protocol_state: count_in(client, "protocol_state", secret_id).await,
    }
}

/// Assert every table at once, reporting each column that differs rather than
/// stopping at the first.
pub async fn assert_tables(
    client: &SharedClient,
    secret_id: u64,
    who: &str,
    step: &str,
    expected: Tables,
) {
    let actual = snapshot(client, secret_id).await;
    if actual == expected {
        return;
    }
    let mut diffs = Vec::new();
    let cols: [(&str, i64, i64); 7] = [
        ("channels", expected.channels, actual.channels),
        (
            "replica_members",
            expected.replica_members,
            actual.replica_members,
        ),
        (
            "channel_links",
            expected.channel_links,
            actual.channel_links,
        ),
        ("secrets", expected.secrets, actual.secrets),
        ("shares", expected.shares, actual.shares),
        ("user_secrets", expected.user_secrets, actual.user_secrets),
        (
            "protocol_state",
            expected.protocol_state,
            actual.protocol_state,
        ),
    ];
    for (name, want, got) in cols {
        if want != got {
            diffs.push(format!("{name}: expected {want}, got {got}"));
        }
    }
    panic!(
        "[{step}] {who} table state wrong —\n    {}",
        diffs.join("\n    ")
    );
}

/// Distinct `version` values present in `shares` for this partition.
pub async fn share_versions(client: &SharedClient, secret_id: u64) -> Vec<i64> {
    client
        .query(
            "SELECT DISTINCT version FROM shares WHERE secret_id = $1 ORDER BY version",
            &[&u64_to_sql(secret_id)],
        )
        .await
        .expect("share_versions failed")
        .into_iter()
        .map(|r| r.get::<_, i64>(0))
        .collect()
}

/// The `replica_id`s stored in this peer's roster, ascending.
pub async fn replica_ids(client: &SharedClient, secret_id: u64) -> Vec<u64> {
    client
        .query(
            "SELECT replica_id FROM replica_members WHERE secret_id = $1 ORDER BY replica_id",
            &[&u64_to_sql(secret_id)],
        )
        .await
        .expect("replica_ids failed")
        .into_iter()
        .map(|r| r.get::<_, i64>(0) as u64)
        .collect()
}

/// The version recorded in `user_secrets`, if the peer holds a snapshot.
pub async fn snapshot_version(client: &SharedClient, secret_id: u64) -> Option<u32> {
    client
        .query_opt(
            "SELECT version FROM user_secrets WHERE secret_id = $1",
            &[&u64_to_sql(secret_id)],
        )
        .await
        .expect("snapshot_version failed")
        .map(|r| r.get::<_, i64>(0) as u32)
}
