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
