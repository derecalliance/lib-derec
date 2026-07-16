// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use rusqlite::OptionalExtension;

use crate::codec::u64_to_sql;
use crate::db::{SharedConnection, lock};

pub fn count_channels(conn: &SharedConnection, secret_id: u64) -> i64 {
    let conn = lock(conn);
    conn.query_row(
        "SELECT COUNT(*) FROM channels WHERE secret_id = ?1",
        rusqlite::params![u64_to_sql(secret_id)],
        |row| row.get(0),
    )
    .expect("count_channels failed")
}

pub fn channel_exists(conn: &SharedConnection, secret_id: u64, channel_id: u64) -> bool {
    let conn = lock(conn);
    let row: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM channels WHERE secret_id = ?1 AND channel_id = ?2",
            rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id)],
            |row| row.get(0),
        )
        .optional()
        .expect("channel_exists query failed");
    row.is_some()
}

pub fn count_secrets(conn: &SharedConnection, secret_id: u64) -> i64 {
    let conn = lock(conn);
    conn.query_row(
        "SELECT COUNT(*) FROM secrets WHERE secret_id = ?1",
        rusqlite::params![u64_to_sql(secret_id)],
        |row| row.get(0),
    )
    .expect("count_secrets failed")
}

pub fn count_shares(conn: &SharedConnection, secret_id: u64) -> i64 {
    let conn = lock(conn);
    conn.query_row(
        "SELECT COUNT(*) FROM shares WHERE secret_id = ?1",
        rusqlite::params![u64_to_sql(secret_id)],
        |row| row.get(0),
    )
    .expect("count_shares failed")
}

pub fn count_shares_for_channel(
    conn: &SharedConnection,
    secret_id: u64,
    channel_id: u64,
) -> i64 {
    let conn = lock(conn);
    conn.query_row(
        "SELECT COUNT(*) FROM shares WHERE secret_id = ?1 AND channel_id = ?2",
        rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id)],
        |row| row.get(0),
    )
    .expect("count_shares_for_channel failed")
}

pub fn count_channel_links(conn: &SharedConnection, secret_id: u64) -> i64 {
    let conn = lock(conn);
    conn.query_row(
        "SELECT COUNT(*) FROM channel_links WHERE secret_id = ?1",
        rusqlite::params![u64_to_sql(secret_id)],
        |row| row.get(0),
    )
    .expect("count_channel_links failed")
}

pub fn count_user_secrets(conn: &SharedConnection, secret_id: u64) -> i64 {
    let conn = lock(conn);
    conn.query_row(
        "SELECT COUNT(*) FROM user_secrets WHERE secret_id = ?1",
        rusqlite::params![u64_to_sql(secret_id)],
        |row| row.get(0),
    )
    .expect("count_user_secrets failed")
}
