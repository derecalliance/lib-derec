// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Durable [`DeRecStateStore`] over SQLite.
//!
//! In-flight orchestrator state is what binds a request to the response it
//! expects. Holding it in memory means a process restart between send and
//! receive silently drops a legitimate response as unsolicited, so a store
//! that persists everything else but not this one leaves the gap it exists to
//! close.
//!
//! Rows are serialized through
//! [`derec_library::protocol::types::state_record::StateItemRecord`] — the
//! same projection the FFI and WASM shims use, so a row written here is
//! readable by any backend.

use derec_library::protocol::types::state_record::StateItemRecord;
use derec_library::protocol::{
    DeRecStateStore, StateItem, StateKey, StateKind, StateStoreFuture,
};

use crate::codec::u64_to_sql;
use crate::db::{SharedConnection, lock};

pub struct SqliteStateStore {
    connection: SharedConnection,
}

impl SqliteStateStore {
    pub fn new(connection: SharedConnection) -> Self {
        Self { connection }
    }
}

/// Discriminant of a [`StateKind`], matching the numbering
/// [`StateItemRecord`] uses on the wire.
fn kind_to_sql(kind: StateKind) -> i64 {
    match kind {
        StateKind::PendingVerification => 0,
        StateKind::PendingRecovery => 1,
        StateKind::PendingUnpair => 2,
        StateKind::SharingRound => 3,
        StateKind::PendingSyncCheck => 4,
    }
}

/// Flatten a key into the `(kind, sub_a, sub_b)` triple the table is keyed by.
/// Kinds without a secondary key use zeroes; `kind` keeps the two
/// channel-keyed kinds apart.
fn key_columns(key: &StateKey) -> (i64, i64, i64) {
    let kind = kind_to_sql(key.kind());
    match key {
        StateKey::PendingVerification { channel_id } | StateKey::PendingUnpair { channel_id } => {
            (kind, u64_to_sql(channel_id.0), 0)
        }
        StateKey::PendingRecovery { secret_id, version } => {
            (kind, u64_to_sql(*secret_id), i64::from(*version))
        }
        StateKey::PendingSyncCheck | StateKey::SharingRound => (kind, 0, 0),
    }
}

fn encode(item: &StateItem) -> Vec<u8> {
    let record = StateItemRecord::from(item);
    serde_json::to_vec(&record).expect("StateItem is always serializable")
}

fn decode(bytes: &[u8]) -> StateItem {
    let record: StateItemRecord =
        serde_json::from_slice(bytes).expect("protocol_state row is not a StateItemRecord");
    record
        .into_item()
        .expect("protocol_state row does not decode to a StateItem")
}

impl DeRecStateStore for SqliteStateStore {
    fn save(&mut self, secret_id: u64, item: StateItem) -> StateStoreFuture<'_, ()> {
        let conn = lock(&self.connection);
        let (kind, sub_a, sub_b) = key_columns(&item.key());
        conn.execute(
            "INSERT INTO protocol_state (secret_id, kind, sub_a, sub_b, data)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(secret_id, kind, sub_a, sub_b) DO UPDATE SET
                 data = excluded.data",
            rusqlite::params![u64_to_sql(secret_id), kind, sub_a, sub_b, encode(&item)],
        )
        .expect("protocol_state save failed");
        Box::pin(std::future::ready(Ok(())))
    }

    fn load(&self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, Option<StateItem>> {
        let conn = lock(&self.connection);
        let (kind, sub_a, sub_b) = key_columns(&key);
        let row = conn
            .query_row(
                "SELECT data FROM protocol_state
                 WHERE secret_id = ?1 AND kind = ?2 AND sub_a = ?3 AND sub_b = ?4",
                rusqlite::params![u64_to_sql(secret_id), kind, sub_a, sub_b],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok();
        Box::pin(std::future::ready(Ok(row.as_deref().map(decode))))
    }

    fn remove(&mut self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, bool> {
        let conn = lock(&self.connection);
        let (kind, sub_a, sub_b) = key_columns(&key);
        let affected = conn
            .execute(
                "DELETE FROM protocol_state
                 WHERE secret_id = ?1 AND kind = ?2 AND sub_a = ?3 AND sub_b = ?4",
                rusqlite::params![u64_to_sql(secret_id), kind, sub_a, sub_b],
            )
            .expect("protocol_state remove failed");
        Box::pin(std::future::ready(Ok(affected > 0)))
    }

    fn load_all(&self, secret_id: u64, kind: StateKind) -> StateStoreFuture<'_, Vec<StateItem>> {
        let conn = lock(&self.connection);
        let mut stmt = conn
            .prepare("SELECT data FROM protocol_state WHERE secret_id = ?1 AND kind = ?2")
            .expect("protocol_state load_all prepare failed");
        let rows = stmt
            .query_map(
                rusqlite::params![u64_to_sql(secret_id), kind_to_sql(kind)],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("protocol_state load_all query failed");
        let items: Vec<StateItem> = rows
            .map(|r| decode(&r.expect("protocol_state row read failed")))
            .collect();
        Box::pin(std::future::ready(Ok(items)))
    }
}
