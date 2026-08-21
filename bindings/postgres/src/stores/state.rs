// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Durable [`DeRecStateStore`] over PostgreSQL.
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
use derec_library::protocol::{DeRecStateStore, StateItem, StateKey, StateKind, StateStoreFuture};

use crate::db::{SharedClient, u64_to_sql};

pub struct PostgresStateStore {
    client: SharedClient,
}

impl PostgresStateStore {
    pub fn new(client: SharedClient) -> Self {
        Self { client }
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

impl DeRecStateStore for PostgresStateStore {
    fn save(&mut self, secret_id: u64, item: StateItem) -> StateStoreFuture<'_, ()> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let (kind, sub_a, sub_b) = key_columns(&item.key());
        let data = encode(&item);
        Box::pin(async move {
            client
                .execute(
                    "INSERT INTO protocol_state (secret_id, kind, sub_a, sub_b, data)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (secret_id, kind, sub_a, sub_b) DO UPDATE SET
                         data = EXCLUDED.data",
                    &[&secret_id, &kind, &sub_a, &sub_b, &data],
                )
                .await
                .expect("protocol_state save failed");
            Ok(())
        })
    }

    fn load(&self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, Option<StateItem>> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let (kind, sub_a, sub_b) = key_columns(&key);
        Box::pin(async move {
            let row = client
                .query_opt(
                    "SELECT data FROM protocol_state
                     WHERE secret_id = $1 AND kind = $2 AND sub_a = $3 AND sub_b = $4",
                    &[&secret_id, &kind, &sub_a, &sub_b],
                )
                .await
                .expect("protocol_state load failed");
            Ok(row.map(|r| decode(&r.get::<_, Vec<u8>>(0))))
        })
    }

    fn remove(&mut self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, bool> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let (kind, sub_a, sub_b) = key_columns(&key);
        Box::pin(async move {
            let affected = client
                .execute(
                    "DELETE FROM protocol_state
                     WHERE secret_id = $1 AND kind = $2 AND sub_a = $3 AND sub_b = $4",
                    &[&secret_id, &kind, &sub_a, &sub_b],
                )
                .await
                .expect("protocol_state remove failed");
            Ok(affected > 0)
        })
    }

    fn load_all(&self, secret_id: u64, kind: StateKind) -> StateStoreFuture<'_, Vec<StateItem>> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let kind = kind_to_sql(kind);
        Box::pin(async move {
            let rows = client
                .query(
                    "SELECT data FROM protocol_state WHERE secret_id = $1 AND kind = $2",
                    &[&secret_id, &kind],
                )
                .await
                .expect("protocol_state load_all failed");
            Ok(rows
                .into_iter()
                .map(|r| decode(&r.get::<_, Vec<u8>>(0)))
                .collect())
        })
    }
}
