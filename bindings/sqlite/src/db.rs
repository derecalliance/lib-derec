// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use rusqlite::Connection;
use std::sync::{Arc, Mutex};

/// Migrations bundled into the binary at compile time. Adding a new
/// migration is two lines: drop a new `.sql` file under `migrations/`
/// and append an entry to this slice with a higher version number.
/// `version` must be strictly increasing.
const MIGRATIONS: &[(i64, &str, &str)] = &[(
    1,
    "0001_init",
    include_str!("../migrations/0001_init.sql"),
)];

/// Shared handle to the underlying in-memory SQLite connection.
///
/// All four `Sqlite*Store` implementations hold a clone of this handle
/// so they read and write through the same connection — that's how the
/// stores agree on a single backing database without each opening their
/// own `:memory:` instance (which would be a separate, empty database).
pub type SharedConnection = Arc<Mutex<Connection>>;

pub struct Database {
    connection: SharedConnection,
}

impl Database {
    /// Open a fresh in-memory database and apply every pending
    /// migration.
    pub fn open_in_memory() -> Self {
        let connection =
            Connection::open_in_memory().expect("failed to open in-memory SQLite database");
        apply_migrations(&connection);
        Self {
            connection: Arc::new(Mutex::new(connection)),
        }
    }

    /// Clone of the shared connection handle. Hand one of these to
    /// each store at construction time.
    pub fn connection(&self) -> SharedConnection {
        self.connection.clone()
    }
}

fn apply_migrations(connection: &Connection) {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS __migrations (
                version    INTEGER PRIMARY KEY,
                name       TEXT    NOT NULL,
                applied_at INTEGER NOT NULL
            );",
        )
        .expect("failed to create __migrations table");

    let mut last_version: i64 = connection
        .query_row("SELECT COALESCE(MAX(version), 0) FROM __migrations", [], |row| {
            row.get(0)
        })
        .expect("failed to query __migrations");

    for (version, name, sql) in MIGRATIONS {
        if *version <= last_version {
            continue;
        }
        if *version != last_version + 1 {
            panic!(
                "migration {name}: expected version {} but got {}",
                last_version + 1,
                version
            );
        }
        connection
            .execute_batch(sql)
            .unwrap_or_else(|e| panic!("failed to apply migration {name}: {e}"));
        connection
            .execute(
                "INSERT INTO __migrations (version, name, applied_at) VALUES (?1, ?2, strftime('%s','now'))",
                rusqlite::params![version, name],
            )
            .unwrap_or_else(|e| panic!("failed to record migration {name}: {e}"));
        last_version = *version;
    }
}

/// Helper: open the lock, panic on a poisoned mutex (which here would
/// only mean a prior panic while holding the lock — fatal either way
/// for these smoke tests).
pub fn lock(connection: &SharedConnection) -> std::sync::MutexGuard<'_, Connection> {
    connection
        .lock()
        .expect("SQLite connection mutex poisoned")
}
