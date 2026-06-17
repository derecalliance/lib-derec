//! `DeRecShareStore` over SQLite — persists opaque share bytes plus
//! the denormalized `Share.secret_id` field alongside the partition
//! key `secret_id`. The denormalized column is kept as documented by
//! the trait: it must match the partition key, and an assertion
//! enforces that on save.

use derec_library::protocol::{DeRecShareStore, ShareStoreFuture};
use derec_library::protocol::types::Share;
use derec_library::types::ChannelId;

use crate::codec::{sql_to_u64, u64_to_sql};
use crate::db::{SharedConnection, lock};

pub struct SqliteShareStore {
    connection: SharedConnection,
}

impl SqliteShareStore {
    pub fn new(connection: SharedConnection) -> Self {
        Self { connection }
    }
}

impl DeRecShareStore for SqliteShareStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let conn = lock(&self.connection);
        let result = if versions.is_empty() {
            let mut stmt = conn
                .prepare(
                    "SELECT share_secret_id, version, replica_id, bytes FROM shares \
                     WHERE secret_id = ?1 AND channel_id = ?2",
                )
                .expect("share load prepare failed");
            let rows = stmt
                .query_map(
                    rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id.0)],
                    map_share_row,
                )
                .expect("share load query failed");
            collect_shares(rows)
        } else {
            let placeholders = vec!["?"; versions.len()].join(", ");
            let sql = format!(
                "SELECT share_secret_id, version, replica_id, bytes FROM shares \
                 WHERE secret_id = ? AND channel_id = ? AND version IN ({placeholders})"
            );
            let mut stmt = conn.prepare(&sql).expect("share load prepare failed");
            let mut params: Vec<i64> = Vec::with_capacity(2 + versions.len());
            params.push(u64_to_sql(secret_id));
            params.push(u64_to_sql(channel_id.0));
            for v in versions {
                params.push(*v as i64);
            }
            let bound: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
            let rows = stmt
                .query_map(bound.as_slice(), map_share_row)
                .expect("share load query failed");
            collect_shares(rows)
        };
        Box::pin(std::future::ready(Ok(result)))
    }

    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        if channel_ids.is_empty() {
            return Box::pin(std::future::ready(Ok(Vec::new())));
        }
        let conn = lock(&self.connection);
        let cid_placeholders = vec!["?"; channel_ids.len()].join(", ");

        let (sql, mut params): (String, Vec<i64>) = if versions.is_empty() {
            let mut p: Vec<i64> = Vec::with_capacity(1 + channel_ids.len());
            p.push(u64_to_sql(secret_id));
            for c in channel_ids {
                p.push(u64_to_sql(c.0));
            }
            (
                format!(
                    "SELECT share_secret_id, version, replica_id, bytes FROM shares \
                     WHERE secret_id = ? AND channel_id IN ({cid_placeholders})"
                ),
                p,
            )
        } else {
            let ver_placeholders = vec!["?"; versions.len()].join(", ");
            let mut p: Vec<i64> = Vec::with_capacity(1 + channel_ids.len() + versions.len());
            p.push(u64_to_sql(secret_id));
            for c in channel_ids {
                p.push(u64_to_sql(c.0));
            }
            for v in versions {
                p.push(*v as i64);
            }
            (
                format!(
                    "SELECT share_secret_id, version, replica_id, bytes FROM shares \
                     WHERE secret_id = ? AND channel_id IN ({cid_placeholders}) \
                     AND version IN ({ver_placeholders})"
                ),
                p,
            )
        };

        let mut stmt = conn.prepare(&sql).expect("load_many prepare failed");
        let bound: Vec<&dyn rusqlite::ToSql> = params
            .iter_mut()
            .map(|p| p as &dyn rusqlite::ToSql)
            .collect();
        let rows = stmt
            .query_map(bound.as_slice(), map_share_row)
            .expect("load_many query failed");
        Box::pin(std::future::ready(Ok(collect_shares(rows))))
    }

    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        if channel_ids.is_empty() {
            return Box::pin(std::future::ready(Ok(Vec::new())));
        }
        let conn = lock(&self.connection);
        let cid_placeholders = vec!["?"; channel_ids.len()].join(", ");
        let sql = format!(
            "SELECT share_secret_id, version, replica_id, bytes FROM shares \
             WHERE secret_id = ? AND channel_id IN ({cid_placeholders})"
        );
        let mut stmt = conn.prepare(&sql).expect("load_all prepare failed");
        let mut params: Vec<i64> = Vec::with_capacity(1 + channel_ids.len());
        params.push(u64_to_sql(secret_id));
        for c in channel_ids {
            params.push(u64_to_sql(c.0));
        }
        let bound: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
        let rows = stmt
            .query_map(bound.as_slice(), map_share_row)
            .expect("load_all query failed");
        Box::pin(std::future::ready(Ok(collect_shares(rows))))
    }

    fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>> {
        let conn = lock(&self.connection);
        let max: Option<i64> = conn
            .query_row(
                "SELECT MAX(version) FROM shares WHERE secret_id = ?1",
                rusqlite::params![u64_to_sql(secret_id)],
                |row| row.get(0),
            )
            .ok()
            .flatten();
        Box::pin(std::future::ready(Ok(max.map(|v| v as u32))))
    }

    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        share: Share,
    ) -> ShareStoreFuture<'_, ()> {
        // The trait contract: the denormalized `share.secret_id` MUST
        // match the partition key. Cheap invariant check makes the
        // bug obvious if any caller ever violates it.
        debug_assert_eq!(
            share.secret_id, secret_id,
            "DeRecShareStore::save invariant: share.secret_id ({}) must match partition secret_id ({})",
            share.secret_id, secret_id,
        );
        let conn = lock(&self.connection);
        // The full storage key is (secret_id, channel_id, version,
        // replica_id) per the trait contract — distinct replicas
        // writing the same numeric version must both survive.
        // The migration's PRIMARY KEY uses `COALESCE(replica_id, -1)`
        // so the NULL-Owner write is its own slot. ON CONFLICT updates
        // the existing slot in place (idempotent re-send).
        conn.execute(
            "INSERT INTO shares (secret_id, channel_id, version, replica_id, share_secret_id, bytes) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(secret_id, channel_id, version, COALESCE(replica_id, -1)) DO UPDATE SET
                 share_secret_id = excluded.share_secret_id,
                 bytes           = excluded.bytes",
            rusqlite::params![
                u64_to_sql(secret_id),
                u64_to_sql(channel_id.0),
                share.version as i64,
                share.replica_id.map(u64_to_sql),
                u64_to_sql(share.secret_id),
                share.bytes,
            ],
        )
        .expect("share save failed");
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove_channel(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, ()> {
        let conn = lock(&self.connection);
        conn.execute(
            "DELETE FROM shares WHERE secret_id = ?1 AND channel_id = ?2",
            rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id.0)],
        )
        .expect("share remove_channel failed");
        Box::pin(std::future::ready(Ok(())))
    }
}

fn map_share_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Share> {
    Ok(Share {
        secret_id: sql_to_u64(row.get::<_, i64>(0)?),
        version: row.get::<_, i64>(1)? as u32,
        replica_id: row.get::<_, Option<i64>>(2)?.map(|v| sql_to_u64(v)),
        bytes: row.get::<_, Vec<u8>>(3)?,
    })
}

fn collect_shares<I>(rows: I) -> Vec<Share>
where
    I: Iterator<Item = rusqlite::Result<Share>>,
{
    rows.map(|r| r.expect("share row failed")).collect()
}
