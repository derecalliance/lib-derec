// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::types::{
    ChannelQuery, ChannelRecord, HelperChannel, HelperFilter, ReplicaFilter, ReplicaMember,
};
use derec_library::protocol::{ChannelStoreFuture, DeRecChannelStore};
use derec_library::types::ChannelId;
use std::collections::{HashSet, VecDeque};

use crate::codec::{
    channel_status_tag, decode_helper, decode_member, encode_channel, replica_role_tag,
    sender_kind_tag, sql_to_u64, u64_to_sql,
};
use crate::db::{SharedConnection, lock};

pub struct SqliteChannelStore {
    connection: SharedConnection,
}

impl SqliteChannelStore {
    pub fn new(connection: SharedConnection) -> Self {
        Self { connection }
    }
}

impl DeRecChannelStore for SqliteChannelStore {
    fn load(
        &self,
        secret_id: u64,
        query: ChannelQuery,
    ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
        let conn = lock(&self.connection);
        // Helper channels and members live in separate tables with separate
        // primary keys — a member is addressed by `replica_id` alone, because
        // it keeps its identity while its channel changes during a handover.
        let result = match query {
            ChannelQuery::Helper { channel_id } => conn
                .query_row(
                    "SELECT data FROM channels WHERE secret_id = ?1 AND channel_id = ?2",
                    rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id.0)],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .ok()
                .map(|bytes| ChannelRecord::Helper(decode_helper(&bytes))),
            ChannelQuery::Replica { replica_id, .. } => conn
                .query_row(
                    "SELECT data FROM replica_members WHERE secret_id = ?1 AND replica_id = ?2",
                    rusqlite::params![u64_to_sql(secret_id), u64_to_sql(replica_id.0)],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .ok()
                .map(|bytes| ChannelRecord::Replica(decode_member(&bytes))),
        };
        Box::pin(std::future::ready(Ok(result)))
    }

    fn save(&mut self, secret_id: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
        let conn = lock(&self.connection);
        let bytes = encode_channel(&record);
        match &record {
            ChannelRecord::Helper(h) => {
                conn.execute(
                    "INSERT INTO channels (secret_id, channel_id, status, peer_role, data)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(secret_id, channel_id) DO UPDATE SET
                         status = excluded.status,
                         peer_role = excluded.peer_role,
                         data = excluded.data",
                    rusqlite::params![
                        u64_to_sql(secret_id),
                        u64_to_sql(h.channel_id.0),
                        channel_status_tag(h.status),
                        sender_kind_tag(h.peer_role),
                        bytes
                    ],
                )
                .expect("helper channel save failed");
            }
            ChannelRecord::Replica(m) => {
                conn.execute(
                    "INSERT INTO replica_members
                         (secret_id, replica_id, channel_id, status, role, data)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(secret_id, replica_id) DO UPDATE SET
                         channel_id = excluded.channel_id,
                         status = excluded.status,
                         role = excluded.role,
                         data = excluded.data",
                    rusqlite::params![
                        u64_to_sql(secret_id),
                        u64_to_sql(m.replica_id.0),
                        u64_to_sql(m.channel_id.0),
                        channel_status_tag(m.status),
                        replica_role_tag(m.role),
                        bytes
                    ],
                )
                .expect("replica member save failed");
            }
        }
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(&mut self, secret_id: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
        let conn = lock(&self.connection);
        let affected = match query {
            ChannelQuery::Helper { channel_id } => {
                let n = conn
                    .execute(
                        "DELETE FROM channels WHERE secret_id = ?1 AND channel_id = ?2",
                        rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id.0)],
                    )
                    .expect("helper channel remove failed");
                conn.execute(
                    "DELETE FROM channel_links WHERE secret_id = ?1 AND (a = ?2 OR b = ?2)",
                    rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id.0)],
                )
                .expect("channel_link cleanup failed");
                n
            }
            ChannelQuery::Replica { replica_id, .. } => conn
                .execute(
                    "DELETE FROM replica_members WHERE secret_id = ?1 AND replica_id = ?2",
                    rusqlite::params![u64_to_sql(secret_id), u64_to_sql(replica_id.0)],
                )
                .expect("replica member remove failed"),
        };
        Box::pin(std::future::ready(Ok(affected > 0)))
    }

    fn helpers(
        &self,
        secret_id: u64,
        filter: HelperFilter,
    ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
        let conn = lock(&self.connection);
        let mut sql = String::from("SELECT data FROM channels WHERE secret_id = ?1");
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(u64_to_sql(secret_id))];

        push_id_clause(
            &mut sql,
            &mut params,
            "channel_id",
            filter.ids.iter().map(|c| c.0),
            false,
        );
        push_tag_clause(
            &mut sql,
            &mut params,
            "status",
            filter.status.iter().copied().map(channel_status_tag),
        );
        if let Some(role) = filter.role {
            params.push(Box::new(sender_kind_tag(role)));
            sql.push_str(&format!(" AND peer_role = ?{}", params.len()));
        }
        push_id_clause(
            &mut sql,
            &mut params,
            "channel_id",
            filter.exclude.iter().map(|c| c.0),
            true,
        );

        let mut stmt = conn.prepare(&sql).expect("helpers prepare failed");
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(refs.as_slice(), |row| row.get::<_, Vec<u8>>(0))
            .expect("helpers query failed");

        let mut out = Vec::new();
        for row in rows {
            out.push(decode_helper(&row.expect("helpers row failed")));
        }
        Box::pin(std::future::ready(Ok(out)))
    }

    fn replicas(
        &self,
        secret_id: u64,
        filter: ReplicaFilter,
    ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
        let conn = lock(&self.connection);
        let mut sql = String::from("SELECT data FROM replica_members WHERE secret_id = ?1");
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(u64_to_sql(secret_id))];

        push_id_clause(
            &mut sql,
            &mut params,
            "replica_id",
            filter.ids.iter().map(|r| r.0),
            false,
        );
        push_tag_clause(
            &mut sql,
            &mut params,
            "status",
            filter.status.iter().copied().map(channel_status_tag),
        );
        if let Some(role) = filter.role {
            params.push(Box::new(replica_role_tag(role)));
            sql.push_str(&format!(" AND role = ?{}", params.len()));
        }
        push_id_clause(
            &mut sql,
            &mut params,
            "replica_id",
            filter.exclude.iter().map(|r| r.0),
            true,
        );

        // Ordered deliberately: this order picks the successor when the
        // group's source is removed, and an unordered SELECT would leave
        // that to the planner. See `DeRecChannelStore::replicas`.
        sql.push_str(" ORDER BY replica_id");

        let mut stmt = conn.prepare(&sql).expect("replicas prepare failed");
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(refs.as_slice(), |row| row.get::<_, Vec<u8>>(0))
            .expect("replicas query failed");

        let mut out = Vec::new();
        for row in rows {
            out.push(decode_member(&row.expect("replicas row failed")));
        }
        Box::pin(std::future::ready(Ok(out)))
    }

    fn link_channel(
        &mut self,
        secret_id: u64,
        a: ChannelId,
        b: ChannelId,
    ) -> ChannelStoreFuture<'_, ()> {
        if a.0 != b.0 {
            let conn = lock(&self.connection);
            conn.execute(
                "INSERT OR IGNORE INTO channel_links (secret_id, a, b) VALUES (?1, ?2, ?3)",
                rusqlite::params![u64_to_sql(secret_id), u64_to_sql(a.0), u64_to_sql(b.0)],
            )
            .expect("link_channel forward insert failed");
            conn.execute(
                "INSERT OR IGNORE INTO channel_links (secret_id, a, b) VALUES (?1, ?2, ?3)",
                rusqlite::params![u64_to_sql(secret_id), u64_to_sql(b.0), u64_to_sql(a.0)],
            )
            .expect("link_channel reverse insert failed");
        }
        Box::pin(std::future::ready(Ok(())))
    }

    fn linked_channels(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        let conn = lock(&self.connection);
        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<u64> = VecDeque::new();
        queue.push_back(channel_id.0);

        let mut stmt = conn
            .prepare("SELECT b FROM channel_links WHERE secret_id = ?1 AND a = ?2")
            .expect("linked_channels prepare failed");

        while let Some(curr) = queue.pop_front() {
            if !visited.insert(curr) {
                continue;
            }
            let neighbors = stmt
                .query_map(
                    rusqlite::params![u64_to_sql(secret_id), u64_to_sql(curr)],
                    |row| row.get::<_, i64>(0),
                )
                .expect("linked_channels query failed");
            for n in neighbors {
                let n = sql_to_u64(n.expect("linked_channels row failed"));
                if !visited.contains(&n) {
                    queue.push_back(n);
                }
            }
        }

        let result: Vec<ChannelId> = visited.into_iter().map(ChannelId).collect();
        Box::pin(std::future::ready(Ok(result)))
    }
}

/// Append `AND col IN (…)` — or `NOT IN` when `negate` — for a non-empty id
/// list, binding each id as its own parameter.
///
/// An empty list appends nothing, which is what an empty
/// [`ChannelFilter`](derec_library::protocol::types::ChannelFilter) field
/// means: no restriction on this column.
fn push_id_clause(
    sql: &mut String,
    params: &mut Vec<Box<dyn rusqlite::ToSql>>,
    column: &str,
    ids: impl Iterator<Item = u64>,
    negate: bool,
) {
    let placeholders = bind_all(params, ids.map(|id| u64_to_sql(id) as i64));
    if placeholders.is_empty() {
        return;
    }
    let op = if negate { "NOT IN" } else { "IN" };
    sql.push_str(&format!(" AND {column} {op} ({})", placeholders.join(", ")));
}

/// Append `AND col IN (…)` for a non-empty list of enum tags.
fn push_tag_clause(
    sql: &mut String,
    params: &mut Vec<Box<dyn rusqlite::ToSql>>,
    column: &str,
    tags: impl Iterator<Item = i64>,
) {
    let placeholders = bind_all(params, tags);
    if placeholders.is_empty() {
        return;
    }
    sql.push_str(&format!(" AND {column} IN ({})", placeholders.join(", ")));
}

/// Bind each value and return its `?N` placeholder, in order.
fn bind_all(
    params: &mut Vec<Box<dyn rusqlite::ToSql>>,
    values: impl Iterator<Item = i64>,
) -> Vec<String> {
    values
        .map(|v| {
            params.push(Box::new(v));
            format!("?{}", params.len())
        })
        .collect()
}
