// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::{ChannelStoreFuture, DeRecChannelStore};
use derec_library::protocol::types::Channel;
use derec_library::types::ChannelId;
use std::collections::{HashSet, VecDeque};

use crate::codec::{decode_channel, encode_channel, sql_to_u64, u64_to_sql};
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
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Option<Channel>> {
        let conn = lock(&self.connection);
        let result = conn
            .query_row(
                "SELECT data FROM channels WHERE secret_id = ?1 AND channel_id = ?2",
                rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id.0)],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok()
            .map(|bytes| decode_channel(&bytes));
        Box::pin(std::future::ready(Ok(result)))
    }

    fn save(&mut self, secret_id: u64, channel: Channel) -> ChannelStoreFuture<'_, ()> {
        let conn = lock(&self.connection);
        let channel_id = channel.id.0;
        let bytes = encode_channel(&channel);
        conn.execute(
            "INSERT INTO channels (secret_id, channel_id, data) VALUES (?1, ?2, ?3)
             ON CONFLICT(secret_id, channel_id) DO UPDATE SET data = excluded.data",
            rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id), bytes],
        )
        .expect("channel save failed");
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, bool> {
        let conn = lock(&self.connection);
        let affected = conn
            .execute(
                "DELETE FROM channels WHERE secret_id = ?1 AND channel_id = ?2",
                rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id.0)],
            )
            .expect("channel remove failed");
        conn.execute(
            "DELETE FROM channel_links WHERE secret_id = ?1 AND (a = ?2 OR b = ?2)",
            rusqlite::params![u64_to_sql(secret_id), u64_to_sql(channel_id.0)],
        )
        .expect("channel_link cleanup failed");
        Box::pin(std::future::ready(Ok(affected > 0)))
    }

    fn channels(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
        let conn = lock(&self.connection);
        let mut stmt = conn
            .prepare("SELECT data FROM channels WHERE secret_id = ?1")
            .expect("channels prepare failed");
        let rows = stmt
            .query_map(rusqlite::params![u64_to_sql(secret_id)], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .expect("channels query failed");

        let mut out = Vec::new();
        for row in rows {
            let bytes = row.expect("channels row failed");
            out.push(decode_channel(&bytes));
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
