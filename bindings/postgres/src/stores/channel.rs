//! `DeRecChannelStore` over Postgres — persists `Channel` records as
//! serde-JSON blobs in the `channels` table and the undirected
//! channel-link graph in `channel_links`.

use derec_library::protocol::types::Channel;
use derec_library::protocol::{ChannelStoreFuture, DeRecChannelStore};
use derec_library::types::ChannelId;
use std::collections::{HashSet, VecDeque};

use crate::codec::{decode_channel, encode_channel};
use crate::db::{SharedClient, sql_to_u64, u64_to_sql};

pub struct PostgresChannelStore {
    client: SharedClient,
}

impl PostgresChannelStore {
    pub fn new(client: SharedClient) -> Self {
        Self { client }
    }
}

impl DeRecChannelStore for PostgresChannelStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Option<Channel>> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let channel_id = u64_to_sql(channel_id.0);
        Box::pin(async move {
            let row = client
                .query_opt(
                    "SELECT data FROM channels WHERE secret_id = $1 AND channel_id = $2",
                    &[&secret_id, &channel_id],
                )
                .await
                .expect("channels load failed");
            Ok(row.map(|r| decode_channel(&r.get::<_, Vec<u8>>(0))))
        })
    }

    fn save(&mut self, secret_id: u64, channel: Channel) -> ChannelStoreFuture<'_, ()> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let channel_id = u64_to_sql(channel.id.0);
        let bytes = encode_channel(&channel);
        Box::pin(async move {
            client
                .execute(
                    "INSERT INTO channels (secret_id, channel_id, data) VALUES ($1, $2, $3)
                     ON CONFLICT (secret_id, channel_id) DO UPDATE SET data = EXCLUDED.data",
                    &[&secret_id, &channel_id, &bytes],
                )
                .await
                .expect("channel save failed");
            Ok(())
        })
    }

    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, bool> {
        let client = self.client.clone();
        let secret_id_i64 = u64_to_sql(secret_id);
        let channel_id_i64 = u64_to_sql(channel_id.0);
        Box::pin(async move {
            let affected = client
                .execute(
                    "DELETE FROM channels WHERE secret_id = $1 AND channel_id = $2",
                    &[&secret_id_i64, &channel_id_i64],
                )
                .await
                .expect("channel remove failed");
            // Per-channel link cleanup mirrors the SQLite binding: a
            // removed channel must not stay reachable through the
            // graph.
            client
                .execute(
                    "DELETE FROM channel_links WHERE secret_id = $1 AND (a = $2 OR b = $2)",
                    &[&secret_id_i64, &channel_id_i64],
                )
                .await
                .expect("channel_link cleanup failed");
            Ok(affected > 0)
        })
    }

    fn channels(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        Box::pin(async move {
            let rows = client
                .query(
                    "SELECT data FROM channels WHERE secret_id = $1",
                    &[&secret_id],
                )
                .await
                .expect("channels query failed");
            Ok(rows
                .into_iter()
                .map(|r| decode_channel(&r.get::<_, Vec<u8>>(0)))
                .collect())
        })
    }

    fn link_channel(
        &mut self,
        secret_id: u64,
        a: ChannelId,
        b: ChannelId,
    ) -> ChannelStoreFuture<'_, ()> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let a_i64 = u64_to_sql(a.0);
        let b_i64 = u64_to_sql(b.0);
        Box::pin(async move {
            if a_i64 != b_i64 {
                client
                    .execute(
                        "INSERT INTO channel_links (secret_id, a, b) VALUES ($1, $2, $3)
                         ON CONFLICT DO NOTHING",
                        &[&secret_id, &a_i64, &b_i64],
                    )
                    .await
                    .expect("link_channel forward insert failed");
                client
                    .execute(
                        "INSERT INTO channel_links (secret_id, a, b) VALUES ($1, $2, $3)
                         ON CONFLICT DO NOTHING",
                        &[&secret_id, &b_i64, &a_i64],
                    )
                    .await
                    .expect("link_channel reverse insert failed");
            }
            Ok(())
        })
    }

    fn linked_channels(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        let client = self.client.clone();
        let secret_id_i64 = u64_to_sql(secret_id);
        let start = channel_id.0;
        Box::pin(async move {
            let mut visited: HashSet<u64> = HashSet::new();
            let mut queue: VecDeque<u64> = VecDeque::new();
            queue.push_back(start);

            while let Some(curr) = queue.pop_front() {
                if !visited.insert(curr) {
                    continue;
                }
                let curr_i64 = u64_to_sql(curr);
                let rows = client
                    .query(
                        "SELECT b FROM channel_links WHERE secret_id = $1 AND a = $2",
                        &[&secret_id_i64, &curr_i64],
                    )
                    .await
                    .expect("linked_channels query failed");
                for row in rows {
                    let n = sql_to_u64(row.get::<_, i64>(0));
                    if !visited.contains(&n) {
                        queue.push_back(n);
                    }
                }
            }
            Ok(visited.into_iter().map(ChannelId).collect())
        })
    }
}
