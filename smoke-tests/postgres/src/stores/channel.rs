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
    sender_kind_tag,
};
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
        query: ChannelQuery,
    ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        Box::pin(async move {
            // Helper channels and members live in separate tables with separate
            // primary keys — a member is addressed by `replica_id` alone,
            // because it keeps its identity while its channel changes during a
            // handover.
            let record = match query {
                ChannelQuery::Helper { channel_id } => client
                    .query_opt(
                        "SELECT data FROM channels WHERE secret_id = $1 AND channel_id = $2",
                        &[&secret_id, &u64_to_sql(channel_id.0)],
                    )
                    .await
                    .expect("channels load failed")
                    .map(|r| ChannelRecord::Helper(decode_helper(&r.get::<_, Vec<u8>>(0)))),
                ChannelQuery::Replica { replica_id, .. } => client
                    .query_opt(
                        "SELECT data FROM replica_members WHERE secret_id = $1 AND replica_id = $2",
                        &[&secret_id, &u64_to_sql(replica_id.0)],
                    )
                    .await
                    .expect("replica_members load failed")
                    .map(|r| ChannelRecord::Replica(decode_member(&r.get::<_, Vec<u8>>(0)))),
            };
            Ok(record)
        })
    }

    fn save(&mut self, secret_id: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let bytes = encode_channel(&record);
        Box::pin(async move {
            match &record {
                ChannelRecord::Helper(h) => {
                    client
                        .execute(
                            "INSERT INTO channels (secret_id, channel_id, status, peer_role, data)
                             VALUES ($1, $2, $3, $4, $5)
                             ON CONFLICT (secret_id, channel_id) DO UPDATE SET
                                 status = EXCLUDED.status,
                                 peer_role = EXCLUDED.peer_role,
                                 data = EXCLUDED.data",
                            &[
                                &secret_id,
                                &u64_to_sql(h.channel_id.0),
                                &(channel_status_tag(h.status) as i16),
                                &(sender_kind_tag(h.peer_role) as i16),
                                &bytes,
                            ],
                        )
                        .await
                        .expect("helper channel save failed");
                }
                ChannelRecord::Replica(m) => {
                    client
                        .execute(
                            "INSERT INTO replica_members
                                 (secret_id, replica_id, channel_id, status, role, data)
                             VALUES ($1, $2, $3, $4, $5, $6)
                             ON CONFLICT (secret_id, replica_id) DO UPDATE SET
                                 channel_id = EXCLUDED.channel_id,
                                 status = EXCLUDED.status,
                                 role = EXCLUDED.role,
                                 data = EXCLUDED.data",
                            &[
                                &secret_id,
                                &u64_to_sql(m.replica_id.0),
                                &u64_to_sql(m.channel_id.0),
                                &(channel_status_tag(m.status) as i16),
                                &(replica_role_tag(m.role) as i16),
                                &bytes,
                            ],
                        )
                        .await
                        .expect("replica member save failed");
                }
            }
            Ok(())
        })
    }

    fn remove(&mut self, secret_id: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
        let client = self.client.clone();
        let secret_id_i64 = u64_to_sql(secret_id);
        Box::pin(async move {
            let affected = match query {
                ChannelQuery::Helper { channel_id } => {
                    let channel_id_i64 = u64_to_sql(channel_id.0);
                    let n = client
                        .execute(
                            "DELETE FROM channels WHERE secret_id = $1 AND channel_id = $2",
                            &[&secret_id_i64, &channel_id_i64],
                        )
                        .await
                        .expect("helper channel remove failed");
                    client
                        .execute(
                            "DELETE FROM channel_links WHERE secret_id = $1 AND (a = $2 OR b = $2)",
                            &[&secret_id_i64, &channel_id_i64],
                        )
                        .await
                        .expect("channel_link cleanup failed");
                    n
                }
                ChannelQuery::Replica { replica_id, .. } => client
                    .execute(
                        "DELETE FROM replica_members WHERE secret_id = $1 AND replica_id = $2",
                        &[&secret_id_i64, &u64_to_sql(replica_id.0)],
                    )
                    .await
                    .expect("replica member remove failed"),
            };
            Ok(affected > 0)
        })
    }

    fn helpers(
        &self,
        secret_id: u64,
        filter: HelperFilter,
    ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let ids: Vec<i64> = filter.ids.iter().map(|c| u64_to_sql(c.0)).collect();
        let status: Vec<i16> = filter
            .status
            .iter()
            .map(|s| channel_status_tag(*s) as i16)
            .collect();
        let role: Option<i16> = filter.role.map(|r| sender_kind_tag(r) as i16);
        let exclude: Vec<i64> = filter.exclude.iter().map(|c| u64_to_sql(c.0)).collect();
        Box::pin(async move {
            let rows = client
                .query(
                    // One prepared statement whatever the filter holds: an
                    // empty array restricts nothing, which is exactly what an
                    // empty `ChannelFilter` field means.
                    "SELECT data FROM channels
                     WHERE secret_id = $1
                       AND (cardinality($2::bigint[]) = 0 OR channel_id = ANY($2))
                       AND (cardinality($3::smallint[]) = 0 OR status = ANY($3))
                       AND ($4::smallint IS NULL OR peer_role = $4)
                       AND NOT (channel_id = ANY($5::bigint[]))",
                    &[&secret_id, &ids, &status, &role, &exclude],
                )
                .await
                .expect("helpers query failed");
            Ok(rows
                .into_iter()
                .map(|r| decode_helper(&r.get::<_, Vec<u8>>(0)))
                .collect())
        })
    }

    fn replicas(
        &self,
        secret_id: u64,
        filter: ReplicaFilter,
    ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let ids: Vec<i64> = filter.ids.iter().map(|r| u64_to_sql(r.0)).collect();
        let status: Vec<i16> = filter
            .status
            .iter()
            .map(|s| channel_status_tag(*s) as i16)
            .collect();
        let role: Option<i16> = filter.role.map(|r| replica_role_tag(r) as i16);
        let exclude: Vec<i64> = filter.exclude.iter().map(|r| u64_to_sql(r.0)).collect();
        Box::pin(async move {
            let rows = client
                .query(
                    // Ordered deliberately: this order picks the successor when
                    // the group's source is removed, and an unordered SELECT
                    // would leave that to the planner. See
                    // `DeRecChannelStore::replicas`.
                    "SELECT data FROM replica_members
                     WHERE secret_id = $1
                       AND (cardinality($2::bigint[]) = 0 OR replica_id = ANY($2))
                       AND (cardinality($3::smallint[]) = 0 OR status = ANY($3))
                       AND ($4::smallint IS NULL OR role = $4)
                       AND NOT (replica_id = ANY($5::bigint[]))
                     ORDER BY replica_id",
                    &[&secret_id, &ids, &status, &role, &exclude],
                )
                .await
                .expect("replicas query failed");
            Ok(rows
                .into_iter()
                .map(|r| decode_member(&r.get::<_, Vec<u8>>(0)))
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
