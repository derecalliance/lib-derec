// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::types::Share;
use derec_library::protocol::{DeRecShareStore, ShareStoreFuture};
use derec_library::types::ChannelId;
use tokio_postgres::types::ToSql;

use crate::db::{SharedClient, sql_to_u64, u64_to_sql};

pub struct PostgresShareStore {
    client: SharedClient,
}

impl PostgresShareStore {
    pub fn new(client: SharedClient) -> Self {
        Self { client }
    }
}

impl DeRecShareStore for PostgresShareStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let versions: Vec<i64> = versions.iter().map(|v| *v as i64).collect();
        let client = self.client.clone();
        let secret_id_i64 = u64_to_sql(secret_id);
        let channel_id_i64 = u64_to_sql(channel_id.0);
        Box::pin(async move {
            let rows = if versions.is_empty() {
                client
                    .query(
                        "SELECT share_secret_id, version, replica_id, bytes FROM shares \
                         WHERE secret_id = $1 AND channel_id = $2",
                        &[&secret_id_i64, &channel_id_i64],
                    )
                    .await
                    .expect("share load failed")
            } else {
                let params: [&(dyn ToSql + Sync); 3] =
                    [&secret_id_i64, &channel_id_i64, &versions];
                client
                    .query(
                        "SELECT share_secret_id, version, replica_id, bytes FROM shares \
                         WHERE secret_id = $1 AND channel_id = $2 AND version = ANY($3::bigint[])",
                        &params,
                    )
                    .await
                    .expect("share load failed")
            };
            Ok(rows.into_iter().map(row_to_share).collect())
        })
    }

    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let channel_ids: Vec<i64> = channel_ids.iter().map(|c| u64_to_sql(c.0)).collect();
        let versions: Vec<i64> = versions.iter().map(|v| *v as i64).collect();
        let client = self.client.clone();
        let secret_id_i64 = u64_to_sql(secret_id);
        Box::pin(async move {
            if channel_ids.is_empty() {
                return Ok(Vec::new());
            }
            let rows = if versions.is_empty() {
                let params: [&(dyn ToSql + Sync); 2] = [&secret_id_i64, &channel_ids];
                client
                    .query(
                        "SELECT share_secret_id, version, replica_id, bytes FROM shares \
                         WHERE secret_id = $1 AND channel_id = ANY($2::bigint[])",
                        &params,
                    )
                    .await
                    .expect("load_many failed")
            } else {
                let params: [&(dyn ToSql + Sync); 3] =
                    [&secret_id_i64, &channel_ids, &versions];
                client
                    .query(
                        "SELECT share_secret_id, version, replica_id, bytes FROM shares \
                         WHERE secret_id = $1 AND channel_id = ANY($2::bigint[]) \
                         AND version = ANY($3::bigint[])",
                        &params,
                    )
                    .await
                    .expect("load_many failed")
            };
            Ok(rows.into_iter().map(row_to_share).collect())
        })
    }

    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let channel_ids: Vec<i64> = channel_ids.iter().map(|c| u64_to_sql(c.0)).collect();
        let client = self.client.clone();
        let secret_id_i64 = u64_to_sql(secret_id);
        Box::pin(async move {
            if channel_ids.is_empty() {
                return Ok(Vec::new());
            }
            let params: [&(dyn ToSql + Sync); 2] = [&secret_id_i64, &channel_ids];
            let rows = client
                .query(
                    "SELECT share_secret_id, version, replica_id, bytes FROM shares \
                     WHERE secret_id = $1 AND channel_id = ANY($2::bigint[])",
                    &params,
                )
                .await
                .expect("load_all failed");
            Ok(rows.into_iter().map(row_to_share).collect())
        })
    }

    fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        Box::pin(async move {
            let row = client
                .query_one(
                    "SELECT MAX(version) FROM shares WHERE secret_id = $1",
                    &[&secret_id],
                )
                .await
                .expect("latest_version failed");
            let v: Option<i64> = row.get(0);
            Ok(v.map(|x| x as u32))
        })
    }

    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        share: Share,
    ) -> ShareStoreFuture<'_, ()> {
        debug_assert_eq!(
            share.secret_id, secret_id,
            "DeRecShareStore::save invariant: share.secret_id ({}) must match partition secret_id ({})",
            share.secret_id, secret_id,
        );
        let client = self.client.clone();
        let secret_id_i64 = u64_to_sql(secret_id);
        let channel_id_i64 = u64_to_sql(channel_id.0);
        let version_i64 = share.version as i64;
        let replica_id_i64: Option<i64> = share.replica_id.map(u64_to_sql);
        let share_secret_id_i64 = u64_to_sql(share.secret_id);
        let bytes = share.bytes;
        Box::pin(async move {
            client
                .execute(
                    "INSERT INTO shares (secret_id, channel_id, version, replica_id, share_secret_id, bytes) \
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT ON CONSTRAINT shares_uniq DO UPDATE SET
                         share_secret_id = EXCLUDED.share_secret_id,
                         bytes           = EXCLUDED.bytes",
                    &[
                        &secret_id_i64,
                        &channel_id_i64,
                        &version_i64,
                        &replica_id_i64,
                        &share_secret_id_i64,
                        &bytes,
                    ],
                )
                .await
                .expect("share save failed");
            Ok(())
        })
    }

    fn remove_channel(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, ()> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let channel_id = u64_to_sql(channel_id.0);
        Box::pin(async move {
            client
                .execute(
                    "DELETE FROM shares WHERE secret_id = $1 AND channel_id = $2",
                    &[&secret_id, &channel_id],
                )
                .await
                .expect("share remove_channel failed");
            Ok(())
        })
    }
}

fn row_to_share(row: tokio_postgres::Row) -> Share {
    Share {
        secret_id: sql_to_u64(row.get::<_, i64>(0)),
        version: row.get::<_, i64>(1) as u32,
        replica_id: row.get::<_, Option<i64>>(2).map(sql_to_u64),
        bytes: row.get::<_, Vec<u8>>(3),
    }
}
