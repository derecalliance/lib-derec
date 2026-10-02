// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::DeRecUserSecretStore;
use derec_library::protocol::ShareStoreFuture;
use derec_library::protocol::types::UserSecrets;

use crate::codec::{assemble_user_secrets, encode_user_secrets_payload};
use crate::db::{SharedClient, sql_to_u64, u64_to_sql};

pub struct PostgresUserSecretStore {
    client: SharedClient,
}

impl PostgresUserSecretStore {
    pub fn new(client: SharedClient) -> Self {
        Self { client }
    }
}

impl DeRecUserSecretStore for PostgresUserSecretStore {
    fn load_latest(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        Box::pin(async move {
            let row = client
                .query_opt(
                    "SELECT version, description, payload, author_replica_id
                     FROM user_secrets WHERE secret_id = $1",
                    &[&secret_id],
                )
                .await
                .expect("user_secrets load_latest failed");
            Ok(row.map(|r| {
                let version = r.get::<_, i64>(0) as u32;
                let description: Option<String> = r.get(1);
                let payload: Vec<u8> = r.get(2);
                let author: Option<i64> = r.get(3);
                assemble_user_secrets(version, description, payload, author.map(sql_to_u64))
            }))
        })
    }

    fn save_latest(&mut self, secret_id: u64, value: UserSecrets) -> ShareStoreFuture<'_, ()> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let version_i64 = value.version as i64;
        let description = value.description.clone();
        let payload = encode_user_secrets_payload(&value.secrets);
        let author = value.author_replica_id.map(u64_to_sql);
        Box::pin(async move {
            client
                .execute(
                    "INSERT INTO user_secrets (secret_id, version, description, payload, author_replica_id)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (secret_id) DO UPDATE SET
                         version           = EXCLUDED.version,
                         description       = EXCLUDED.description,
                         payload           = EXCLUDED.payload,
                         author_replica_id = EXCLUDED.author_replica_id",
                    &[&secret_id, &version_i64, &description, &payload, &author],
                )
                .await
                .expect("user_secrets save_latest failed");
            Ok(())
        })
    }

    fn remove(&mut self, secret_id: u64) -> ShareStoreFuture<'_, ()> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        Box::pin(async move {
            client
                .execute(
                    "DELETE FROM user_secrets WHERE secret_id = $1",
                    &[&secret_id],
                )
                .await
                .expect("user_secrets remove failed");
            Ok(())
        })
    }
}
