//! `DeRecSecretStore` over Postgres — persists each `SecretValue`
//! as a tagged BYTEA blob keyed by `(secret_id, channel_id, kind)`.

use derec_library::protocol::{
    DeRecSecretStore, MissingPolicy, SecretKind, SecretStoreError, SecretStoreFuture, SecretValue,
};
use derec_library::types::ChannelId;
use std::collections::HashMap;
use tokio_postgres::types::ToSql;

use crate::codec::{decode_secret_value, encode_secret_value, secret_kind_tag};
use crate::db::{SharedClient, sql_to_u64, u64_to_sql};

pub struct PostgresSecretStore {
    client: SharedClient,
}

impl PostgresSecretStore {
    pub fn new(client: SharedClient) -> Self {
        Self { client }
    }
}

impl DeRecSecretStore for PostgresSecretStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let channel_id = u64_to_sql(channel_id.0);
        let kind_i32 = secret_kind_tag(kind);
        Box::pin(async move {
            let row = client
                .query_opt(
                    "SELECT data FROM secrets WHERE secret_id = $1 AND channel_id = $2 AND kind = $3",
                    &[&secret_id, &channel_id, &kind_i32],
                )
                .await
                .expect("secret load failed");
            Ok(row.map(|r| decode_secret_value(&r.get::<_, Vec<u8>>(0))))
        })
    }

    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        let requested: Vec<u64> = channel_ids.iter().map(|c| c.0).collect();
        let client = self.client.clone();
        let secret_id_i64 = u64_to_sql(secret_id);
        let kind_i32 = secret_kind_tag(kind);
        Box::pin(async move {
            if requested.is_empty() {
                return Ok(Vec::new());
            }

            // `$1 = ANY($2::bigint[])` is the idiomatic Postgres
            // alternative to a dynamic IN-list and avoids the
            // SQL-rebuild step.
            let channel_ids_i64: Vec<i64> =
                requested.iter().copied().map(u64_to_sql).collect();
            let params: [&(dyn ToSql + Sync); 3] = [&secret_id_i64, &kind_i32, &channel_ids_i64];
            let rows = client
                .query(
                    "SELECT channel_id, data FROM secrets \
                     WHERE secret_id = $1 AND kind = $2 AND channel_id = ANY($3::bigint[])",
                    &params,
                )
                .await
                .expect("load_many query failed");

            let mut found: HashMap<u64, SecretValue> = HashMap::new();
            for row in rows {
                let cid = sql_to_u64(row.get::<_, i64>(0));
                let bytes: Vec<u8> = row.get(1);
                found.insert(cid, decode_secret_value(&bytes));
            }

            let mut result: Vec<(ChannelId, SecretValue)> = Vec::with_capacity(requested.len());
            let mut missing: Vec<u64> = Vec::new();
            for cid in &requested {
                match found.remove(cid) {
                    Some(v) => result.push((ChannelId(*cid), v)),
                    None => missing.push(*cid),
                }
            }
            if missing_policy == MissingPolicy::Fail && !missing.is_empty() {
                return Err(SecretStoreError::MissingEntries {
                    kind,
                    channel_ids: missing,
                });
            }
            Ok(result)
        })
    }

    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        value: SecretValue,
    ) -> SecretStoreFuture<'_, ()> {
        let kind = match &value {
            SecretValue::SharedKey(_) => SecretKind::SharedKey,
            SecretValue::PairingSecret(_) => SecretKind::PairingSecret,
            SecretValue::PairingContact(_) => SecretKind::PairingContact,
        };
        let bytes = encode_secret_value(&value);
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let channel_id = u64_to_sql(channel_id.0);
        let kind_i32 = secret_kind_tag(kind);
        Box::pin(async move {
            client
                .execute(
                    "INSERT INTO secrets (secret_id, channel_id, kind, data) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (secret_id, channel_id, kind) DO UPDATE SET data = EXCLUDED.data",
                    &[&secret_id, &channel_id, &kind_i32, &bytes],
                )
                .await
                .expect("secret save failed");
            Ok(())
        })
    }

    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, ()> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let channel_id = u64_to_sql(channel_id.0);
        let kind_i32 = secret_kind_tag(kind);
        Box::pin(async move {
            client
                .execute(
                    "DELETE FROM secrets WHERE secret_id = $1 AND channel_id = $2 AND kind = $3",
                    &[&secret_id, &channel_id, &kind_i32],
                )
                .await
                .expect("secret remove failed");
            Ok(())
        })
    }
}
