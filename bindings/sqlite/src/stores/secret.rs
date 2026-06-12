//! `DeRecSecretStore` over SQLite — persists each `SecretValue` as a
//! tagged blob keyed by `(secret_id, channel_id, kind)`.

use derec_library::protocol::{
    DeRecSecretStore, MissingPolicy, SecretKind, SecretStoreError, SecretStoreFuture, SecretValue,
};
use derec_library::types::ChannelId;
use std::collections::HashMap;

use crate::codec::{
    decode_secret_value, encode_secret_value, secret_kind_tag, sql_to_u64, u64_to_sql,
};
use crate::db::{SharedConnection, lock};

pub struct SqliteSecretStore {
    connection: SharedConnection,
}

impl SqliteSecretStore {
    pub fn new(connection: SharedConnection) -> Self {
        Self { connection }
    }
}

impl DeRecSecretStore for SqliteSecretStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        let conn = lock(&self.connection);
        let result = conn
            .query_row(
                "SELECT data FROM secrets WHERE secret_id = ?1 AND channel_id = ?2 AND kind = ?3",
                rusqlite::params![
                    u64_to_sql(secret_id),
                    u64_to_sql(channel_id.0),
                    secret_kind_tag(kind),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .ok()
            .map(|bytes| decode_secret_value(&bytes));
        Box::pin(std::future::ready(Ok(result)))
    }

    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        if channel_ids.is_empty() {
            return Box::pin(std::future::ready(Ok(Vec::new())));
        }

        let conn = lock(&self.connection);
        // Build a placeholder list `?, ?, ?, …` for the IN clause —
        // SQLite has no native array binding. Keeps the same call
        // shape (single round-trip) the trait expects.
        let placeholders = vec!["?"; channel_ids.len()].join(", ");
        let sql = format!(
            "SELECT channel_id, data FROM secrets \
             WHERE secret_id = ? AND kind = ? AND channel_id IN ({placeholders})"
        );
        let mut stmt = conn.prepare(&sql).expect("load_many prepare failed");

        let mut params: Vec<i64> = Vec::with_capacity(2 + channel_ids.len());
        params.push(u64_to_sql(secret_id));
        params.push(secret_kind_tag(kind));
        for cid in channel_ids {
            params.push(u64_to_sql(cid.0));
        }
        let bound: Vec<&dyn rusqlite::ToSql> =
            params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();

        let rows = stmt
            .query_map(bound.as_slice(), |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .expect("load_many query failed");

        let mut found: HashMap<u64, SecretValue> = HashMap::new();
        for row in rows {
            let (cid, bytes) = row.expect("load_many row failed");
            found.insert(sql_to_u64(cid), decode_secret_value(&bytes));
        }

        // Preserve request order, and apply MissingPolicy on absent
        // entries.
        let mut result: Vec<(ChannelId, SecretValue)> = Vec::with_capacity(channel_ids.len());
        let mut missing: Vec<u64> = Vec::new();
        for cid in channel_ids {
            match found.remove(&cid.0) {
                Some(v) => result.push((*cid, v)),
                None => missing.push(cid.0),
            }
        }
        if missing_policy == MissingPolicy::Fail && !missing.is_empty() {
            return Box::pin(std::future::ready(Err(
                SecretStoreError::MissingEntries {
                    kind,
                    channel_ids: missing,
                },
            )));
        }
        Box::pin(std::future::ready(Ok(result)))
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
        let conn = lock(&self.connection);
        conn.execute(
            "INSERT INTO secrets (secret_id, channel_id, kind, data) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(secret_id, channel_id, kind) DO UPDATE SET data = excluded.data",
            rusqlite::params![
                u64_to_sql(secret_id),
                u64_to_sql(channel_id.0),
                secret_kind_tag(kind),
                bytes,
            ],
        )
        .expect("secret save failed");
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, ()> {
        let conn = lock(&self.connection);
        conn.execute(
            "DELETE FROM secrets WHERE secret_id = ?1 AND channel_id = ?2 AND kind = ?3",
            rusqlite::params![
                u64_to_sql(secret_id),
                u64_to_sql(channel_id.0),
                secret_kind_tag(kind),
            ],
        )
        .expect("secret remove failed");
        Box::pin(std::future::ready(Ok(())))
    }
}
