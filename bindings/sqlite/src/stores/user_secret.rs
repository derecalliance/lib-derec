//! `DeRecUserSecretStore` over SQLite — keeps at most one
//! `UserSecrets` snapshot per `secret_id`, with `version`,
//! `description`, and the prost-encoded `Vec<UserSecret>` payload
//! stored as separate columns.

use derec_library::protocol::DeRecUserSecretStore;
use derec_library::protocol::ShareStoreFuture;
use derec_library::protocol::types::UserSecrets;

use crate::codec::{
    assemble_user_secrets, encode_user_secrets_payload, u64_to_sql,
};
use crate::db::{SharedConnection, lock};

pub struct SqliteUserSecretStore {
    connection: SharedConnection,
}

impl SqliteUserSecretStore {
    pub fn new(connection: SharedConnection) -> Self {
        Self { connection }
    }
}

impl DeRecUserSecretStore for SqliteUserSecretStore {
    fn load_latest(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        let conn = lock(&self.connection);
        let row = conn
            .query_row(
                "SELECT version, description, payload FROM user_secrets WHERE secret_id = ?1",
                rusqlite::params![u64_to_sql(secret_id)],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u32,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .ok();
        let value = row.map(|(v, d, p)| assemble_user_secrets(v, d, p));
        Box::pin(std::future::ready(Ok(value)))
    }

    fn save_latest(
        &mut self,
        secret_id: u64,
        value: UserSecrets,
    ) -> ShareStoreFuture<'_, ()> {
        let conn = lock(&self.connection);
        let payload = encode_user_secrets_payload(&value.secrets);
        conn.execute(
            "INSERT INTO user_secrets (secret_id, version, description, payload)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(secret_id) DO UPDATE SET
                 version     = excluded.version,
                 description = excluded.description,
                 payload     = excluded.payload",
            rusqlite::params![
                u64_to_sql(secret_id),
                value.version as i64,
                value.description,
                payload,
            ],
        )
        .expect("user_secret save_latest failed");
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(&mut self, secret_id: u64) -> ShareStoreFuture<'_, ()> {
        let conn = lock(&self.connection);
        conn.execute(
            "DELETE FROM user_secrets WHERE secret_id = ?1",
            rusqlite::params![u64_to_sql(secret_id)],
        )
        .expect("user_secret remove failed");
        Box::pin(std::future::ready(Ok(())))
    }
}
