//! `DeRecUserSecretStore` over Postgres — keeps at most one
//! `UserSecrets` snapshot per `secret_id`, with `version`,
//! `description`, and the prost-encoded `Vec<UserSecret>` payload
//! stored as separate columns.

use derec_library::protocol::DeRecUserSecretStore;
use derec_library::protocol::ShareStoreFuture;
use derec_library::protocol::types::UserSecrets;

use crate::codec::{assemble_user_secrets, encode_user_secrets_payload};
use crate::db::{SharedClient, u64_to_sql};

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
                    "SELECT version, description, payload FROM user_secrets WHERE secret_id = $1",
                    &[&secret_id],
                )
                .await
                .expect("user_secrets load_latest failed");
            Ok(row.map(|r| {
                let version = r.get::<_, i64>(0) as u32;
                let description: Option<String> = r.get(1);
                let payload: Vec<u8> = r.get(2);
                assemble_user_secrets(version, description, payload)
            }))
        })
    }

    fn save_latest(
        &mut self,
        secret_id: u64,
        value: UserSecrets,
    ) -> ShareStoreFuture<'_, ()> {
        let client = self.client.clone();
        let secret_id = u64_to_sql(secret_id);
        let version_i64 = value.version as i64;
        let description = value.description.clone();
        let payload = encode_user_secrets_payload(&value.secrets);
        Box::pin(async move {
            client
                .execute(
                    "INSERT INTO user_secrets (secret_id, version, description, payload)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (secret_id) DO UPDATE SET
                         version     = EXCLUDED.version,
                         description = EXCLUDED.description,
                         payload     = EXCLUDED.payload",
                    &[&secret_id, &version_i64, &description, &payload],
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
