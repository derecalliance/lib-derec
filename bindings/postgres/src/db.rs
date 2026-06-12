//! Postgres database wrapper + per-Database schema isolation.
//!
//! Postgres has no in-memory mode (the docker-compose file mounts
//! `/var/lib/postgresql/data` as a tmpfs to approximate that), so
//! isolation between simulated "devices" is done by giving each
//! `Database::open_isolated()` call its own randomly-named schema.
//! `search_path` is pinned to that schema for the connection, so
//! every store query reads/writes only the per-device tables.

use std::sync::Arc;
use tokio_postgres::{Client, NoTls};

/// Migrations bundled into the binary at compile time. Adding a
/// migration is two lines: drop a new `.sql` file under `migrations/`
/// and append an entry here with a strictly increasing `version`.
const MIGRATIONS: &[(i64, &str, &str)] = &[(
    1,
    "0001_init",
    include_str!("../migrations/0001_init.sql"),
)];

/// Connection string default; override via `DATABASE_URL`.
const DEFAULT_DATABASE_URL: &str =
    "postgres://postgres:postgres@localhost:15432/derec_test";

/// Schema-name prefix. The startup-side cleanup walks
/// `information_schema.schemata` for everything matching this prefix
/// and drops it, so stale schemas from previous runs do not pile up.
const SCHEMA_PREFIX: &str = "peer_";

/// Shared async client. `Arc` so all four store impls can hold a
/// clone and share the same connection (and therefore the same
/// `search_path`, i.e. the same isolated schema).
pub type SharedClient = Arc<Client>;

pub struct Database {
    client: SharedClient,
    #[allow(dead_code)]
    schema: String,
}

impl Database {
    /// Open a fresh isolated database: connect to Postgres, create a
    /// new schema, pin `search_path` to it for this connection, and
    /// apply every pending migration against it.
    pub async fn open_isolated() -> Self {
        let url =
            std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_owned());
        let (client, connection) = tokio_postgres::connect(&url, NoTls)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "failed to connect to Postgres at {url}: {e}\n\
                     Did you run `docker compose up -d` in bindings/postgres?"
                )
            });
        // The connection actor drives the wire protocol — spawn it
        // onto the current Tokio runtime and forget the handle.
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("postgres connection error: {e}");
            }
        });

        let schema = format!("{SCHEMA_PREFIX}{}", uuid::Uuid::new_v4().simple());
        client
            .batch_execute(&format!(r#"CREATE SCHEMA "{schema}""#))
            .await
            .unwrap_or_else(|e| panic!("CREATE SCHEMA \"{schema}\" failed: {e}"));
        client
            .batch_execute(&format!(r#"SET search_path TO "{schema}""#))
            .await
            .unwrap_or_else(|e| panic!("SET search_path failed: {e}"));

        apply_migrations(&client).await;

        Self {
            client: Arc::new(client),
            schema,
        }
    }

    pub fn client(&self) -> SharedClient {
        self.client.clone()
    }
}

async fn apply_migrations(client: &Client) {
    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS __migrations (
                version    BIGINT PRIMARY KEY,
                name       TEXT   NOT NULL,
                applied_at BIGINT NOT NULL
            );",
        )
        .await
        .expect("failed to create __migrations table");

    let mut last_version: i64 = client
        .query_one("SELECT COALESCE(MAX(version), 0) FROM __migrations", &[])
        .await
        .expect("failed to query __migrations")
        .get(0);

    for (version, name, sql) in MIGRATIONS {
        if *version <= last_version {
            continue;
        }
        if *version != last_version + 1 {
            panic!(
                "migration {name}: expected version {} but got {}",
                last_version + 1,
                version
            );
        }
        client
            .batch_execute(sql)
            .await
            .unwrap_or_else(|e| panic!("failed to apply migration {name}: {e}"));
        client
            .execute(
                "INSERT INTO __migrations (version, name, applied_at) VALUES ($1, $2, EXTRACT(EPOCH FROM NOW())::BIGINT)",
                &[version, name],
            )
            .await
            .unwrap_or_else(|e| panic!("failed to record migration {name}: {e}"));
        last_version = *version;
    }
}

/// Drop every `peer_*` schema left over from previous runs. Called
/// once at the start of `main()` so accumulated schemas from earlier
/// invocations don't bloat the database. Errors are surfaced as
/// panics — this is a smoke-test harness, not production code.
pub async fn cleanup_stale_schemas() {
    let url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_owned());
    let (client, connection) = tokio_postgres::connect(&url, NoTls)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "cleanup: failed to connect to Postgres at {url}: {e}\n\
                 Did you run `docker compose up -d` in bindings/postgres?"
            )
        });
    let handle = tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("cleanup postgres connection error: {e}");
        }
    });

    let rows = client
        .query(
            "SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE $1",
            &[&format!("{SCHEMA_PREFIX}%")],
        )
        .await
        .expect("listing schemas failed");
    let count = rows.len();
    for row in rows {
        let name: String = row.get(0);
        client
            .batch_execute(&format!(r#"DROP SCHEMA "{name}" CASCADE"#))
            .await
            .unwrap_or_else(|e| panic!("dropping schema {name} failed: {e}"));
    }
    if count > 0 {
        println!("[postgres] dropped {count} stale schema(s) from previous runs");
    }

    drop(client);
    handle.abort();
}

/// `u64` ↔ `i64` round-trip. Postgres `BIGINT` is signed 64-bit;
/// the cast preserves the bit pattern in both directions so values
/// with the high bit set come back identical.
pub fn u64_to_sql(value: u64) -> i64 {
    value as i64
}

pub fn sql_to_u64(value: i64) -> u64 {
    value as u64
}
