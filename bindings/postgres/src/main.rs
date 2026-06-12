//! Postgres-backed smoke test for the DeRec store traits.
//!
//! Same flow set as the SQLite binding but persists every store
//! method through tokio-postgres against an isolated schema per
//! "device" (peer). Requires a Postgres container running locally —
//! `docker compose up -d` from this directory will spin one up on
//! the expected port (15432).

mod codec;
mod db;
mod flows;
mod peer;
mod stores;
mod transport;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    db::cleanup_stale_schemas().await;

    flows::run_all().await;

    println!("All Postgres smoke tests passed.");
}
