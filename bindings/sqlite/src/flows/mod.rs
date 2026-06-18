pub mod assertions;
pub mod helpers;

pub mod discovery_recovery;
pub mod multi_tenancy;
pub mod multi_secret;
pub mod pairing;
pub mod persistence;
pub mod replica_sync;
pub mod sharing;
pub mod unpairing;

pub async fn run_all() {
    pairing::run().await;
    sharing::run().await;
    discovery_recovery::run().await;
    unpairing::run().await;
    persistence::run().await;
    multi_tenancy::run().await;
    multi_secret::run().await;
    replica_sync::run().await;
}
