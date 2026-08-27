// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

mod codec;
mod db;
mod flows;
mod peer;
mod stateless;
mod stores;
mod transport;

// Multi-threaded on purpose: the suite doubles as a check that nothing in the
// library requires a single-threaded executor. A store future that was not
// `Send`, or protocol state that could not cross threads, would fail to
// compile here rather than in a user's axum service.
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    db::cleanup_stale_schemas().await;

    flows::run_all().await;

    println!("All Postgres smoke tests passed.");
}
