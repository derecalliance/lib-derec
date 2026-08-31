// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

mod codec;
mod db;
mod flows;
mod peer;
mod stores;
mod transport;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    flows::run_all().await;

    println!("All SQLite smoke tests passed.");
}
