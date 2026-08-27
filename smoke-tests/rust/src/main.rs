// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

mod primitives;
mod protocol;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("── Primitives smoke tests ──────────────────────────────────");
    primitives::run_all();

    println!();
    println!("── Protocol smoke tests ────────────────────────────────────");
    protocol::run_all().await;

    println!();
    println!("All smoke tests passed.");
}
