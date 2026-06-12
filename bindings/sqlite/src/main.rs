//! SQLite-backed smoke test for the DeRec store traits.
//!
//! Mirrors a subset of the Rust binding's protocol flows but swaps
//! every store implementation for one that persists to an in-memory
//! SQLite database. The asserts here are deliberately stricter than
//! the parity-tests in the other bindings — the goal is to prove the
//! store traits compose cleanly with a real persistent backend, not
//! just to drive the protocol to a successful end-state.

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
