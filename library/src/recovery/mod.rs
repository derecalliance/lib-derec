// SPDX-License-Identifier: Apache-2.0

//! # Recovery Flow
//!
//! This module implements the **secret recovery protocol** defined by DeRec.
//!
//! Recovery allows an Owner who has lost access to their secret to reconstruct
//! it using shares previously distributed to a set of Helpers.
//!
//! The recovery process consists of the following steps:
//!
//! 1. The Owner pairs with Helpers in **recovery mode**.
//! 2. The Owner requests the shares stored by each Helper.
//! 3. Each Helper responds with the share it holds for the given `(secret_id, version)`.
//! 4. Once a sufficient number of shares are collected, the Owner verifies them
//!    and reconstructs the secret.
//!
//! Secret reconstruction uses a **threshold secret sharing scheme**, meaning that
//! at least `t` valid shares must be collected before recovery can succeed.
//!
//! Incorrect or corrupted shares may be provided by malicious or faulty Helpers.
//! The recovery algorithm verifies each share before attempting reconstruction,
//! allowing the Owner to discard invalid shares and continue collecting others
//! until the threshold is reached.
//!
//! ## Module structure
//!
//! - `core` — implementation of the recovery protocol logic
//! - `error` — recovery-specific error types
//! - `wasm` — WebAssembly bindings for TypeScript consumers
//!
//! Most applications should use the high-level recovery functions provided by
//! this module rather than interacting with protobuf messages directly.

mod error;
pub use error::*;

mod core;
pub use core::*;

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[cfg(test)]
mod test;
