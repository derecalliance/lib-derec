// SPDX-License-Identifier: Apache-2.0

//! # Pairing Flow
//!
//! This module implements the **pairing protocol** defined by DeRec.
//!
//! Pairing establishes a secure communication channel between an **Owner**
//! and a **Helper** before any secret shares can be exchanged.
//!
//! During pairing the two parties:
//!
//! 1. Exchange public encryption and signature keys
//! 2. Verify the pairing nonce from the contact message
//! 3. Derive a shared key used for subsequent encrypted communication
//!
//! The pairing protocol consists of a request/response exchange:
//!
//! ```text
//! Initiator → PairRequestMessage
//! Responder → PairResponseMessage
//! ```
//!
//! Once the exchange completes successfully, both parties obtain a
//! [`PairingSharedKey`] which is used to encrypt and authenticate all
//! subsequent protocol messages.
//!
//! ## Module structure
//!
//! - `core` — implementation of the pairing protocol logic
//! - `types` — data structures used by the pairing flow
//! - `error` — pairing-specific error types
//! - `wasm` — WebAssembly bindings for TypeScript consumers
//!
//! Most applications should interact with the high-level functions exposed
//! by this module rather than manipulating protobuf messages directly.

mod error;
pub use error::*;

mod core;
pub use core::*;

mod types;
pub use types::*;

#[cfg(target_arch = "wasm32")]
mod wasm;
#[cfg(target_arch = "wasm32")]
pub use wasm::*;

#[cfg(test)]
mod test;
