// SPDX-License-Identifier: Apache-2.0

//! # Sharing Flow
//!
//! This module implements the **sharing protocol** defined by DeRec.
//!
//! Sharing is the process by which an Owner protects secret data by generating a
//! set of **shares** and distributing one share to each Helper. A threshold number
//! of Helpers (`t`) is required to reconstruct the secret during recovery.
//!
//! ## What is shared
//!
//! DeRec supports secrets of arbitrary length by using **hybrid encryption**:
//!
//! - The secret data is encrypted into a ciphertext (e.g. using an AEAD such as AES-GCM).
//! - The symmetric encryption key is then split into `n` shares using a
//!   **threshold secret sharing** scheme (e.g. Shamir), so that any `t` shares are
//!   sufficient to reconstruct the key.
//!
//! Each Helper receives (at minimum) the information needed to contribute to
//! recovery, including their share and the authentication data required to validate it.
//!
//! ## Verifiability
//!
//! Helpers may be faulty or malicious and could return corrupted shares during recovery.
//! To enable **verifiable recovery**, each share includes authentication data that allows
//! a recovering Owner to validate that the share is consistent with the committed set of
//! shares for that version.
//!
//! Implementations typically use a **vector commitment** construction (for example, a
//! Merkle-tree commitment) where:
//!
//! - The commitment (root) is replicated with shares
//! - Each share includes an opening proof (e.g. Merkle path)
//! - Recovery verifies openings against the commitment before reconstruction
//!
//! ## Versioning
//!
//! Shares are **versioned**. A new version is generated and distributed when:
//!
//! - the secret value changes, or
//! - the helper set changes (add/remove helpers), or
//! - protocol parameters affecting recovery change (e.g. threshold).
//!
//! Applications can use share versions to manage updates, detect stale state on Helpers,
//! and coordinate clean-up of older share versions.
//!
//! ## Module structure
//!
//! - `core` — implementation of share generation and update logic
//! - `types` — data structures used by the sharing flow (share contents, metadata, etc.)
//! - `error` — sharing-specific error types
//! - `wasm` — WebAssembly bindings for TypeScript consumers
//!
//! Most applications should interact with the high-level APIs exposed by this module
//! rather than constructing protobuf messages directly.

mod error;
pub use error::*;

mod core;
pub use core::*;

mod types;
pub use types::*;

#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(test)]
mod test;
