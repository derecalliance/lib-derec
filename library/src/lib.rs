// SPDX-License-Identifier: Apache-2.0

//! # DeRec Library
//!
//! This crate provides an implementation of the **DeRec protocol**, a decentralized
//! secret recovery mechanism that protects sensitive data by distributing shares
//! of the secret among a set of Helpers.
//!
//! Instead of relying on a single backup location, DeRec uses **threshold secret
//! sharing** so that a secret can be reconstructed only when a sufficient number
//! of Helpers collaborate.
//!
//! ## Protocol flows
//!
//! The library implements the core protocol flows defined by DeRec:
//!
//! - [`primitives::pairing`] — establishes a secure communication channel
//!   between an Owner and a Helper
//! - [`primitives::sharing`] — generates and distributes secret shares to
//!   Helpers
//! - [`primitives::verification`] — periodically checks that Helpers are
//!   still storing the correct share
//! - [`primitives::recovery`] — reconstructs the secret using shares
//!   retrieved from Helpers
//!
//! These flows correspond to the lifecycle of a protected secret:
//!
//! ```text
//! Pairing → Sharing → Verification (periodic) → Recovery (if needed)
//! ```
//!
//! ## Design
//!
//! The library provides a **high-level API** for implementing DeRec-compatible
//! applications. Each flow is implemented as a separate module exposing the
//! functions required to produce and process protocol messages.
//!
//! Protocol messages themselves are defined using **protobuf** and are exposed
//! through the [`derec_proto`] crate. Most applications should interact with
//! the higher-level APIs instead of manipulating protobuf messages directly.
//!
//! ## Error handling
//!
//! All public APIs return [`Result<T>`], which wraps the crate-wide [`Error`] type.
//! This type aggregates errors originating from the individual protocol flows
//! while preserving their specific error semantics.
//!
//! ## Target environments
//!
//! The library is designed to work in both:
//!
//! - native Rust environments
//! - WebAssembly environments (via bindings exposed by individual modules)
//!
//! WebAssembly bindings are primarily intended for integration with TypeScript
//! applications.

pub mod derec_message;
pub mod primitives;
pub mod protocol;
pub mod protocol_version;
pub mod transport;
pub mod types;
mod utils;

mod error;
pub use error::Error;

/// Generate a fresh **replica identity** using the OS CSPRNG.
///
/// Replica identities are per-device `u64` values that uniquely identify each
/// participant in a replica group. The orchestrator auto-injects this id
/// under the reserved `derec.replica_id` key in `CommunicationInfo` during
/// replica-mode pairings (see
/// [`protocol::DeRecProtocolBuilder::with_replica_id`]).
///
/// Persistence contract: the caller **must** persist the returned value once
/// per device and pass the same id on every subsequent
/// [`protocol::DeRecProtocolBuilder::with_replica_id`] call. A replica that
/// changes its id between restarts cannot be re-identified by peers and will
/// fail re-pairing / secret sync.
///
/// Apps that do not use replica flows do not need to call this.
pub fn generate_replica_id() -> u64 {
    rand::random()
}

#[cfg(not(target_arch = "wasm32"))]
mod ffi;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub type Result<T> = std::result::Result<T, Error>;
