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
//! - [`pairing`] — establishes a secure communication channel between an Owner
//!   and a Helper
//! - [`sharing`] — generates and distributes secret shares to Helpers
//! - [`verification`] — periodically checks that Helpers are still storing
//!   the correct share
//! - [`recovery`] — reconstructs the secret using shares retrieved from Helpers
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
//! through the [`protos`] module. Most applications should interact with the
//! higher-level APIs instead of manipulating protobuf messages directly.
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

pub mod pairing;
pub mod recovery;
pub mod sharing;
pub mod types;
mod utils;
pub mod verification;

mod error;
pub use error::Error;

#[cfg(target_arch = "wasm32")]
pub(crate) mod ts_bindings_utils;

pub type Result<T> = std::result::Result<T, Error>;
