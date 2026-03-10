// SPDX-License-Identifier: Apache-2.0

//! # Verification Flow
//!
//! This module implements the **share verification protocol** defined by DeRec.
//!
//! Verification is an optional but strongly recommended maintenance mechanism that
//! allows an Owner to periodically confirm that a Helper is still retaining the
//! correct share for a given `(secret_id, version)`.
//!
//! ## Purpose
//!
//! In practice, Helpers may lose state (device loss, storage corruption, app bugs),
//! or may refuse to cooperate during recovery. Verification reduces the likelihood
//! of discovering these failures only at recovery time.
//!
//! ## Protocol overview
//!
//! Verification is a challenge-response interaction initiated by the Owner:
//!
//! 1. The Owner sends a random challenge nonce to the Helper.
//! 2. The Helper computes a response derived from the stored share contents and
//!    the challenge nonce.
//! 3. The Owner verifies the response. If it matches the expected value, the Helper
//!    is considered to be holding the correct share.
//!
//! If verification fails, the Owner may respond by re-sending the correct share,
//! retrying verification, and/or taking application-defined remediation actions
//! (e.g., marking the Helper inactive, warning the user, or initiating re-sharing).
//!
//! ## Relationship to recovery
//!
//! Verification does not reconstruct the secret. It is a proactive health check to
//! improve the probability that enough Helpers will provide valid shares when the
//! Owner later enters recovery mode.
//!
//! ## Module structure
//!
//! - `core` — implementation of the verification logic (challenge construction and validation)
//! - `error` — verification-specific error types
//! - `wasm` — WebAssembly bindings for TypeScript consumers
//!
//! Most applications should interact with the high-level APIs exposed by this module
//! rather than constructing protobuf messages directly.

mod error;
pub use error::*;

mod core;
pub use core::*;

#[cfg(test)]
mod test;
