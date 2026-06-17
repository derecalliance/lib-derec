// SPDX-License-Identifier: Apache-2.0

//! # DeRec Cryptography
//!
//! Cryptographic primitives for the DeRec protocol: pairing key exchange,
//! symmetric channel encryption, and verifiable secret sharing.
//!
//! ## Feature flags
//!
//! ### `logging` (off by default)
//!
//! Enables structured [`tracing`] instrumentation on the [`pairing`] protocol
//! functions. When active, the crate emits spans and events at three levels:
//!
//! | Level   | What is logged |
//! |---------|----------------|
//! | `info`  | Protocol flow milestones — contact generated, pairing request created, shared key derived |
//! | `debug` | Intermediate state — role, public key sizes, ciphertext sizes |
//! | `trace` | Low-level byte lengths of ML-KEM / ECIES material and XOR combiner inputs |
//!
//! **Security guarantee**: secret key bytes are never emitted. Only lengths,
//! roles, and success/failure outcomes appear in events.
//!
//! ### Activating instrumentation
//!
//! Add the feature to your dependency and wire up a subscriber in your
//! application:
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! derec-cryptography = { version = "*", features = ["logging"] }
//! tracing-subscriber = { version = "0.3", features = ["env-filter"] }
//! ```
//!
//! ```rust,ignore
//! // main.rs / lib.rs — set DEREC_LOG=debug before running
//! tracing_subscriber::fmt()
//!     .with_env_filter(
//!         tracing_subscriber::EnvFilter::from_env("DEREC_LOG")
//!     )
//!     .init();
//! ```
//!
//! The library itself never installs a subscriber and never reads `DEREC_LOG`
//! directly — that is always the consumer's responsibility.

pub mod channel;
pub mod pairing;
pub mod replica;
pub mod vss;
