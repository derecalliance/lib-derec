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

pub mod derec_message;
pub mod primitives;
pub mod protocol;
pub mod protocol_version;
pub mod types;
mod utils;

mod error;
pub use error::Error;

#[cfg(not(target_arch = "wasm32"))]
mod ffi;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub type Result<T> = std::result::Result<T, Error>;

// --- Higher-Level API Design (proposed, v2) ---
//
// The current API is stateless and message-oriented: callers must route every
// incoming byte slice to the right function, store intermediate key material,
// and track which flow is active.  The design below lifts that coordination
// into the library itself.  The application only needs to implement two traits
// that represent the two external concerns the library can never own: storage
// and transport.
//
// Design requirements addressed in this revision:
//   - DeRecStore and DeRecProtocol are fully async (stable async-fn-in-trait,
//     Rust 1.75+, no #[async_trait] macro required).
//   - All trait methods return Result<_>: infallible-looking operations like
//     remove_pairing_secret can still fail on I/O or serialization errors.
//   - FFI and WASM export strategy is documented at the bottom.
//
// ──────────────────────────────────────────────────────────────────────────────
// TRAITS
// ──────────────────────────────────────────────────────────────────────────────
//
// /// Persistent storage backend.
// ///
// /// All methods are async so implementations may perform I/O (disk, network,
// /// secure enclave) without blocking the executor.  The library calls these
// /// whenever it needs to read or write protocol state.
// trait DeRecStore {
//     // Shared (post-pairing) channel keys, keyed by channel_id.
//     async fn load_shared_key(&self, channel_id: u64) -> Result<Option<SharedKey>>;
//     async fn save_shared_key(&mut self, channel_id: u64, key: SharedKey) -> Result<()>;
//
//     // Ephemeral pairing key material — only alive between request and response.
//     async fn load_pairing_secret(&self, channel_id: u64) -> Result<Option<PairingSecretKeyMaterial>>;
//     async fn save_pairing_secret(&mut self, channel_id: u64, secret: PairingSecretKeyMaterial) -> Result<()>;
//     async fn remove_pairing_secret(&mut self, channel_id: u64) -> Result<()>;
//
//     // Secret shares (Helper side).
//     async fn load_share(&self, channel_id: u64, version: i32) -> Result<Option<Vec<u8>>>;
//     async fn save_share(&mut self, channel_id: u64, version: i32, share: Vec<u8>) -> Result<()>;
//
//     // Channel registry — used by process() to enumerate known peers.
//     async fn load_channel_ids(&self) -> Result<Vec<u64>>;
// }
//
// /// Outbound transport.
// ///
// /// Async so the implementation may perform real network I/O.  The `endpoint`
// /// mirrors the `TransportProtocol` from the protobuf and tells the
// /// implementation where and how to deliver the bytes.
// trait DeRecTransport {
//     async fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> Result<()>;
// }
//
// ──────────────────────────────────────────────────────────────────────────────
// EVENTS
// ──────────────────────────────────────────────────────────────────────────────
//
// `process` returns zero or more events so the application reacts to outcomes
// rather than routing messages manually.
//
// enum DeRecEvent {
//     /// Pairing completed on both sides — shared key is now persisted.
//     PairingComplete { channel_id: u64 },
//
//     /// A share was accepted and persisted (Helper side).
//     ShareStored { channel_id: u64, version: i32 },
//
//     /// A verification challenge was answered correctly.
//     ShareVerified { channel_id: u64, version: i32 },
//
//     /// Recovery completed — secret is returned exactly once, then forgotten.
//     SecretRecovered { secret: Vec<u8> },
//
//     /// Well-formed message with no actionable effect (e.g. an ACK).
//     NoOp,
// }
//
// ──────────────────────────────────────────────────────────────────────────────
// PROTOCOL ORCHESTRATOR
// ──────────────────────────────────────────────────────────────────────────────
//
// struct DeRecProtocol<S: DeRecStore, T: DeRecTransport> {
//     store: S,
//     transport: T,
//     own_transport: TransportProtocol, // endpoint advertised to peers
// }
//
// impl<S: DeRecStore, T: DeRecTransport> DeRecProtocol<S, T> {
//
//     // ── Owner-initiated actions ────────────────────────────────────────────
//
//     /// Generate an out-of-band contact message (QR code payload, deep link …).
//     /// Persists the ephemeral pairing secret automatically via store.
//     async fn create_contact(&mut self, channel_id: u64) -> Result<ContactMessage>;
//
//     /// Begin pairing as the responder (scanned a peer's contact).
//     /// Sends the pairing request via transport and returns immediately.
//     /// The pairing response arrives later and completes via process().
//     async fn initiate_pairing(
//         &mut self,
//         kind: SenderKind,
//         contact: ContactMessage,
//     ) -> Result<()>;
//
//     /// Split `secret` and send one share to each paired Helper.
//     async fn protect_secret(&mut self, secret: Vec<u8>, threshold: usize) -> Result<()>;
//
//     /// Send a verification challenge to every known Helper.
//     async fn verify_shares(&mut self) -> Result<()>;
//
//     /// Pair in recovery mode with each Helper, then request shares.
//     /// DeRecEvent::SecretRecovered is emitted once threshold shares arrive.
//     async fn start_recovery(&mut self, helpers: Vec<ContactMessage>) -> Result<()>;
//
//     // ── Single inbound entry point ─────────────────────────────────────────
//
//     /// Feed any incoming wire bytes here regardless of which flow they belong to.
//     ///
//     /// The library decodes the envelope, routes to the correct handler, drives
//     /// the state machine, persists state via store, sends replies via transport,
//     /// and returns the events the application should react to.
//     async fn process(&mut self, message: &[u8]) -> Result<Vec<DeRecEvent>>;
// }
//
// ──────────────────────────────────────────────────────────────────────────────
// USAGE EXAMPLE (Rust / native)
// ──────────────────────────────────────────────────────────────────────────────
//
// // 1. Provide storage and transport implementations.
// let store     = SqliteStore::open("derec.db").await?;
// let transport = HttpTransport::new();
// let own_tp    = TransportProtocol::http("https://myapp.example/derec");
//
// // 2. Build the orchestrator.
// let mut protocol = DeRecProtocol { store, transport, own_transport: own_tp };
//
// // 3a. Owner side — share a secret.
// let contact = protocol.create_contact(CHANNEL_ID).await?;
// display_as_qr_code(&contact); // out-of-band delivery to the Helper
// // … Helper scans QR → sends a pairing request …
// let raw = receive_from_network().await;
// let events = protocol.process(&raw).await?;
// // → [DeRecEvent::PairingComplete { channel_id: CHANNEL_ID }]
// protocol.protect_secret(my_secret, threshold: 3).await?;
//
// // 3b. Helper side — same entry point handles all inbound messages.
// loop {
//     let raw = receive_from_network().await;
//     for event in protocol.process(&raw).await? {
//         match event {
//             DeRecEvent::ShareStored { channel_id, version } =>
//                 log::info!("stored share v{version} for channel {channel_id}"),
//             DeRecEvent::ShareVerified { .. } =>
//                 log::info!("verification passed"),
//             _ => {}
//         }
//     }
// }
//
// // 3c. Recovery — Owner re-pairs, then awaits enough share responses.
// protocol.start_recovery(known_helpers).await?;
// loop {
//     let raw = receive_from_network().await;
//     for event in protocol.process(&raw).await? {
//         if let DeRecEvent::SecretRecovered { secret } = event {
//             restore_from_secret(secret);
//             return Ok(());
//         }
//     }
// }
//
// ──────────────────────────────────────────────────────────────────────────────
// FFI / WASM EXPORT STRATEGY
// ──────────────────────────────────────────────────────────────────────────────
//
// WASM (NodeJS / Web):
//   Rust async maps 1-to-1 to JS Promises via wasm-bindgen-futures.
//   The WASM bindings expose async #[wasm_bindgen] functions that JS/TS awaits
//   normally.  DeRecStore and DeRecTransport implementations live on the JS side
//   and are passed into the WASM module as JS objects; wasm-bindgen bridges each
//   async trait method to a js_sys::Promise call.
//
// FFI (.Net):
//   async does not cross the C FFI boundary.  Strategy:
//
//   - The FFI shim spins up a Tokio single-threaded runtime once and exposes
//     synchronous #[no_mangle] extern "C" functions that call
//     runtime.block_on(protocol.process(bytes)) internally.
//
//   - DeRecStore and DeRecTransport are implemented on the Rust side using C
//     function-pointer callbacks supplied by the host at construction time
//     (.Net passes them via P/Invoke).  Each async trait method calls its
//     callback synchronously (the callback is always C# code, so it can block)
//     and wraps the result in an immediately-ready future.
//
//     Sketch of the FFI store adapter:
//
//     type LoadSharedKeyFn = extern "C" fn(channel_id: u64, out: *mut [u8; 32]) -> i32;
//     type SaveSharedKeyFn = extern "C" fn(channel_id: u64, key: *const [u8; 32]) -> i32;
//     // … one callback per DeRecStore method …
//
//     struct FfiStore {
//         load_shared_key: LoadSharedKeyFn,
//         save_shared_key: SaveSharedKeyFn,
//         // …
//     }
//
//     impl DeRecStore for FfiStore {
//         async fn load_shared_key(&self, channel_id: u64) -> Result<Option<SharedKey>> {
//             let mut buf = [0u8; 32];
//             match (self.load_shared_key)(channel_id, &mut buf) {
//                 0 => Ok(Some(buf)),  // found
//                 1 => Ok(None),       // not found
//                 _ => Err(Error::Store("load_shared_key callback failed")),
//             }
//         }
//         // … mirror pattern for every other method …
//     }
//
//   The C# wrapper (DeRec.Library) constructs the callback struct, pins the
//   delegates to prevent GC relocation, and hands the raw function pointers to
//   Rust.  From the C# consumer's perspective the API is fully synchronous and
//   looks no different from the existing FFI layer.
