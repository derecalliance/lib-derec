// SPDX-License-Identifier: Apache-2.0

//! C FFI for the stateful `DeRecProtocol` orchestrator.
//!
//! Architecture mirrors the WASM `DeRecProtocolWasm`: a foreign caller
//! supplies managed implementations of the four storage/transport traits
//! and gets back an opaque handle representing one protocol instance.
//! Each FFI entry point uses a single-threaded tokio runtime owned by
//! the handle to `block_on` the async core protocol — so all FFI calls
//! are synchronous from the caller's perspective.
//!
//! ## Memory & ownership
//!
//! - Bytes returned to the caller via `DeRecBuffer` are freed with
//!   [`crate::ffi::derec_free_buffer`].
//! - Bytes passed in by the caller (e.g. callback return buffers) are
//!   owned by the caller and freed via [`DeRecCallbacks::free_buffer`].
//! - The handle itself is freed with [`derec_protocol_free`].
//!
//! ## Threading
//!
//! The handle holds a `&mut DeRecProtocol`, so the foreign caller MUST
//! NOT invoke multiple FFI entry points on the same handle concurrently.
//! Documented on the dotnet side; not enforced here.

pub mod events;
pub mod flow;
pub mod handle;
pub mod stores;
