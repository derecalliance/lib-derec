// SPDX-License-Identifier: Apache-2.0

//! # Protobuf Bindings
//!
//! This module exposes the Rust types generated from the DeRec protocol
//! protobuf definitions.
//!
//! The types are generated at build time using `prost` from the protocol
//! `.proto` files and correspond directly to the message definitions used
//! by the DeRec protocol.
//!
//! These structures are used internally by the library to:
//!
//! - serialize protocol messages before transmission
//! - deserialize received messages
//! - provide a strongly-typed representation of protocol data
//!
//! The generated code mirrors the protobuf schema and therefore follows the
//! naming and structure defined in the protocol specification rather than
//! typical Rust conventions.
//!
//! ## Important
//!
//! The contents of this module are **generated code** and should not be edited
//! manually. Any changes must be performed in the protobuf definitions and the
//! bindings regenerated.
//!
//! Most users of the library should interact with the higher-level APIs
//! provided by the protocol flow modules (`pairing`, `sharing`, `verification`,
//! and `recovery`) rather than manipulating protobuf messages directly.

pub mod derec_proto {
    include!(concat!(
        env!("OUT_DIR"),
        "/org.derecalliance.derec.protobuf.rs"
    ));
}
