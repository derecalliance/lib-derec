// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The recoverable [`Secret`] and its versioned encoding.
//!
//! `model` holds the `Secret` data model; `codec` + `versions` implement the
//! **normative recoverable format** — the bytes placed in
//! `DeRecSecret.secret_data`, which are encrypted and VSS-split to helpers and
//! reconstructed from a threshold of shares on recovery. Because a secret
//! protected by one application must be recoverable by another, the format is
//! self-describing and implementation-independent.
//!
//! # Wire format
//!
//! ```text
//! secret_data = [ major: u8 ] · payload
//! ```
//!
//! The leading byte is the encoding **major version**; it is read *before*
//! decompression, so a future version may change the compression as well as the
//! JSON schema. The version for that byte selects the handler that owns both.
//! Only breaking changes bump the major (currently `1`); backward-compatible
//! additions are absorbed within a major by the decoder's field tolerance. A
//! new major is minted only as part of a breaking DeRec protocol change that
//! alters the secret, so it moves in lockstep with the protocol majors that
//! touch the secret — but it is deliberately **not** the protocol version
//! itself: the protocol version advances for reasons unrelated to the secret,
//! and stamping stored secrets with it would make older implementations reject
//! secrets whose encoding they actually support. The
//! version is a property of the encoding, not of the [`Secret`] data model, and
//! never appears in the protobuf form used for the internal replica-sync message
//! ([`ReplicaSecretPayload`](crate::protocol::types::ReplicaSecretPayload)).
//!
//! # v1 payload
//!
//! `payload = gzip(json(secret))` (RFC 1952). Byte fields are standard-padded
//! base64 (RFC 4648 §4), `u64` fields are decimal strings, keys are snake_case,
//! and absent/empty optional keys are omitted (a decoder accepts absent, `null`,
//! or empty as "not present"). Schema:
//!
//! ```text
//! Secret      { owner_replica_id:str<u64>, helpers:[Helper], secrets:[UserSecret],
//!               replicas?:Replicas }
//! Helper      { channel_id:str<u64>, transport_uri:str, shared_key:base64,
//!               communication_info?:{str:str} }
//! UserSecret  { id:base64, name:str, data:base64 }
//! Replicas    { shared_key:base64, replicas:[ReplicaInfo] }
//! ReplicaInfo { channel_id:str<u64>, transport_uri:str, replica_id:str<u64>,
//!               sender_kind:int, communication_info?:{str:str} }
//! ```
//!
//! # Conformance
//!
//! Golden vectors (a canonical [`Secret`] paired with its exact v1 JSON) live
//! under `library/tests/golden/`. gzip *decoding* is universal but *encoding*
//! is not byte-stable, so conformance is defined on the JSON (pre-gzip).

mod codec;
mod model;
mod versions;

pub use codec::SecretError;
pub use model::{HelperInfo, ReplicaInfo, Replicas, Secret, UserSecret};

impl Secret {
    /// Encode this secret to its recoverable bytes (`[major] · payload`; see
    /// the module documentation for the format).
    ///
    /// Note: this is **not** the `prost::Message` encoding (`encode_to_vec`),
    /// which yields the protobuf form used only for the internal replica-sync
    /// message. `Secret::encode` is the recoverable, cross-application format.
    pub fn encode(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decode a secret from its recoverable bytes (see the module documentation).
    ///
    /// Note: this shadows `prost::Message::decode`; it decodes the recoverable
    /// versioned encoding, not the protobuf form.
    pub fn decode(bytes: &[u8]) -> Result<Self, SecretError> {
        codec::decode(bytes)
    }
}
