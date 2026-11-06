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
//! Only breaking changes bump the major (currently `3`); backward-compatible
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
//! Encodes always write the latest major; the decoder accepts majors `3` and
//! `2` and rejects every other value.
//!
//! # v3 payload
//!
//! `payload = gzip(json(secret))` (RFC 1952). Byte fields are standard-padded
//! base64 (RFC 4648 §4), `u64` fields are decimal strings, keys are snake_case,
//! and absent/empty optional keys are omitted (a decoder accepts absent, `null`,
//! or empty as "not present"). Schema:
//!
//! ```text
//! Secret      { helpers:[Helper], secrets:[UserSecret], replicas?:Replicas,
//!               threshold?:int }
//! Helper      { channel_id:str<u64>, transports:[Endpoint], shared_key:base64,
//!               communication_info?:{str:str}, weight?:int }
//! UserSecret  { id:base64, name:str, data:base64 }
//! Replicas    { members:[ReplicaInfo], shared_key:base64,
//!               channel_id:str<u64> }
//! ReplicaInfo { replica_id:str<u64>, transports:[Endpoint],
//!               role:"Source"|"Destination",
//!               communication_info?:{str:str} }
//! Endpoint    { uri:str, protocol:int }
//! ```
//!
//! `transports` lists every endpoint the peer advertised, in its preference
//! order; `protocol` is the `TransportProtocol` discriminant.
//!
//! `weight` is the number of Shamir subshares the Helper received in the round
//! that wrote the roster. It is omitted when `1`, an absent key decodes as `1`,
//! and a `0` makes the payload malformed. The field was added within v3: a
//! decoder that predates it ignores the key, and every roster written before
//! it decodes with every Helper at `1`.
//!
//! `threshold` is the `t` the roster's version was split with. It is omitted
//! when absent, an absent key decodes as `None`, and a value below `2` makes
//! the payload malformed. The field was added within v3: a decoder that
//! predates it ignores the key, and every roster written before it decodes
//! with no threshold.
//!
//! ## What changed from v2
//!
//! v2 stored a single `transport_uri` string per roster entry, so a peer
//! reachable on several transports could not be represented, and the protocol
//! had to be inferred from the URI scheme. v3 stores every endpoint with its
//! discriminant. A v2 payload still decodes: each URI becomes a one-element
//! list with the protocol taken from its scheme, and a URI that names no known
//! transport yields an entry with no endpoints.
//!
//! ## What changed from v1, and why v1 does not decode
//!
//! Three shape changes, all in the replica group:
//!
//! - **`channel_id` moved from each member to the group.** Every member of a
//!   group is addressed on one channel, so carrying it per member invited
//!   disagreement about a value that cannot legitimately differ.
//! - **`sender_kind` became `role`**, a
//!   [`ReplicaRole`](crate::protocol::types::ReplicaRole) discriminant rather
//!   than a wire `SenderKind`. Role is a property of *membership*, and exactly
//!   one member of a group carries `Source`.
//! - **`replicas` became `members`**, matching the field it now names.
//!
//! **There is no v1 decode path.** A v1 roster cannot express a source member
//! — it has no `transport_uri` for one — so it cannot be upgraded losslessly,
//! and a v1 payload is rejected rather than guessed at. No published release
//! carries a v1 roster: the last published version predates the roster
//! entirely, so nothing in the wild needs migrating.
//!
//! # Security of the encoding
//!
//! ## Every helper sees the compressed length
//!
//! The whole payload is one gzip stream: the user's secrets, every helper's
//! channel key and `communication_info`, and the replica group key. AES-GCM
//! keeps the length, and every share carries the full ciphertext, so every
//! helper learns the compressed length of every version. A helper also
//! chooses part of what is compressed, its own `communication_info`, which it
//! can change with `UpdateChannelInfo`. When that text repeats part of a
//! secret elsewhere in the stream, the stream compresses better. Over many
//! versions, a corrupted helper could therefore learn another helper's
//! channel key, the group key or the user's secrets a few characters at a
//! time: the side channel behind the CRIME and BREACH attacks. Each guess
//! costs a new version, which only the owner creates, after a contact change
//! the owner's application has to accept. The format does not close this
//! channel. Applications should keep
//! [`AutoAcceptPolicy::update_channel_info`](crate::protocol::AutoAcceptPolicy::update_channel_info)
//! off and treat a helper that keeps changing its contact details as
//! suspect.
//!
//! ## Decoding has no memory limit
//!
//! In recovery the payload is decrypted from shares that nothing
//! authenticates, so a forged recovery group can deliver any payload,
//! including one built to exhaust memory, and the version byte that selects
//! the decoder is part of it. The decoder parses the JSON while the stream is
//! being inflated. A payload that is not JSON is refused after its first
//! bytes, and whitespace around the JSON passes through without being
//! buffered; a corrupt or truncated stream is
//! [`SecretError::Decompression`], anything else malformed is
//! [`SecretError::Json`].
//!
//! A payload that is valid JSON still receives the memory its largest value
//! claims, and gzip lets a payload claim up to about 1030 times its own size.
//! The library sets no limit. When memory runs out, a native process is
//! killed by the operating system or aborts, with no error and no event;
//! under WebAssembly the call fails with a trap, after which the instance
//! must not be used. An application bounds this with
//! `parameter_range.max_share_size`: a recovery share larger than it is
//! refused before anything is decoded, so a payload can claim at most about
//! 1030 times that size.
//!
//! # Conformance
//!
//! Golden vectors (a canonical [`Secret`] paired with its exact v3 JSON, plus v2
//! vectors for the decode path) live under `library/tests/golden/`. gzip *decoding* is universal but *encoding*
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
