// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#![cfg(feature = "serde")]

//! Guards the TypeScript message declarations against drifting behind
//! `library/src/interop/dto.rs`.
//!
//! Those DTOs are what the SDK boundaries actually serialize, so `dto.rs` is
//! the shape of the JSON every TypeScript caller receives. The three surfaces
//! that describe that JSON — nodejs, web and react-native — are hand-written
//! and nothing links them to it. A field added to a DTO therefore reaches the
//! wire immediately and the type declarations never, which is the worst
//! version of this failure: the data is present at run time and invisible to
//! the compiler, so callers cannot read it without a cast and have no reason
//! to think it exists.
//!
//! That is not hypothetical. `replica_id` was added to seven messages and
//! declared on none of the three surfaces; every suite in the repository
//! stayed green, including a round-trip test asserting the field survives
//! encoding, because runtime round-trips cannot see a missing *declaration*.
//! `enum_fixture.rs` already solved the same class of problem for enum
//! members by reading the `.d.ts` files as text. This does it for fields.
//!
//! The check runs in both directions. A field in `dto.rs` and not in a
//! surface is the bug above; a field in a surface and not in `dto.rs` is a
//! promise the runtime never keeps.
//!
//! `dto` is compiled only with the `serde` feature, so this file is inert
//! under a bare `cargo test`. The Makefile's `cargo test -p derec-library
//! --features ffi` (`ffi` implies `serde`) is the run that exercises it.

use derec_library::interop::dto;

/// Pairs each DTO with its field names, and makes the pairing self-checking.
///
/// The destructuring below has no `..` arm, so adding a field to a DTO fails
/// to compile here until the list names it — the same trick that keeps the
/// hand-mirrored enum lists in `enum_fixture.rs` from rotting, where the
/// wildcard-free `match` plays this part.
macro_rules! message_fields {
    ($($name:ident { $($field:ident),+ $(,)? })+) => {{
        #[allow(dead_code, non_snake_case, unused_variables)]
        fn exhaustive() {
            $(
                fn $name(value: dto::$name) {
                    let dto::$name { $($field),+ } = value;
                }
            )+
        }

        vec![$((stringify!($name), vec![$(stringify!($field)),+])),+]
    }};
}

/// Every hand-written surface describing the DTO JSON.
const SURFACES: [&str; 3] = [
    "packages/nodejs/index.d.ts",
    "packages/web/index.d.ts",
    "packages/react-native/src/types.ts",
];

/// Field names declared directly on `export interface <name>`.
///
/// Returns `None` when the interface is absent entirely. Fields sit at exactly
/// two spaces of indentation in all three files; anything more deeply indented
/// belongs to a nested object literal and is not a field of this interface.
fn declared_fields(source: &str, interface: &str) -> Option<Vec<String>> {
    let header = format!("export interface {interface} {{");
    let start = source
        .match_indices(&header)
        .find(|(i, _)| *i == 0 || source.as_bytes()[i - 1] == b'\n')
        .map(|(i, _)| i + header.len())?;

    let body = &source[start..];
    let end = body.find("\n}").map_or(body.len(), |i| i + 1);

    let mut fields = Vec::new();
    for line in body[..end].lines() {
        let Some(rest) = line.strip_prefix("  ") else {
            continue;
        };
        if rest.starts_with([' ', '*', '/']) {
            continue;
        }
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        if rest[name.len()..].starts_with(':') || rest[name.len()..].starts_with("?:") {
            fields.push(name);
        }
    }
    Some(fields)
}

#[test]
fn typescript_surfaces_declare_every_dto_field() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

    let expected: Vec<(&str, Vec<&str>)> = message_fields! {
        Timestamp { seconds, nanos }
        TransportProtocol { uri, protocol }
        DeRecResult { status, memo }
        CommunicationInfoKeyValue { key, string_value, bytes_value }
        CommunicationInfo { communication_info_entries }
        ParameterRange {
            min_share_size, max_share_size, min_time_between_verifications,
            max_time_between_verifications, min_time_between_share_updates,
            max_time_between_share_updates, min_unresponsive_deletion_timeout,
            max_unresponsive_deletion_timeout, min_unresponsive_deactivation_timeout,
            max_unresponsive_deactivation_timeout,
        }
        ContactMessage {
            channel_id, transport_protocol, nonce, contact_mode, mlkem_encapsulation_key,
            ecies_public_key, contact_binding_hash, timestamp, supported_transports,
        }
        PairRequestMessage {
            sender_kind, mlkem_ciphertext, ecies_public_key, nonce, communication_info,
            parameter_range, transport_protocol, timestamp, supported_transports,
        }
        PairResponseMessage {
            result, nonce, communication_info, parameter_range, timestamp, channel_id,
        }
        PrePairRequestMessage { nonce, transport_protocol, timestamp, supported_transports }
        PrePairResponseMessage {
            result, mlkem_encapsulation_key, ecies_public_key, nonce, timestamp,
        }
        VersionListEntry { version, version_description }
        VersionList { secret_id, versions }
        GetSecretIdsVersionsRequestMessage {
            timestamp, reply_to, replica_id,
        }
        GetSecretIdsVersionsResponseMessage { result, secret_list, timestamp, replica_id }
        VersionEntry { version, description }
        SecretVersionEntry { secret_id, versions }
        SiblingHash { is_left, hash }
        CommittedDeRecShare { de_rec_share, commitment, merkle_path }
        StoreShareRequestMessage {
            share, share_algorithm, version, keep_list, version_description, timestamp,
            secret_id, reply_to, replica_id,
        }
        StoreShareResponseMessage { result, version, timestamp, secret_id, replica_id }
        GetShareRequestMessage {
            secret_id, version, timestamp, reply_to, replica_id,
        }
        GetShareResponseMessage {
            share_algorithm, committed_de_rec_share, result, timestamp, secret_id, version,
            replica_id,
        }
        UnpairRequestMessage { memo, timestamp, reply_to, replica_id }
        UnpairResponseMessage { result, timestamp }
        VerifyShareRequestMessage {
            secret_id, version, nonce, timestamp, reply_to,
        }
        VerifyShareResponseMessage { result, secret_id, version, nonce, hash, timestamp }
    };

    let mut problems = Vec::new();

    for surface in SURFACES {
        let path = format!("{root}/{surface}");
        let source =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));

        for (name, fields) in &expected {
            let Some(declared) = declared_fields(&source, name) else {
                problems.push(format!("{surface}: no `export interface {name}`"));
                continue;
            };

            let undeclared: Vec<_> = fields
                .iter()
                .filter(|f| !declared.iter().any(|d| d == *f))
                .collect();
            if !undeclared.is_empty() {
                problems.push(format!("{surface}: {name} does not declare {undeclared:?}"));
            }

            let unbacked: Vec<_> = declared
                .iter()
                .filter(|d| !fields.iter().any(|f| f == d))
                .collect();
            if !unbacked.is_empty() {
                problems.push(format!(
                    "{surface}: {name} declares {unbacked:?}, which the DTO does not emit"
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "TypeScript declarations have drifted from library/src/interop/dto.rs:\n  {}\n\n\
         Update the surface(s) listed, or the DTO if the core changed.",
        problems.join("\n  ")
    );
}

/// `withUnsafeConnection` and the `Grpc` transport discriminant have no
/// `dto::` struct behind them to destructure exhaustively: `unsafe_http` /
/// `unsafe_connection` live on the private FFI `ProtocolConfig`
/// (`library/src/interop/ffi/protocol/handle/mod.rs`), and the transport
/// `Protocol` enum is declared in `protobufs/transportprotocol.proto` — both
/// unreachable from this external test crate the way `dto::` is. The check
/// is therefore textual, the same trick `enum_fixture.rs` uses for the
/// nodejs/web runtime shims: assert each surface's source actually forwards
/// the value, so a surface that gained the enum member (A1) or the config
/// key (A5) on the Rust side without a matching setter here fails loudly
/// instead of silently rejecting or ignoring it.
#[test]
fn typescript_surfaces_forward_unsafe_connection_and_grpc() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");

    for pkg in ["nodejs", "web"] {
        let path = format!("{root}/packages/{pkg}/index.d.ts");
        let dts = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        assert!(
            dts.contains("withUnsafeConnection(allow: boolean): DeRecProtocolBuilder;"),
            "{path} does not declare withUnsafeConnection"
        );
    }

    let rn_path = format!("{root}/packages/react-native/src/protocol.ts");
    let rn = std::fs::read_to_string(&rn_path).unwrap_or_else(|e| panic!("reading {rn_path}: {e}"));
    assert!(
        rn.contains("withUnsafeConnection(allow: boolean): this")
            && rn.contains("this.config.unsafe_connection = allow;"),
        "{rn_path} does not forward unsafe_connection to the wire config"
    );
    assert!(
        rn.contains("case 'grpc':"),
        "{rn_path} protocolDiscriminant does not resolve the Grpc protocol name"
    );
}
