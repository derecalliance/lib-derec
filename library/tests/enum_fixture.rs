// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Guards `library/tests/fixtures/enums.json` against drifting behind the Rust
//! definitions it mirrors.
//!
//! Every enum listed there is hand-mirrored into five SDKs with nothing linking
//! the copies. `ChannelStatus` gained `Unpairing` and neither Go nor .NET
//! learned of it; both then rejected a value the core legitimately emits, and
//! both test suites stayed green because each SDK only ever round-tripped the
//! variants it already knew about.
//!
//! The fixture is the external source of truth that fixes that: the SDKs assert
//! they can decode every entry, and this file asserts the entries are complete.
//!
//! Each check below pairs a hand-written list with an exhaustive `match` that
//! has no wildcard arm. Adding a variant in Rust therefore fails to compile
//! *here* — a few lines from the list that needs the new entry — and updating
//! the fixture is what then makes the SDK tests fail until each SDK is updated.

use std::collections::BTreeSet;

use derec_library::protocol::events::{
    CorruptionReason, IgnoreReason, NotRestoredReason, PendingActionKind, VerifyFailureReason,
};
use derec_library::protocol::types::{ChannelStatus, ReplicaRole, SecretKind, StateKind};

/// Names the fixture records for one enum, in wire encoding.
fn fixture_names(enum_name: &str) -> BTreeSet<String> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/enums.json");
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let doc: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {path}: {e}"));
    doc["enums"][enum_name]["variants"]
        .as_array()
        .unwrap_or_else(|| panic!("fixture has no variants for {enum_name}"))
        .iter()
        .map(|v| {
            v["name"]
                .as_str()
                .expect("variant name is a string")
                .to_owned()
        })
        .collect()
}

fn assert_matches_fixture(enum_name: &str, rust: &[&str]) {
    let rust: BTreeSet<String> = rust.iter().map(|s| (*s).to_owned()).collect();
    let fixture = fixture_names(enum_name);
    let missing: Vec<_> = rust.difference(&fixture).cloned().collect();
    let extra: Vec<_> = fixture.difference(&rust).cloned().collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{enum_name} has drifted from library/tests/fixtures/enums.json\n  \
         in Rust but not the fixture: {missing:?}\n  \
         in the fixture but not Rust: {extra:?}\n  \
         Update the fixture, then update every SDK until its tests pass again."
    );
}

#[test]
fn channel_status_fixture_is_complete() {
    let all = [
        ChannelStatus::Pending,
        ChannelStatus::Paired,
        ChannelStatus::Unpairing,
    ];
    let names: Vec<&str> = all
        .iter()
        .map(|s| match s {
            ChannelStatus::Pending => "Pending",
            ChannelStatus::Paired => "Paired",
            ChannelStatus::Unpairing => "Unpairing",
        })
        .collect();
    assert_eq!(names.len(), all.len());
    assert_matches_fixture("ChannelStatus", &names);
}

#[test]
fn replica_role_fixture_is_complete() {
    let all = [ReplicaRole::Source, ReplicaRole::Destination];
    let names: Vec<&str> = all
        .iter()
        .map(|r| match r {
            ReplicaRole::Source => "Source",
            ReplicaRole::Destination => "Destination",
        })
        .collect();
    assert_matches_fixture("ReplicaRole", &names);
}

#[test]
fn secret_kind_fixture_is_complete() {
    let all = [
        SecretKind::SharedKey,
        SecretKind::PairingSecret,
        SecretKind::PairingContact,
    ];
    let names: Vec<&str> = all
        .iter()
        .map(|k| match k {
            SecretKind::SharedKey => "SharedKey",
            SecretKind::PairingSecret => "PairingSecret",
            SecretKind::PairingContact => "PairingContact",
        })
        .collect();
    assert_matches_fixture("SecretKind", &names);
}

#[test]
fn state_kind_fixture_is_complete() {
    let all = [
        StateKind::PendingVerification,
        StateKind::PendingRecovery,
        StateKind::PendingUnpair,
        StateKind::SharingRound,
        StateKind::PendingReplicaDiscovery,
    ];
    let names: Vec<&str> = all
        .iter()
        .map(|k| match k {
            StateKind::PendingVerification => "PendingVerification",
            StateKind::PendingRecovery => "PendingRecovery",
            StateKind::PendingUnpair => "PendingUnpair",
            StateKind::SharingRound => "SharingRound",
            StateKind::PendingReplicaDiscovery => "PendingReplicaDiscovery",
        })
        .collect();
    assert_matches_fixture("StateKind", &names);
}

#[test]
fn pending_action_kind_fixture_is_complete() {
    let all = [
        PendingActionKind::Pairing,
        PendingActionKind::PrePair,
        PendingActionKind::StoreShare,
        PendingActionKind::VerifyShare,
        PendingActionKind::Discovery,
        PendingActionKind::GetShare,
        PendingActionKind::Unpair,
        PendingActionKind::UpdateChannelInfo,
        PendingActionKind::Failed,
    ];
    let names: Vec<&str> = all
        .iter()
        .map(|k| match k {
            PendingActionKind::Pairing => "Pairing",
            PendingActionKind::PrePair => "PrePair",
            PendingActionKind::StoreShare => "StoreShare",
            PendingActionKind::VerifyShare => "VerifyShare",
            PendingActionKind::Discovery => "Discovery",
            PendingActionKind::GetShare => "GetShare",
            PendingActionKind::Unpair => "Unpair",
            PendingActionKind::UpdateChannelInfo => "UpdateChannelInfo",
            PendingActionKind::Failed => "Failed",
        })
        .collect();
    assert_matches_fixture("PendingActionKind", &names);
}

/// The protobuf-derived enums are re-declared by hand in each SDK rather than
/// re-exported from generated code, so they drift like any other mirror.
#[test]
fn ignore_reason_fixture_is_complete() {
    let all = [
        IgnoreReason::PendingVerification,
        IgnoreReason::Expired,
        IgnoreReason::TimestampMismatch,
        IgnoreReason::StaleResponse,
    ];
    let names: Vec<&str> = all
        .iter()
        .map(|r| match r {
            IgnoreReason::PendingVerification => "PendingVerification",
            IgnoreReason::Expired => "Expired",
            IgnoreReason::TimestampMismatch => "TimestampMismatch",
            IgnoreReason::StaleResponse => "StaleResponse",
        })
        .collect();
    assert_matches_fixture("IgnoreReason", &names);
}

#[test]
fn not_restored_reason_fixture_is_complete() {
    let all = [NotRestoredReason::NoTransports];
    let names: Vec<&str> = all
        .iter()
        .map(|r| match r {
            NotRestoredReason::NoTransports => "NoTransports",
        })
        .collect();
    assert_matches_fixture("NotRestoredReason", &names);
}

#[test]
fn verify_failure_reason_fixture_is_complete() {
    let all = [
        VerifyFailureReason::NoSharedKey,
        VerifyFailureReason::NoProof,
        VerifyFailureReason::DispatchFailed,
    ];
    let names: Vec<&str> = all
        .iter()
        .map(|r| match r {
            VerifyFailureReason::NoSharedKey => "NoSharedKey",
            VerifyFailureReason::NoProof => "NoProof",
            VerifyFailureReason::DispatchFailed => "DispatchFailed",
        })
        .collect();
    assert_matches_fixture("VerifyFailureReason", &names);
}

#[test]
fn corruption_reason_fixture_is_complete() {
    let all = [
        CorruptionReason::Malformed,
        CorruptionReason::InvalidProof,
        CorruptionReason::Inconsistent,
    ];
    let names: Vec<&str> = all
        .iter()
        .map(|r| match r {
            CorruptionReason::Malformed => "Malformed",
            CorruptionReason::InvalidProof => "InvalidProof",
            CorruptionReason::Inconsistent => "Inconsistent",
        })
        .collect();
    assert_matches_fixture("CorruptionReason", &names);
}

#[test]
fn protobuf_enum_fixtures_are_complete() {
    use derec_proto::{ContactMode, SenderKind, StatusEnum};

    let sender: Vec<&str> = [
        SenderKind::Owner,
        SenderKind::Helper,
        SenderKind::ReplicaSource,
        SenderKind::ReplicaDestination,
    ]
    .iter()
    .map(|k| match k {
        SenderKind::Owner => "Owner",
        SenderKind::Helper => "Helper",
        SenderKind::ReplicaSource => "ReplicaSource",
        SenderKind::ReplicaDestination => "ReplicaDestination",
    })
    .collect();
    assert_matches_fixture("SenderKind", &sender);

    let contact: Vec<&str> = [
        ContactMode::InlineKeys,
        ContactMode::HashedKeys,
        ContactMode::NoKeys,
    ]
    .iter()
    .map(|m| match m {
        ContactMode::InlineKeys => "InlineKeys",
        ContactMode::HashedKeys => "HashedKeys",
        ContactMode::NoKeys => "NoKeys",
    })
    .collect();
    assert_matches_fixture("ContactMode", &contact);

    let status: Vec<&str> = [
        StatusEnum::Ok,
        StatusEnum::Partial,
        StatusEnum::Fail,
        StatusEnum::SizeLimitExceeded,
        StatusEnum::TooFrequent,
        StatusEnum::UnknownSecretId,
        StatusEnum::UnknownShareVersion,
        StatusEnum::DecryptionFailed,
        StatusEnum::VerificationFailed,
        StatusEnum::FormatError,
        StatusEnum::Rejected,
        StatusEnum::IncompatibleParameterRange,
        StatusEnum::UnsupportedTransportProtocol,
        StatusEnum::VersionConflict,
        StatusEnum::ReplicaIdConflict,
        StatusEnum::RequestToClose,
    ]
    .iter()
    .map(|s| match s {
        StatusEnum::Ok => "Ok",
        StatusEnum::Partial => "Partial",
        StatusEnum::Fail => "Fail",
        StatusEnum::SizeLimitExceeded => "SizeLimitExceeded",
        StatusEnum::TooFrequent => "TooFrequent",
        StatusEnum::UnknownSecretId => "UnknownSecretId",
        StatusEnum::UnknownShareVersion => "UnknownShareVersion",
        StatusEnum::DecryptionFailed => "DecryptionFailed",
        StatusEnum::VerificationFailed => "VerificationFailed",
        StatusEnum::FormatError => "FormatError",
        StatusEnum::Rejected => "Rejected",
        StatusEnum::IncompatibleParameterRange => "IncompatibleParameterRange",
        StatusEnum::UnsupportedTransportProtocol => "UnsupportedTransportProtocol",
        StatusEnum::VersionConflict => "VersionConflict",
        StatusEnum::ReplicaIdConflict => "ReplicaIdConflict",
        StatusEnum::RequestToClose => "RequestToClose",
    })
    .collect();
    assert_matches_fixture("StatusEnum", &status);
}

/// The numeric discriminants have to match too — an SDK that agrees on the
/// names but not the values is just as broken.
#[test]
fn numeric_discriminants_match_the_fixture() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/enums.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read fixture"))
            .expect("parse fixture");

    let wire = |enum_name: &str, variant: &str| -> i64 {
        doc["enums"][enum_name]["variants"]
            .as_array()
            .expect("variants")
            .iter()
            .find(|v| v["name"] == variant)
            .unwrap_or_else(|| panic!("{enum_name}::{variant} missing from fixture"))["wire"]
            .as_i64()
            .expect("numeric wire value")
    };

    for (name, kind) in [
        ("SharedKey", SecretKind::SharedKey),
        ("PairingSecret", SecretKind::PairingSecret),
        ("PairingContact", SecretKind::PairingContact),
    ] {
        assert_eq!(wire("SecretKind", name), kind as i64, "SecretKind::{name}");
    }

    // Declaration order is the wire order here, so a plain cast is correct.
    // It was not always: `SharingRound` and `PendingReplicaDiscovery` were declared
    // in the opposite order to the numbering every shim uses, so `kind as u32`
    // would have filed a row under the wrong kind.
    for (name, kind) in [
        ("PendingVerification", StateKind::PendingVerification),
        ("PendingRecovery", StateKind::PendingRecovery),
        ("PendingUnpair", StateKind::PendingUnpair),
        ("SharingRound", StateKind::SharingRound),
        (
            "PendingReplicaDiscovery",
            StateKind::PendingReplicaDiscovery,
        ),
    ] {
        assert_eq!(wire("StateKind", name), kind as i64, "StateKind::{name}");
    }
    assert_eq!(
        wire("SenderKind", "ReplicaDestination"),
        derec_proto::SenderKind::ReplicaDestination as i64
    );
    assert_eq!(
        wire("ContactMode", "NoKeys"),
        derec_proto::ContactMode::NoKeys as i64
    );
    assert_eq!(
        wire("StatusEnum", "ReplicaIdConflict"),
        derec_proto::StatusEnum::ReplicaIdConflict as i64
    );
}

/// The TypeScript SDKs declare their string enums as *types*, which erase at
/// runtime, so there is nothing a JS test can inspect and no runtime check to
/// write. The drift that matters there is a union missing a member the core
/// emits, so the check is textual and lives here, where the fixture is already
/// loaded.
#[test]
fn typescript_declarations_cover_the_fixture() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{root}/library/tests/fixtures/enums.json"))
            .expect("read fixture"),
    )
    .expect("parse fixture");

    for pkg in ["nodejs", "web"] {
        let path = format!("{root}/packages/{pkg}/index.d.ts");
        let dts = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));

        // Event tags are the discriminants of the DeRecEvent union. A tag the
        // core emits but the union omits leaves callers unable to name it.
        let mut missing = Vec::new();
        for v in fixture["enums"]["DeRecEvent"]["variants"]
            .as_array()
            .expect("event variants")
        {
            let tag = v["wire"].as_str().expect("event tag");
            if !dts.contains(&format!("type: \"{tag}\"")) {
                missing.push(tag.to_owned());
            }
        }
        assert!(
            missing.is_empty(),
            "packages/{pkg}/index.d.ts does not declare these event tags: {missing:?}\n               Add them to the DeRecEvent union, then update the fixture if the core changed."
        );

        // The runtime shim is a separate hand-written object from the
        // declaration file, and only it exists at run time. `ContactMode.NoKeys`
        // and two `FlowKind` members were declared in the `.d.ts` but absent
        // here, so TypeScript accepted them and they evaluated to `undefined`.
        let js_path = format!("{root}/packages/{pkg}/index.js");
        let js =
            std::fs::read_to_string(&js_path).unwrap_or_else(|e| panic!("reading {js_path}: {e}"));
        for (enum_name, js_object) in [
            ("ContactMode", "ContactMode"),
            ("FlowKind", "FlowKind"),
            ("StatusEnum", "StatusEnum"),
        ] {
            let mut absent = Vec::new();
            for v in fixture["enums"][enum_name]["variants"]
                .as_array()
                .unwrap_or_else(|| panic!("{enum_name} variants"))
            {
                let name = v["name"].as_str().expect("name");
                let wire = v["wire"].as_i64().expect("wire");
                if !js.contains(&format!("{name}: {wire}")) {
                    absent.push(format!("{name}: {wire}"));
                }
            }
            assert!(
                absent.is_empty(),
                "packages/{pkg}/index.js `{js_object}` is missing {absent:?} — \
                 declared in index.d.ts but absent at run time, so callers get `undefined`"
            );
        }

        // The value enums are declared as the frozen objects the shim ships:
        // `export declare const X: { readonly Name: wire; … }`, with no
        // reverse mapping, so each member must be declared with its wire value.
        for enum_name in ["ContactMode", "FlowKind", "StatusEnum"] {
            assert!(
                dts.contains(&format!("export declare const {enum_name}: {{")),
                "packages/{pkg}/index.d.ts must declare `{enum_name}` as the const object index.js ships"
            );
            assert!(
                !dts.contains(&format!("export enum {enum_name}")),
                "packages/{pkg}/index.d.ts declares `{enum_name}` as an enum, whose reverse mapping index.js does not ship"
            );
            let mut missing = Vec::new();
            for v in fixture["enums"][enum_name]["variants"]
                .as_array()
                .unwrap_or_else(|| panic!("{enum_name} variants"))
            {
                let name = v["name"].as_str().expect("name");
                let wire = v["wire"].as_i64().expect("wire");
                if !dts.contains(&format!("readonly {name}: {wire};")) {
                    missing.push(format!("{name}: {wire}"));
                }
            }
            assert!(
                missing.is_empty(),
                "packages/{pkg}/index.d.ts {enum_name} is missing: {missing:?}"
            );
        }
    }
}

/// React Native declares the same event union by hand in its own file, so it
/// drifts independently of nodejs and web. The reason unions are checked with
/// the tags: a reason the core emits but a union omits is as unnameable as a
/// missing tag.
#[test]
fn every_typescript_surface_names_every_event_and_reason() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{root}/library/tests/fixtures/enums.json"))
            .expect("read fixture"),
    )
    .expect("parse fixture");
    let wires = |enum_name: &str| -> Vec<String> {
        fixture["enums"][enum_name]["variants"]
            .as_array()
            .unwrap_or_else(|| panic!("{enum_name} variants"))
            .iter()
            .map(|v| v["wire"].as_str().expect("string wire").to_owned())
            .collect()
    };

    for surface in [
        "packages/nodejs/index.d.ts",
        "packages/web/index.d.ts",
        "packages/react-native/src/types.ts",
    ] {
        let path = format!("{root}/{surface}");
        let source =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));

        let mut missing: Vec<String> = wires("DeRecEvent")
            .into_iter()
            .filter(|tag| !source.contains(&format!("type: \"{tag}\"")))
            .collect();

        for reason in [
            "IgnoreReason",
            "NotRestoredReason",
            "CorruptionReason",
            "VerifyFailureReason",
        ] {
            let header = format!("export type {reason} =");
            let line = source
                .lines()
                .find(|l| l.starts_with(&header))
                .unwrap_or_else(|| panic!("{surface} declares no `{header}`"));
            missing.extend(
                wires(reason)
                    .into_iter()
                    .filter(|w| !line.contains(&format!("\"{w}\"")))
                    .map(|w| format!("{reason}::{w}")),
            );
        }

        assert!(
            missing.is_empty(),
            "{surface} does not name {missing:?}. Add them, then update the fixture if the core changed."
        );
    }
}

/// Every double-quoted snake_case literal between the first occurrence of
/// `start` and the following occurrence of `end` in `source`.
fn quoted_literals_between(source: &str, start: &str, end: &str) -> BTreeSet<String> {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("source does not contain {start:?}"));
    let rest = &source[from + start.len()..];
    let to = rest
        .find(end)
        .unwrap_or_else(|| panic!("source does not contain {end:?} after {start:?}"));
    let block = &rest[..to];

    let mut out = BTreeSet::new();
    let bytes = block.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"'
            && let Some(len) = block[i + 1..].find('"')
        {
            out.insert(block[i + 1..i + 1 + len].to_owned());
            i += 1 + len + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// `DeRecErrorCode` is a string-literal union in every TypeScript surface, so
/// — like the reason unions above — there is no runtime value a JS test can
/// check; the drift that matters is textual, and this is where the fixture
/// is already loaded.
///
/// Node and Web go through WASM, which raises marshalling-level codes of its
/// own before a value ever reaches the library (malformed argument shapes,
/// bad flow kinds, values that will not fit a `u64`); those codes are not in
/// the fixture because no Rust `Error` variant produces them, so they are
/// listed explicitly here, sourced from every `js_error("...")` call site
/// under `library/src/interop/wasm/`. React Native goes through the C ABI
/// instead, which raises no marshalling-level codes of its own (malformed
/// FFI input is reported under the fixture's own `ffi_*` codes), so its
/// union is exactly the fixture with no extras.
#[test]
fn derec_error_code_union_covers_fixture_and_wasm_extras() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{root}/library/tests/fixtures/enums.json"))
            .expect("read fixture"),
    )
    .expect("parse fixture");

    let fixture_codes: BTreeSet<String> = fixture["enums"]["DeRecErrorCode"]["variants"]
        .as_array()
        .expect("DeRecErrorCode variants")
        .iter()
        .map(|v| v["text"].as_str().expect("variant text").to_owned())
        .collect();

    // Every `js_error("...")` call site under library/src/interop/wasm/, as
    // of this test's writing. A code added there without a matching entry
    // here fails this test the moment the corresponding `.d.ts` union is
    // updated to carry it — see the two `assert_eq!`s below.
    let wasm_only: BTreeSet<String> = [
        "builder_missing",
        "decode_error",
        "envelope_decode_error",
        "internal",
        "invalid_auto_accept_policy",
        "invalid_communication_info",
        "invalid_contact_mode",
        "invalid_discovery_target",
        "invalid_flow_kind",
        "invalid_flow_params",
        "invalid_max_subshares",
        "invalid_nonce",
        "invalid_own_transport",
        "invalid_parameter_range",
        "invalid_peer_communication_info",
        "invalid_protocol",
        "invalid_recovered_secret",
        "invalid_refusal_reason",
        "invalid_replica_id",
        "invalid_secret_id",
        "invalid_sender_kind",
        "invalid_shared_key_length",
        "invalid_status",
        "invalid_timeouts",
        "invalid_transport_protocol",
        "invalid_unpair_ack",
        "serialization_error",
        "serialize",
        "wasm_deserialize_error",
        "wasm_serialize_error",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    assert!(
        wasm_only.is_disjoint(&fixture_codes),
        "a code listed as WASM-only is actually in the fixture: {:?}",
        wasm_only.intersection(&fixture_codes).collect::<Vec<_>>()
    );

    // React Native goes through the C ABI, which has no marshalling-level
    // codes of its own beyond the fixture's `ffi_*` entries.
    let rn_only: BTreeSet<String> = BTreeSet::new();

    for pkg in ["nodejs", "web"] {
        let path = format!("{root}/packages/{pkg}/index.d.ts");
        let dts = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        let declared = quoted_literals_between(&dts, "export type DeRecErrorCode =", ";");
        let expected: BTreeSet<String> = fixture_codes.union(&wasm_only).cloned().collect();
        assert_eq!(
            declared, expected,
            "packages/{pkg}/index.d.ts's DeRecErrorCode has drifted from the fixture plus the documented WASM-only codes"
        );
    }

    let rn_path = format!("{root}/packages/react-native/src/errors.ts");
    let rn_source =
        std::fs::read_to_string(&rn_path).unwrap_or_else(|e| panic!("reading {rn_path}: {e}"));
    let rn_declared = quoted_literals_between(
        &rn_source,
        "export const DEREC_ERROR_CODES = [",
        "] as const;",
    );
    let rn_expected: BTreeSet<String> = fixture_codes.union(&rn_only).cloned().collect();
    assert_eq!(
        rn_declared, rn_expected,
        "packages/react-native/src/errors.ts's DEREC_ERROR_CODES has drifted from the fixture"
    );
}
