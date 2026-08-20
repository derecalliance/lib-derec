// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Guards `bindings/test_fixture/enums.json` against drifting behind the Rust
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

use derec_library::protocol::events::PendingActionKind;
use derec_library::protocol::types::{ChannelStatus, ReplicaRole, SecretKind, StateKind};

/// Names the fixture records for one enum, in wire encoding.
fn fixture_names(enum_name: &str) -> BTreeSet<String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../bindings/test_fixture/enums.json"
    );
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
        "{enum_name} has drifted from bindings/test_fixture/enums.json\n  \
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
        StateKind::PendingSyncCheck,
    ];
    let names: Vec<&str> = all
        .iter()
        .map(|k| match k {
            StateKind::PendingVerification => "PendingVerification",
            StateKind::PendingRecovery => "PendingRecovery",
            StateKind::PendingUnpair => "PendingUnpair",
            StateKind::SharingRound => "SharingRound",
            StateKind::PendingSyncCheck => "PendingSyncCheck",
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
        })
        .collect();
    assert_matches_fixture("PendingActionKind", &names);
}

/// The protobuf-derived enums are re-declared by hand in each SDK rather than
/// re-exported from generated code, so they drift like any other mirror.
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
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../bindings/test_fixture/enums.json"
    );
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
    // It was not always: `SharingRound` and `PendingSyncCheck` were declared
    // in the opposite order to the numbering every shim uses, so `kind as u32`
    // would have filed a row under the wrong kind.
    for (name, kind) in [
        ("PendingVerification", StateKind::PendingVerification),
        ("PendingRecovery", StateKind::PendingRecovery),
        ("PendingUnpair", StateKind::PendingUnpair),
        ("SharingRound", StateKind::SharingRound),
        ("PendingSyncCheck", StateKind::PendingSyncCheck),
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

/// The TypeScript SDKs declare their enums as *types*, which erase at runtime,
/// so there is nothing a JS test can inspect and no runtime check to write.
/// The drift that matters there is a union missing a member the core emits, so
/// the check is textual and lives here, where the fixture is already loaded.
#[test]
fn typescript_declarations_cover_the_fixture() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{root}/bindings/test_fixture/enums.json"))
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
        for (enum_name, js_object) in [("ContactMode", "ContactMode"), ("FlowKind", "FlowKind")] {
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

        // ContactMode is re-declared as a value enum in both packages.
        let mut missing_modes = Vec::new();
        for v in fixture["enums"]["ContactMode"]["variants"]
            .as_array()
            .expect("contact modes")
        {
            let name = v["name"].as_str().expect("name");
            let wire = v["wire"].as_i64().expect("wire");
            if !dts.contains(&format!("{name} = {wire}")) {
                missing_modes.push(format!("{name} = {wire}"));
            }
        }
        assert!(
            missing_modes.is_empty(),
            "packages/{pkg}/index.d.ts ContactMode is missing: {missing_modes:?}"
        );
    }
}
