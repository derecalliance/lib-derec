// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Guards the five SDK API surfaces against drifting behind the core.
//!
//! [`enum_fixture`](../enum_fixture.rs) does this for enum *members* and
//! [`dto_field_parity`](../dto_field_parity.rs) for message *fields*. Neither
//! covers the API itself — the protocol methods, the builder options, the flow
//! parameter types and the store trait methods — and that is where drift went
//! unnoticed: an audit found Go missing a `SecretID` accessor the other four
//! exposed, missing the `ReplicaDiscoveryParams` type the other four declare
//! deliberately, and the three TypeScript surfaces missing the filter
//! `matches` helper .NET and Go both shipped. Every suite was green throughout,
//! because nothing links an SDK's method list to the core's.
//!
//! `fixtures/api_surface.json` is that link. The checks run in both
//! directions:
//!
//! - **Fixture vs core.** A method, option, flow or store method that exists in
//!   Rust and is absent from the fixture fails here. `DeRecFlow` is matched
//!   exhaustively with no wildcard arm, so a new flow fails to *compile* in
//!   this file; the rest are read from the sources that define them — the
//!   generated C header, the FFI config struct, and `traits.rs`.
//! - **Fixture vs SDKs.** Anything named in the fixture and not declared by an
//!   SDK fails, naming the SDK and the file.
//!
//! The SDK side is text search, as it is in the two tests above: these are five
//! languages the Rust compiler cannot see into, so reading their declarations
//! as text is the only check available that costs nothing to run.

use std::collections::BTreeSet;
use std::path::PathBuf;

use derec_library::protocol::DeRecFlow;

/// Repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("library/ has a parent")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn fixture() -> serde_json::Value {
    let raw = read("library/tests/fixtures/api_surface.json");
    serde_json::from_str(&raw).expect("api_surface.json is valid JSON")
}

fn entries(section: &str) -> Vec<serde_json::Value> {
    fixture()[section]
        .as_array()
        .unwrap_or_else(|| panic!("api_surface.json has no `{section}` array"))
        .clone()
}

fn field(entry: &serde_json::Value, key: &str) -> String {
    entry[key]
        .as_str()
        .unwrap_or_else(|| panic!("fixture entry {entry} has no `{key}`"))
        .to_owned()
}

/// The five surfaces a declaration has to appear in, as (label, path).
///
/// Go is listed twice because it splits the protocol across files; a name
/// present in either satisfies the check.
const SDK_PROTOCOL: &[(&str, &[&str])] = &[
    (
        "dotnet",
        &["packages/dotnet/DeRec.Library/src/Protocol/DeRecProtocol.cs"],
    ),
    (
        "go",
        &[
            "packages/go/protocol/protocol.go",
            "packages/go/protocol/flow.go",
            "packages/go/protocol/contact.go",
        ],
    ),
    ("nodejs", &["packages/nodejs/index.d.ts"]),
    ("web", &["packages/web/index.d.ts"]),
    ("react-native", &["packages/react-native/src/protocol.ts"]),
];

const SDK_BUILDER: &[(&str, &[&str])] = &[
    (
        "dotnet",
        &["packages/dotnet/DeRec.Library/src/Protocol/DeRecProtocolBuilder.cs"],
    ),
    ("go", &["packages/go/protocol/protocol.go"]),
    ("nodejs", &["packages/nodejs/index.d.ts"]),
    ("web", &["packages/web/index.d.ts"]),
    ("react-native", &["packages/react-native/src/protocol.ts"]),
];

const SDK_HELPERS: &[(&str, &[&str])] = &[
    (
        "dotnet",
        &["packages/dotnet/DeRec.Library/src/Protocol/Stores.cs"],
    ),
    ("go", &["packages/go/internal/native/store_types.go"]),
    (
        "nodejs",
        &["packages/nodejs/index.d.ts", "packages/nodejs/index.js"],
    ),
    ("web", &["packages/web/index.d.ts", "packages/web/index.js"]),
    ("react-native", &["packages/react-native/src/types.ts"]),
];

const SDK_TYPES: &[(&str, &[&str])] = &[
    (
        "dotnet",
        &[
            "packages/dotnet/DeRec.Library/src/Protocol/Flows.cs",
            "packages/dotnet/DeRec.Library/src/Protocol/Stores.cs",
        ],
    ),
    (
        "go",
        &[
            "packages/go/protocol/flow.go",
            "packages/go/protocol/stores.go",
            "packages/go/internal/native/store_types.go",
        ],
    ),
    ("nodejs", &["packages/nodejs/index.d.ts"]),
    ("web", &["packages/web/index.d.ts"]),
    ("react-native", &["packages/react-native/src/types.ts"]),
];

/// The shape a name has to appear in to count as *declared*.
///
/// A bare token search is not enough, and the gap that motivated this file
/// proves it: Go held `SecretID` as a field on the input `Config` while the
/// constructed protocol had no such accessor. The identifier was present four
/// times in the file — in a doc comment, a struct field, and two struct
/// literals — so a token search reports a method that does not exist.
#[derive(Clone, Copy)]
enum Shape {
    /// Go receiver method: `func (p *DeRecProtocol) SecretID() uint64`.
    GoMethod,
    /// Go struct field: `Threshold uint32`.
    GoField,
    /// C# member: a `public` method, property or field.
    CsMember,
    /// A member declaration that opens its line — TypeScript interface and
    /// class members, and Go interface methods, share this shape.
    LineMember,
    /// A type name, distinctive enough that any mention is a declaration.
    TypeName,
}

fn declared_in(text: &str, needle: &str, shape: Shape) -> bool {
    match shape {
        Shape::TypeName => text
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|tok| tok == needle),
        Shape::GoMethod => text.contains(&format!(") {needle}(")),
        Shape::GoField => text.lines().any(|l| {
            let t = l.trim_start();
            t.strip_prefix(needle)
                .is_some_and(|rest| rest.starts_with(char::is_whitespace))
        }),
        Shape::CsMember => text.lines().any(|l| {
            let t = l.trim_start();
            // A callable, whether or not it carries an access modifier:
            // interface members declare none, so requiring `public` would
            // report every `IChannelStore` method as absent.
            t.contains(&format!(" {needle}("))
                // A property or field, which does carry one.
                || (t.starts_with("public")
                    && (t.contains(&format!(" {needle} ")) || t.contains(&format!(" {needle};"))))
        }),
        Shape::LineMember => text.lines().any(|l| {
            let t = l.trim_start();
            // Strip the modifiers a member declaration may open with.
            let t = [
                "readonly ",
                "get ",
                "async ",
                "abstract ",
                "override ",
                "export declare function ",
                "export function ",
                "function ",
            ]
            .iter()
            .fold(t, |acc, m| acc.strip_prefix(m).unwrap_or(acc));
            t.strip_prefix(needle).is_some_and(|rest| {
                rest.starts_with('(') || rest.starts_with("?(") || rest.starts_with(':')
            })
        }),
    }
}

/// Whether `needle` is declared, in the right shape, in `paths`.
///
/// `require_all` distinguishes two reasons a surface spans several files. Go
/// splits the protocol across three, and a name in any one of them is
/// declared. A TypeScript package instead has a *declaration* file and a
/// *runtime* file, and a name must be in both: present in `index.d.ts` and
/// absent from `index.js` is the worst shape of all, because it type-checks
/// and hands the caller `undefined`.
fn declared(paths: &[&str], needle: &str, shape: Shape, require_all: bool) -> bool {
    let mut hits = paths.iter().map(|p| declared_in(&read(p), needle, shape));
    if require_all {
        hits.all(|h| h)
    } else {
        hits.any(|h| h)
    }
}

/// The declaration shape to require, per SDK, for a given section.
fn shape_for(sdk: &str, section: &str) -> Shape {
    match (sdk, section) {
        (_, "flow_params") => Shape::TypeName,
        ("go", "sdk_helpers") => Shape::GoMethod,
        ("go", "protocol_methods") => Shape::GoMethod,
        ("go", "builder_options") => Shape::GoField,
        ("go", _) => Shape::LineMember,
        ("dotnet", _) => Shape::CsMember,
        _ => Shape::LineMember,
    }
}

/// Assert every fixture entry is declared by every SDK, reporting all misses
/// at once rather than the first.
fn assert_declared(section: &str, surfaces: &[(&str, &[&str])], require_all: bool) {
    let mut missing: Vec<String> = Vec::new();
    for entry in entries(section) {
        for (sdk, paths) in surfaces {
            let key = if *sdk == "nodejs" || *sdk == "web" || *sdk == "react-native" {
                "ts"
            } else {
                sdk
            };
            let name = field(&entry, key);
            if !declared(paths, &name, shape_for(sdk, section), require_all) {
                missing.push(format!("  {sdk}: `{name}` (from {section} entry {entry})"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these SDKs do not declare part of the API surface:\n{}\n\n\
         Either add the declaration, or — if the core dropped it — remove the \
         entry from library/tests/fixtures/api_surface.json.",
        missing.join("\n")
    );
}

// ── fixture vs core ────────────────────────────────────────────────────────

/// Every flow the core defines has a params type named in the fixture.
///
/// The `match` has no wildcard arm, so adding a `DeRecFlow` variant fails to
/// compile here until this list names it.
#[test]
fn fixture_covers_every_flow() {
    fn name_of(flow: &DeRecFlow) -> &'static str {
        match flow {
            DeRecFlow::Pairing { .. } => "Pairing",
            DeRecFlow::Discovery { .. } => "Discovery",
            DeRecFlow::ProtectSecret { .. } => "ProtectSecret",
            DeRecFlow::VerifyShares { .. } => "VerifyShares",
            DeRecFlow::RecoverSecret { .. } => "RecoverSecret",
            DeRecFlow::ReplicaDiscovery => "ReplicaDiscovery",
            DeRecFlow::UnpairReplica { .. } => "UnpairReplica",
            DeRecFlow::Unpair { .. } => "Unpair",
            DeRecFlow::UpdateChannelInfo { .. } => "UpdateChannelInfo",
        }
    }
    // Kept in step with the match above by `name_of` being total: a new
    // variant breaks compilation there, and this list is what fails next.
    let all = [
        "Pairing",
        "Discovery",
        "ProtectSecret",
        "VerifyShares",
        "RecoverSecret",
        "ReplicaDiscovery",
        "UnpairReplica",
        "Unpair",
        "UpdateChannelInfo",
    ];
    let _ = name_of; // the match is the guard; this silences dead-code.

    let in_fixture: BTreeSet<String> = entries("flow_params")
        .iter()
        .map(|e| field(e, "flow"))
        .collect();
    let in_core: BTreeSet<String> = all.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(
        in_core.difference(&in_fixture).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "flows defined by the core and absent from api_surface.json"
    );
    assert_eq!(
        in_fixture.difference(&in_core).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "flows in api_surface.json that the core no longer defines"
    );
}

/// Every `derec_protocol_*` export is named in the fixture.
///
/// The generated header is the source of truth because it is regenerated from
/// the Rust by cbindgen and checked in: a new export lands here without anyone
/// having to remember this file exists.
#[test]
fn fixture_covers_every_ffi_protocol_export() {
    // Expressed as a constructor and a disposer in each SDK rather than as
    // methods, so they have no row in the fixture.
    const LIFECYCLE: &[&str] = &["new", "free", "version"];

    let header = read("packages/react-native/cpp/derec_ffi.h");
    let mut exported: BTreeSet<String> = BTreeSet::new();
    for tok in header.split(|c: char| !c.is_alphanumeric() && c != '_') {
        if let Some(rest) = tok.strip_prefix("derec_protocol_")
            && !rest.is_empty()
        {
            exported.insert(rest.to_owned());
        }
    }
    let named: BTreeSet<String> = entries("protocol_methods")
        .iter()
        .map(|e| field(e, "rust"))
        .collect();

    let missing: Vec<&String> = exported
        .iter()
        .filter(|e| !LIFECYCLE.contains(&e.as_str()) && !named.contains(*e))
        .collect();
    assert!(
        missing.is_empty(),
        "derec_ffi.h exports these and api_surface.json does not name them: {missing:?}\n\
         Add a row with each SDK's spelling, then update the SDKs until the \
         parity tests pass."
    );
}

/// Every field an application can set through the FFI config is named in the
/// fixture.
#[test]
fn fixture_covers_every_config_option() {
    let src = read("library/src/interop/ffi/protocol/handle/mod.rs");
    let body = src
        .split_once("struct ProtocolConfig {")
        .expect("ProtocolConfig is declared in the FFI handle module")
        .1
        .split_once("\n}")
        .expect("ProtocolConfig has a closing brace")
        .0;

    let mut fields: BTreeSet<String> = BTreeSet::new();
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with("//") || line.starts_with("#[") || line.is_empty() {
            continue;
        }
        if let Some((name, _)) = line.split_once(':')
            && name.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            && !name.is_empty()
        {
            fields.insert(name.to_owned());
        }
    }

    // Taken as the builder's constructor argument in every SDK rather than as
    // a setter, so it has no `builder_options` row.
    const CONSTRUCTOR_ARGS: &[&str] = &["secret_id"];

    let named: BTreeSet<String> = entries("builder_options")
        .iter()
        .map(|e| field(e, "rust"))
        .chain(CONSTRUCTOR_ARGS.iter().map(|s| (*s).to_owned()))
        .collect();
    let missing: Vec<&String> = fields.difference(&named).collect();
    assert!(
        missing.is_empty(),
        "ProtocolConfig has these fields and api_surface.json does not name them: {missing:?}"
    );
}

/// Every store trait method is named in the fixture.
#[test]
fn fixture_covers_every_store_trait_method() {
    let src = read("library/src/protocol/traits.rs");
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    let mut current: Option<String> = None;
    for line in src.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("pub trait ") {
            let name = rest.split([':', ' ', '{']).next().unwrap_or("").to_owned();
            current = name.starts_with("DeRec").then_some(name);
            continue;
        }
        // A trait is a top-level item, so its body ends at the first
        // column-zero `}`. Without this the walk keeps attributing every
        // later four-space `fn` — forwarding impls, test helpers — to
        // whichever trait was declared last.
        if line == "}" {
            current = None;
            continue;
        }
        // Only declarations inside the trait body, which are indented by four.
        if let Some(trait_name) = current.as_ref()
            && let Some(rest) = line.strip_prefix("    fn ")
            && let Some((method, _)) = rest.split_once('(')
        {
            found.insert((trait_name.clone(), method.to_owned()));
        }
    }

    let named: BTreeSet<(String, String)> = entries("store_methods")
        .iter()
        .map(|e| (field(e, "trait"), field(e, "rust")))
        .collect();
    let missing: Vec<&(String, String)> = found.difference(&named).collect();
    assert!(
        missing.is_empty(),
        "these store trait methods are not named in api_surface.json: {missing:?}"
    );
}

// ── fixture vs SDKs ────────────────────────────────────────────────────────

#[test]
fn every_sdk_declares_every_protocol_method() {
    assert_declared("protocol_methods", SDK_PROTOCOL, false);
}

#[test]
fn every_sdk_declares_every_builder_option() {
    assert_declared("builder_options", SDK_BUILDER, false);
}

#[test]
fn every_sdk_declares_every_flow_params_type() {
    assert_declared("flow_params", SDK_TYPES, false);
}

#[test]
fn every_sdk_declares_every_store_method() {
    assert_declared("store_methods", SDK_TYPES, false);
}

/// Conveniences every SDK must offer that the core does not define, so no
/// other check would notice one going missing.
#[test]
fn every_sdk_declares_every_shared_helper() {
    assert_declared("sdk_helpers", SDK_HELPERS, true);
}
