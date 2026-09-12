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
        &[
            "packages/dotnet/DeRec.Library/src/Protocol/Stores.cs",
            "packages/dotnet/DeRec.Library/src/ContactMessage.cs",
        ],
    ),
    (
        "go",
        &[
            "packages/go/internal/native/store_types.go",
            "packages/go/derecpb/endpoints.go",
            "packages/go/protocol/stores.go",
        ],
    ),
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
    /// Go callable: a receiver method,
    /// `func (p *DeRecProtocol) SecretID() uint64`, or a package-level
    /// function, `func AdvertisedEndpoints(m EndpointAdvertiser)`.
    GoMethod,
    /// Anything Go can export under a name: a callable, or a declared type.
    ///
    /// Used for `sdk_helpers`, where a binding is free to express a shared
    /// convenience as whichever of the two reads best — a filter predicate is
    /// naturally a method, a transport adapter naturally a type — and the
    /// fixture's claim is only that the name is exported.
    GoExport,
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
        Shape::GoMethod => {
            text.contains(&format!(") {needle}(")) || text.contains(&format!("func {needle}("))
        }
        Shape::GoExport => {
            declared_in(text, needle, Shape::GoMethod) || text.contains(&format!("type {needle} "))
        }
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
///
/// That distinction is a property of the *SDK*, not of the section, so only
/// the TypeScript packages ever require all of their paths — see
/// [`requires_every_path`].
fn declared(paths: &[&str], needle: &str, shape: Shape, require_all: bool) -> bool {
    let mut hits = paths.iter().map(|p| declared_in(&read(p), needle, shape));
    if require_all {
        hits.all(|h| h)
    } else {
        hits.any(|h| h)
    }
}

/// Whether every path listed for `sdk` must declare the name, or just one.
///
/// Only the TypeScript packages split a surface into a declaration file and a
/// runtime file that must agree. Go and .NET list several files because a
/// surface is spread across them, so any one of them declaring the name is
/// enough — `Matches` lives beside the store types and `AdvertisedEndpoints`
/// beside the generated messages, and neither file has reason to hold both.
fn requires_every_path(sdk: &str) -> bool {
    matches!(sdk, "nodejs" | "web" | "react-native")
}

/// The declaration shape to require, per SDK, for a given section.
fn shape_for(sdk: &str, section: &str) -> Shape {
    match (sdk, section) {
        (_, "flow_params") => Shape::TypeName,
        ("go", "sdk_helpers") => Shape::GoExport,
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
            let all_paths = require_all && requires_every_path(sdk);
            if !declared(paths, &name, shape_for(sdk, section), all_paths) {
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

// ── prose vs core ──────────────────────────────────────────────────────────
//
// The checks above hold the SDKs to the core. These hold the *documentation*
// to it, because the two defects below shipped in 0.0.3 and were found by
// reading rather than by running anything:
//
// - The changelog described `Error::NoCommonTransport` as current behaviour in
//   two entries after the variant had been renamed to `NoUsableEndpoint`. The
//   trap is sharper than a typo: `NO_COMMON_TRANSPORT` is still the live
//   cross-binding error *code* for that error, so a consumer grepping the
//   TypeScript bindings finds the string and concludes the Rust is what is
//   wrong.
// - The deprecation wave named two removal versions, 0.0.5 and 0.1.0, purely
//   because the notes were written at different times.
//
// Both are mechanically detectable, and a changelog that is wrong once is a
// changelog a reader stops trusting in full.

/// Every error enum in the crate, mapped to its variant names.
///
/// Read from the sources rather than matched in Rust: these are fifteen enums
/// across nine modules, most of them not re-exported anywhere this test could
/// name them, and an exhaustive match on each would be more code than the
/// check it serves.
fn error_variants() -> std::collections::BTreeMap<String, BTreeSet<String>> {
    const SOURCES: &[&str] = &[
        "library/src/error.rs",
        "library/src/derec_message/error.rs",
        "library/src/transport/mod.rs",
        "library/src/protocol/error.rs",
        "library/src/protocol/types/secret/codec.rs",
        "library/src/protocol/handlers/restore.rs",
        "library/src/primitives/pairing/error.rs",
        "library/src/primitives/recovery/error.rs",
        "library/src/primitives/sharing/error.rs",
        "library/src/primitives/verification/error.rs",
        "library/src/primitives/discovery/error.rs",
        "library/src/primitives/unpairing/error.rs",
    ];

    let mut found: std::collections::BTreeMap<String, BTreeSet<String>> =
        std::collections::BTreeMap::new();

    for rel in SOURCES {
        let src = read(rel);
        let mut current: Option<String> = None;
        for line in src.lines() {
            if let Some(rest) = line.strip_prefix("pub enum ") {
                let name = rest.split([' ', '{', '<']).next().unwrap_or("").to_owned();
                current = (name == "Error" || name.ends_with("Error")).then_some(name);
                continue;
            }
            // An enum is a top-level item, so its body ends at the first
            // column-zero `}`. A struct variant's own closing brace is
            // indented, so it does not end the walk early.
            if line == "}" {
                current = None;
                continue;
            }
            // Variants are indented by four and capitalised. The leading
            // character test is what keeps a struct variant's fields — which
            // are indented by eight and lowercase — from being read as
            // variants of their own.
            if let Some(enum_name) = current.as_ref()
                && let Some(rest) = line.strip_prefix("    ")
                && rest.starts_with(|c: char| c.is_ascii_uppercase())
            {
                let variant = rest
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or("");
                if !variant.is_empty() {
                    found
                        .entry(enum_name.clone())
                        .or_default()
                        .insert(variant.to_owned());
                }
            }
        }
    }

    assert!(
        found.contains_key("Error"),
        "no `pub enum Error` was found — the variant walk is reading nothing, \
         which would make every check below pass vacuously"
    );
    found
}

/// Every `SomeError::Variant` the changelog names is a variant that exists.
///
/// The whole file is in scope: the crate has never been past 0.0.x, so every
/// entry in it describes the current surface.
///
/// A retired spelling is allowed only where it explains its own rename, which
/// is why the allowlist carries a `replaced_by` that has to appear in the same
/// paragraph. Without that clause this check would pass the defect it exists
/// for: the two entries that described `NoCommonTransport` as current
/// behaviour were wrong precisely because they named it *alone*.
#[test]
fn changelog_error_variants_resolve() {
    let known = error_variants();
    let retired: std::collections::BTreeMap<(String, String), String> = fixture()["documented_api"]
        ["retired_error_variants"]
        .as_array()
        .expect("documented_api.retired_error_variants is an array")
        .iter()
        .map(|e| {
            (
                (field(e, "enum"), field(e, "variant")),
                field(e, "replaced_by"),
            )
        })
        .collect();

    let changelog = read("CHANGELOG.md");
    let mut unresolved: BTreeSet<String> = BTreeSet::new();

    // Paragraph-scoped rather than line-scoped: the changelog is wrapped
    // prose, so a rename and the name it replaced routinely land on
    // neighbouring lines.
    for paragraph in paragraphs(&changelog) {
        for line in &paragraph.lines {
            for (owner, variant) in qualified_paths(line) {
                // `crate::Error::Foo` yields `crate::Error` too; only the
                // error enums are ours to check, and anything else on the line
                // is a module path this test has no opinion about.
                let Some(variants) = known.get(&owner) else {
                    continue;
                };
                if variants.contains(&variant) {
                    continue;
                }
                match retired.get(&(owner.clone(), variant.clone())) {
                    Some(replacement) if paragraph.names(replacement) => continue,
                    Some(replacement) => unresolved.insert(format!(
                        "CHANGELOG.md:{}: `{owner}::{variant}` is retired and this \
                         entry does not name `{replacement}`, so it reads as current",
                        paragraph.first_line
                    )),
                    None => unresolved.insert(format!(
                        "CHANGELOG.md:{}: `{owner}::{variant}` is not a variant of `{owner}`",
                        paragraph.first_line
                    )),
                };
            }
        }
    }

    assert!(
        unresolved.is_empty(),
        "the changelog names error variants that do not exist:\n  {}\n\n\
         Correct the entry, or — if it names a retired spelling deliberately, \
         to explain a rename — add it to `documented_api.retired_error_variants` \
         in api_surface.json with the reason and the replacement.",
        unresolved.into_iter().collect::<Vec<_>>().join("\n  ")
    );
}

/// A blank-line-delimited block, with the 1-based line number it starts at.
struct Paragraph<'a> {
    first_line: usize,
    lines: Vec<&'a str>,
}

impl Paragraph<'_> {
    /// Whether any line names `needle`. Equivalent to searching the joined
    /// text, since every name this test looks for is a single identifier and
    /// so cannot straddle a line break.
    fn names(&self, needle: &str) -> bool {
        self.lines.iter().any(|l| l.contains(needle))
    }
}

fn paragraphs(doc: &str) -> Vec<Paragraph<'_>> {
    let mut out: Vec<Paragraph<'_>> = Vec::new();
    let mut start = 0usize;
    let mut lines: Vec<&str> = Vec::new();

    for (i, line) in doc.lines().enumerate() {
        if line.trim().is_empty() {
            if !lines.is_empty() {
                out.push(Paragraph {
                    first_line: start + 1,
                    lines: std::mem::take(&mut lines),
                });
            }
            continue;
        }
        if lines.is_empty() {
            start = i;
        }
        lines.push(line);
    }
    if !lines.is_empty() {
        out.push(Paragraph {
            first_line: start + 1,
            lines,
        });
    }
    out
}

/// `Owner::Member` pairs on one line, with the owner's own path prefix stripped.
fn qualified_paths(line: &str) -> Vec<(String, String)> {
    fn ident_before(s: &str) -> &str {
        let end = s.len();
        let start = s
            .rfind(|c: char| !c.is_alphanumeric() && c != '_')
            .map_or(0, |i| i + 1);
        &s[start..end]
    }
    fn ident_after(s: &str) -> &str {
        let end = s
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(s.len());
        &s[..end]
    }

    let mut out = Vec::new();
    let mut rest = line;
    let mut consumed = 0usize;
    while let Some(at) = rest.find("::") {
        let owner = ident_before(&line[..consumed + at]);
        let member = ident_after(&rest[at + 2..]);
        if !owner.is_empty() && !member.is_empty() {
            out.push((owner.to_owned(), member.to_owned()));
        }
        consumed += at + 2;
        rest = &line[consumed..];
    }
    out
}

/// Every deprecation in the crate names the wave's single removal version.
///
/// Split horizons are what this catches. They are never a decision — they are
/// what happens when two notes are written weeks apart — and a consumer
/// planning one migration reads them as two.
#[test]
fn every_deprecation_shares_the_release_horizon() {
    let horizon = &fixture()["documented_api"]["deprecation_horizon"];
    let since = horizon["since"].as_str().expect("horizon names a `since`");
    let removed_at = horizon["removed_at"]
        .as_str()
        .expect("horizon names a `removed_at`");
    let exceptions: BTreeSet<String> = horizon["exceptions"]
        .as_array()
        .expect("horizon.exceptions is an array")
        .iter()
        .map(|e| field(e, "symbol"))
        .collect();

    let mut wrong: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (rel, symbol, attr) in deprecations() {
        checked += 1;
        if exceptions.contains(&symbol) {
            continue;
        }
        if !attr.contains(&format!("since = \"{since}\"")) {
            wrong.push(format!("{rel}: `{symbol}` is not `since = \"{since}\"`"));
        }
        // Matched on the note's text because `deprecated` has no field for a
        // removal version; the note is the only place it can be stated, and
        // it is the only place a consumer will read it.
        if !attr.contains(&format!("removed at {removed_at}")) {
            wrong.push(format!(
                "{rel}: `{symbol}` does not say `removed at {removed_at}`"
            ));
        }
    }

    assert!(
        checked > 0,
        "no `#[deprecated]` attributes were found — the walk is reading nothing"
    );
    assert!(
        wrong.is_empty(),
        "these deprecations disagree with the wave's horizon \
         (since {since}, removed at {removed_at}):\n  {}\n\n\
         Align the note, or add the symbol to \
         `documented_api.deprecation_horizon.exceptions` with the reason it \
         needs longer.",
        wrong.join("\n  ")
    );
}

/// Every deprecated symbol is named in the changelog.
///
/// A deprecation the release notes do not mention reaches a consumer as a
/// build warning with no context and no migration.
#[test]
fn changelog_names_every_deprecated_symbol() {
    let changelog = read("CHANGELOG.md");
    let unmentioned: Vec<String> = deprecations()
        .into_iter()
        .filter(|(_, symbol, _)| !changelog.contains(symbol.as_str()))
        .map(|(rel, symbol, _)| format!("{rel}: `{symbol}`"))
        .collect();

    assert!(
        unmentioned.is_empty(),
        "these symbols are deprecated in the source and absent from the changelog:\n  {}",
        unmentioned.join("\n  ")
    );
}

/// Every `#[deprecated]` in the library, as (file, deprecated symbol, attribute
/// text).
fn deprecations() -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for rel in rust_sources("library/src") {
        let src = read(&rel);
        let mut lines = src.lines().peekable();
        while let Some(line) = lines.next() {
            if !line.trim_start().starts_with("#[deprecated") {
                continue;
            }
            // The attribute spans several lines and ends at the first `)]`.
            let mut attr = line.to_owned();
            while !attr.contains(")]") {
                match lines.next() {
                    Some(l) => {
                        attr.push(' ');
                        attr.push_str(l.trim());
                    }
                    None => break,
                }
            }
            // The item follows, after any remaining attributes and docs.
            let mut symbol = String::new();
            for l in lines.by_ref() {
                let t = l.trim_start();
                if t.is_empty() || t.starts_with("#[") || t.starts_with("//") {
                    continue;
                }
                symbol = item_name(t);
                break;
            }
            if !symbol.is_empty() {
                out.push((rel.clone(), symbol, attr));
            }
        }
    }
    out
}

/// The name a declaration introduces: the token after `fn`, or the leading
/// identifier for an enum variant.
fn item_name(decl: &str) -> String {
    let head = match decl.split_once("fn ") {
        Some((_, rest)) => rest,
        None => decl,
    };
    head.split(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or("")
        .to_owned()
}

/// Every `.rs` file under `rel`, repository-relative.
fn rust_sources(rel: &str) -> Vec<String> {
    let root = repo_root();
    let mut out = Vec::new();
    let mut stack = vec![root.join(rel)];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let relative = path
                    .strip_prefix(&root)
                    .expect("walked from the repository root");
                out.push(relative.to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    out
}
