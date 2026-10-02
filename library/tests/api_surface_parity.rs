// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Guards the five SDK API surfaces against drifting behind the core.
//!
//! [`enum_fixture`](../enum_fixture.rs) does this for enum *members* and
//! [`dto_field_parity`](../dto_field_parity.rs) for message *fields*. This
//! file covers the API itself — the protocol methods, the builder, the flow
//! parameter and store record types, the store interfaces, the primitives and
//! the shared helpers.
//!
//! `fixtures/api_surface.json` links each SDK's spelling to the core's. The
//! checks run in three layers:
//!
//! - **Core vs fixture.** The expected surface is derived from the Rust
//!   source: the `pub fn`s of `DeRecProtocol` and `DeRecProtocolBuilder`, the
//!   `pub fn`s of the primitives modules, the store traits with their
//!   parameters, and the structs every SDK record mirrors. Anything public in
//!   Rust that the fixture does not name fails, and so does a fixture entry the
//!   core no longer defines. `DeRecFlow` is matched exhaustively, so a new
//!   flow fails to *compile* here.
//! - **Core vs exports.** Every Rust public method must reach the SDKs through
//!   an FFI export, a WASM export, or an allow-list entry that says why not;
//!   and every FFI and WASM export must be named somewhere, so none is
//!   orphaned.
//! - **Fixture vs SDKs.** Each SDK declaration is read as a *block* — the
//!   interface, class, record, struct or object literal that declares it — and
//!   its members are compared as a set, both ways: a member missing from an
//!   SDK fails, and so does one an SDK declares that the core does not. Where
//!   parameters and fields have names, those are compared too, modulo casing.
//!   The store bridges are also read, so a member every SDK declares but no
//!   bridge ever calls fails as well.
//!
//! Intentional differences — lifecycle naming, a type a language expresses
//! inline, a decision still open — are listed in allow-lists below, each with
//! its reason. An allow-list entry that no longer matches anything fails, so
//! the lists cannot outlive what they excuse.

#[path = "support/decl.rs"]
mod decl;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use decl::{Kind, Lang, Member, norm};
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

fn opt_field(entry: &serde_json::Value, key: &str) -> Option<String> {
    entry[key].as_str().map(str::to_owned)
}

fn str_list(entry: &serde_json::Value, key: &str) -> Vec<String> {
    entry[key]
        .as_array()
        .unwrap_or_else(|| panic!("fixture entry {entry} has no `{key}` list"))
        .iter()
        .map(|v| v.as_str().expect("list entries are strings").to_owned())
        .collect()
}

/// Every file under `rel` (repository-relative) with extension `ext`,
/// skipping Go test files.
fn files_under(rel: &str, ext: &str) -> Vec<String> {
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
            } else if path.extension().is_some_and(|e| e == ext)
                && !path.to_string_lossy().ends_with("_test.go")
            {
                let relative = path.strip_prefix(&root).expect("walked from the root");
                out.push(relative.to_string_lossy().into_owned());
            }
        }
    }
    out.sort();
    out
}

/// Non-test Go files directly in one package directory.
fn go_package(rel: &str) -> Vec<(String, String)> {
    let root = repo_root();
    let mut out: Vec<(String, String)> = std::fs::read_dir(root.join(rel))
        .unwrap_or_else(|e| panic!("reading {rel}: {e}"))
        .map(|e| e.expect("a readable directory entry").path())
        .filter(|p| {
            p.extension().is_some_and(|e| e == "go") && !p.to_string_lossy().ends_with("_test.go")
        })
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .expect("under root")
                .to_string_lossy()
                .into_owned();
            let src = read(&rel);
            (rel, src)
        })
        .collect();
    out.sort();
    out
}

fn load(paths: &[&str]) -> Vec<(String, String)> {
    paths.iter().map(|p| ((*p).to_owned(), read(p))).collect()
}

// ── allow-lists ────────────────────────────────────────────────────────────
//
// Each entry is (sdk, owner, member, reason). `sdk` is one of `rust`, `ffi`,
// `wasm`, `dotnet`, `go`, `nodejs`, `web`, `react-native`. A reason starting
// with "pending decision:" records a real gap the owner has yet to decide on.

type Allow = (&'static str, &'static str, &'static str, &'static str);

/// Members an SDK class or object declares beyond the core's surface.
const EXTRA_MEMBERS: &[Allow] = &[
    (
        "dotnet",
        "DeRecProtocolBuilder",
        "GenerateReplicaId",
        "the replica id generator sdk_helper; .NET hangs it on the builder that consumes it",
    ),
    (
        "react-native",
        "DeRecProtocol",
        "fromHost",
        "the factory DeRecProtocolBuilder.build() calls; TypeScript has no package-private visibility",
    ),
];

/// Fields an SDK record declares beyond, or omits from, the Rust struct it
/// mirrors. `member` is the field's normalized name, or `rust=sdk` for a field
/// the SDK declares under another name.
const RECORD_FIELDS: &[Allow] = &[
    (
        "dotnet",
        "Timeouts",
        "inboundmessagesecs=inboundmessage",
        "a TimeSpan carries its unit, so the name drops `Secs`; the wire DTO converts to seconds",
    ),
    (
        "dotnet",
        "Timeouts",
        "sharingroundsecs=sharinground",
        "a TimeSpan carries its unit, so the name drops `Secs`; the wire DTO converts to seconds",
    ),
    (
        "dotnet",
        "Timeouts",
        "unpairacksecs=unpairack",
        "a TimeSpan carries its unit, so the name drops `Secs`; the wire DTO converts to seconds",
    ),
];

/// Records an SDK does not declare as a named type.
const UNNAMED_RECORDS: &[Allow] = &[
    (
        "nodejs",
        "RemoveExpiredChannelsPolicy",
        "",
        "declared inline as the type of Timeouts.expired_channels",
    ),
    (
        "web",
        "RemoveExpiredChannelsPolicy",
        "",
        "declared inline as the type of Timeouts.expired_channels",
    ),
    (
        "react-native",
        "RemoveExpiredChannelsPolicy",
        "",
        "declared inline as the type of Timeouts.expired_channels",
    ),
];

/// Rust public items that reach no SDK through the export it would need.
const UNEXPORTED: &[Allow] = &[
    (
        "rust",
        "DeRecProtocol",
        "new",
        "the raw constructor; every SDK constructs through the builder, whose FFI form is derec_protocol_new",
    ),
    (
        "ffi",
        "DeRecProtocol",
        "secret_id",
        "each FFI SDK keeps the secret_id it passed to derec_protocol_new; WASM exports it",
    ),
];

/// FFI and WASM exports that back no fixture entry.
const INFRASTRUCTURE_EXPORTS: &[Allow] = &[
    (
        "ffi",
        "",
        "derec_free_buffer",
        "releases buffers the library hands out",
    ),
    (
        "ffi",
        "",
        "derec_free_error",
        "releases error values the library hands out",
    ),
    (
        "ffi",
        "",
        "derec_free_string",
        "releases strings the library hands out",
    ),
    (
        "ffi",
        "",
        "derec_protocol_new",
        "lifecycle: the builder's build()",
    ),
    (
        "ffi",
        "",
        "derec_protocol_free",
        "lifecycle: .NET Dispose, Go Close, React Native free",
    ),
    (
        "ffi",
        "",
        "derec_error_code_name",
        "maps error codes to the names every SDK reports",
    ),
    (
        "ffi",
        "",
        "derec_error_category_name",
        "maps error categories to the names every SDK reports",
    ),
    (
        "ffi",
        "",
        "derec_encode_message_json",
        "message JSON codec the FFI SDKs marshal through",
    ),
    (
        "ffi",
        "",
        "derec_decode_message_json",
        "message JSON codec the FFI SDKs marshal through",
    ),
    (
        "ffi",
        "",
        "derec_transport_protocol_name",
        "protocol name codec the FFI SDKs marshal through",
    ),
    (
        "ffi",
        "",
        "derec_transport_protocol_discriminant",
        "protocol name codec the FFI SDKs marshal through",
    ),
    (
        "ffi",
        "",
        "derec_transport_endpoints_json",
        "decodes a transport callback's endpoint buffer for FFI SDKs",
    ),
    ("wasm", "", "wasm_start", "module initialisation hook"),
];

/// Store methods whose parameters an SDK spells differently from the
/// fixture's `params`, as (fixture key, interface, member, params, reason).
/// The override is still compared exactly: it pins the SDK's list rather than
/// skipping it.
type ParamOverride = (
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
    &'static str,
);

const STORE_PARAMS: &[ParamOverride] = &[
    (
        "ts",
        "ChannelStore",
        "save",
        &["secret_id", "channel_id", "replica_id", "bytes"],
        "the record crosses as opaque JSON bytes, so the key it is stored under travels beside it",
    ),
    (
        "ts",
        "SecretStore",
        "save",
        &["secret_id", "channel_id", "kind", "value"],
        "the value crosses as raw bytes, so the kind the core reads off the SecretValue variant travels beside it",
    ),
    (
        "ts",
        "StateStore",
        "save",
        &["secret_id", "item_json"],
        "the item crosses as the opaque JSON the core wrote, and the name says so",
    ),
    (
        "ts",
        "StateStore",
        "load",
        &["secret_id", "key_json"],
        "the key crosses as the opaque JSON the core wrote, and the name says so",
    ),
    (
        "ts",
        "StateStore",
        "remove",
        &["secret_id", "key_json"],
        "the key crosses as the opaque JSON the core wrote, and the name says so",
    ),
];

thread_local! {
    /// Allow-list entries consulted during a test, so unused ones can fail.
    static USED: RefCell<BTreeSet<(String, String, String)>> = const { RefCell::new(BTreeSet::new()) };
}

fn allowed(list: &[Allow], sdk: &str, owner: &str, member: &str) -> bool {
    let hit = list
        .iter()
        .any(|(s, o, m, _)| *s == sdk && *o == owner && (*m == member || m.is_empty()));
    if hit {
        USED.with(|u| {
            u.borrow_mut()
                .insert((sdk.to_owned(), owner.to_owned(), member.to_owned()))
        });
    }
    hit
}

/// Fail on allow-list entries a test consulted none of.
fn assert_all_used(name: &str, list: &[Allow]) {
    let used = USED.with(|u| u.borrow().clone());
    let stale: Vec<String> = list
        .iter()
        .filter(|(s, o, m, _)| {
            !used
                .iter()
                .any(|(us, uo, um)| us == s && uo == o && (um == m || m.is_empty()))
        })
        .map(|(s, o, m, _)| format!("({s}, {o}, {m})"))
        .collect();
    assert!(
        stale.is_empty(),
        "{name} has entries nothing matches any more — remove them: {stale:?}"
    );
}

fn fail_if(problems: Vec<String>, what: &str) {
    assert!(
        problems.is_empty(),
        "{what}:\n  {}\n\nUpdate the SDK(s) named, or — if the core changed — \
         library/tests/fixtures/api_surface.json. An intentional difference goes \
         in an allow-list in library/tests/api_surface_parity.rs with its reason.",
        problems.join("\n  ")
    );
}

// ── Rust source readers ────────────────────────────────────────────────────

/// Public methods of every inherent `impl` block of `ty` in `files`.
fn rust_impl_methods(files: &[String], ty: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for rel in files {
        let src = read(rel);
        let masked = decl::mask(&src, Lang::Rust);
        for at in decl::word_positions(&masked, "impl") {
            let Some(open) = masked[at..].find('{').map(|i| at + i) else {
                continue;
            };
            let header = &masked[at..open];
            // `impl<..> Ty<..>` and `impl Ty`, never `impl Trait for Ty`.
            if !decl::word_positions(header, "for").is_empty() {
                continue;
            }
            let names_ty = decl::word_positions(header, ty).iter().any(|&p| {
                let rest = header[p + ty.len()..].trim_start();
                rest.starts_with('<') || rest.is_empty() || rest.starts_with("where")
            });
            if !names_ty {
                continue;
            }
            let Some(close) = decl::matching(&masked, open) else {
                continue;
            };
            for m in decl::members(&src, &masked, open + 1..close, Lang::Rust, ty, false, false) {
                if m.public && m.kind == Kind::Method {
                    out.insert(m.name);
                }
            }
        }
    }
    out
}

/// Field names of `struct name` in a Rust file.
fn rust_struct_fields(rel: &str, name: &str) -> Vec<String> {
    let src = read(rel);
    let masked = decl::mask(&src, Lang::Rust);
    let block = decl::find_block(&masked, &["struct"], name)
        .unwrap_or_else(|| panic!("{rel} declares no `struct {name}`"));
    decl::members(&src, &masked, block.body, Lang::Rust, name, false, true)
        .into_iter()
        .filter(|m| m.kind == Kind::Field)
        .map(|m| m.name)
        .collect()
}

/// Methods of `trait name` in `traits.rs`, with their parameter names.
fn rust_trait(name: &str) -> BTreeMap<String, Vec<String>> {
    let src = read("library/src/protocol/traits.rs");
    let masked = decl::mask(&src, Lang::Rust);
    let block = decl::find_block(&masked, &["trait"], name)
        .unwrap_or_else(|| panic!("traits.rs declares no `trait {name}`"));
    decl::members(&src, &masked, block.body, Lang::Rust, name, true, false)
        .into_iter()
        .filter(|m| m.kind == Kind::Method)
        .map(|m| (m.name, m.params))
        .collect()
}

/// Every `extern "C" fn` the FFI layer exports.
fn ffi_exports() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for rel in files_under("library/src/interop/ffi", "rs") {
        let src = read(&rel);
        let masked = decl::mask(&src, Lang::Rust);
        for (at, _) in src.match_indices("extern \"C\" fn ") {
            if !masked[at..].starts_with("extern") {
                continue;
            }
            let rest = &src[at + "extern \"C\" fn ".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            // Only exported symbols: the callback signatures in the store
            // structs are `extern "C" fn(` with no name.
            let line_start = src[..at].rfind('\n').map_or(0, |i| i + 1);
            if !name.is_empty() && src[line_start..at].contains("pub") {
                out.insert(name);
            }
        }
    }
    out
}

/// Free functions the WASM layer exports, by their JavaScript name.
fn wasm_exports() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for rel in files_under("library/src/interop/wasm", "rs") {
        let src = read(&rel);
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some(rest) = line
                .strip_prefix("pub fn ")
                .or_else(|| line.strip_prefix("pub async fn "))
            else {
                continue;
            };
            let fn_name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            // The attribute block directly above names the export.
            let mut j = i;
            let mut exported = None;
            while j > 0 {
                j -= 1;
                let l = lines[j].trim_start();
                if l.starts_with("///") || l.starts_with("//") {
                    continue;
                }
                if !l.starts_with("#[") {
                    break;
                }
                if l.starts_with("#[wasm_bindgen") {
                    exported = Some(
                        l.split("js_name")
                            .nth(1)
                            .map(|r| {
                                r.trim_start_matches([' ', '='])
                                    .trim_start_matches('"')
                                    .split(['"', ')', ','])
                                    .next()
                                    .unwrap_or("")
                                    .trim()
                                    .to_owned()
                            })
                            .unwrap_or_else(|| fn_name.clone()),
                    );
                }
            }
            if let Some(name) = exported {
                out.insert(name);
            }
        }
    }
    out
}

/// Methods of a WASM-exported Rust type, by their Rust name.
fn wasm_methods(ty: &str) -> BTreeSet<String> {
    rust_impl_methods(&files_under("library/src/interop/wasm", "rs"), ty)
}

// ── SDK source readers ─────────────────────────────────────────────────────

const SDKS: &[&str] = &["dotnet", "go", "nodejs", "web", "react-native"];

/// The fixture key holding an SDK's spelling.
fn key(sdk: &str) -> &'static str {
    match sdk {
        "dotnet" => "dotnet",
        "go" => "go",
        _ => "ts",
    }
}

/// Files that declare an SDK's public types.
fn type_files(sdk: &str) -> Vec<(String, String)> {
    match sdk {
        "dotnet" => load(&[
            "packages/dotnet/DeRec.Library/src/Protocol/Flows.cs",
            "packages/dotnet/DeRec.Library/src/Protocol/Stores.cs",
            "packages/dotnet/DeRec.Library/src/Protocol/DeRecProtocol.cs",
            "packages/dotnet/DeRec.Library/src/Protocol/DeRecProtocolBuilder.cs",
            "packages/dotnet/DeRec.Library/src/Protocol/ParameterRange.cs",
            "packages/dotnet/DeRec.Library/src/TransportProtocol.cs",
            "packages/dotnet/DeRec.Library/src/ContactMessage.cs",
            "packages/dotnet/DeRec.Library/src/ProtocolVersion.cs",
        ]),
        "go" => {
            let mut v = go_package("packages/go/protocol");
            v.extend(go_package("packages/go/internal/native"));
            v.extend(go_package("packages/go/derec"));
            v.extend(load(&["packages/go/derecpb/endpoints.go"]));
            v
        }
        "nodejs" => load(&["packages/nodejs/index.d.ts"]),
        "web" => load(&["packages/web/index.d.ts"]),
        "react-native" => load(&[
            "packages/react-native/src/types.ts",
            "packages/react-native/src/protocol.ts",
        ]),
        other => panic!("unknown sdk {other}"),
    }
}

/// The members a type declares in an SDK: interface and class members, a C#
/// record's positional parameters and properties, a Go struct's fields or
/// interface's methods. `None` when the SDK declares no such type.
fn sdk_type(sdk: &str, name: &str, files: &[(String, String)]) -> Option<Vec<Member>> {
    match sdk {
        "go" => {
            if let Some(fields) = decl::go_fields(files, name) {
                return Some(
                    fields
                        .into_iter()
                        .map(|f| Member {
                            name: f,
                            kind: Kind::Field,
                            params: Vec::new(),
                            public: true,
                            is_static: false,
                            text: String::new(),
                        })
                        .collect(),
                );
            }
            let (src, masked, block) = decl::go_type_block(files, name, "interface")?;
            Some(decl::members(
                &src,
                &masked,
                block.body,
                Lang::Go,
                name,
                true,
                false,
            ))
        }
        "dotnet" => {
            for (_, src) in files {
                let masked = decl::mask(src, Lang::CSharp);
                let Some(block) =
                    decl::find_block(&masked, &["interface", "class", "record", "struct"], name)
                else {
                    continue;
                };
                let interface = block.header.split_whitespace().any(|w| w == "interface");
                let mut out = Vec::new();
                if let Some(params) = block.params.clone() {
                    for p in decl::param_names(&masked, params, Lang::CSharp) {
                        out.push(Member {
                            name: p,
                            kind: Kind::Field,
                            params: Vec::new(),
                            public: true,
                            is_static: false,
                            text: String::new(),
                        });
                    }
                }
                out.extend(decl::members(
                    src,
                    &masked,
                    block.body,
                    Lang::CSharp,
                    name,
                    interface,
                    false,
                ));
                return Some(out);
            }
            None
        }
        _ => {
            for (_, src) in files {
                let masked = decl::mask(src, Lang::Ts);
                // `type X = Record<string, never>` declares a type with no
                // members.
                for at in decl::word_positions(&masked, "type") {
                    let rest = masked[at + 4..].trim_start();
                    if let Some(r) = rest.strip_prefix(name)
                        && r.trim_start().starts_with('=')
                        && r.trim_start()[1..]
                            .trim_start()
                            .starts_with("Record<string, never>")
                    {
                        return Some(Vec::new());
                    }
                }
                if let Some(block) = decl::find_block(&masked, &["interface", "class"], name) {
                    return Some(decl::members(
                        src,
                        &masked,
                        block.body,
                        Lang::Ts,
                        name,
                        true,
                        false,
                    ));
                }
            }
            None
        }
    }
}

/// Public, non-constructor member names.
fn public_names(members: &[Member]) -> BTreeSet<String> {
    members
        .iter()
        .filter(|m| m.public && m.kind != Kind::Constructor)
        .map(|m| m.name.clone())
        .collect()
}

/// Compare an SDK's declared member names against the expected set, both
/// ways, consulting `EXTRA_MEMBERS` for declared extras.
fn compare_members(
    problems: &mut Vec<String>,
    sdk: &str,
    owner: &str,
    declared: &BTreeSet<String>,
    expected: &BTreeSet<String>,
) {
    for m in expected.difference(declared) {
        problems.push(format!("{sdk}: {owner} does not declare `{m}`"));
    }
    for m in declared.difference(expected) {
        if !allowed(EXTRA_MEMBERS, sdk, owner, m) {
            problems.push(format!(
                "{sdk}: {owner} declares `{m}`, which the core's surface does not have"
            ));
        }
    }
}

/// Lifecycle members, spelled per language: Rust `Drop` is .NET `Dispose`,
/// Go `Close` and the JavaScript `free` / `Symbol.dispose` pair. A builder
/// that holds no native handle has none.
fn lifecycle(sdk: &str, class: &str) -> &'static [&'static str] {
    match (sdk, class) {
        ("dotnet", "DeRecProtocol") => &["Dispose"],
        ("go", "DeRecProtocol") => &["Close"],
        ("nodejs" | "web" | "react-native", "DeRecProtocol") => &["free", "[Symbol.dispose]"],
        // wasm-bindgen gives the builder a native handle too.
        ("nodejs" | "web", "DeRecProtocolBuilder") => &["free", "[Symbol.dispose]"],
        _ => &[],
    }
}

/// The class declaring the protocol or builder surface in a TypeScript SDK.
fn ts_class(sdk: &str, class: &str) -> Vec<Member> {
    let rel = match sdk {
        "nodejs" => "packages/nodejs/index.d.ts",
        "web" => "packages/web/index.d.ts",
        _ => "packages/react-native/src/protocol.ts",
    };
    let src = read(rel);
    let masked = decl::mask(&src, Lang::Ts);
    let block = decl::find_block(&masked, &["class"], class)
        .unwrap_or_else(|| panic!("{rel} declares no class {class}"));
    decl::members(&src, &masked, block.body, Lang::Ts, class, true, false)
}

fn dotnet_class(rel: &str, class: &str) -> Vec<Member> {
    let src = read(rel);
    let masked = decl::mask(&src, Lang::CSharp);
    let block = decl::find_block(&masked, &["class"], class)
        .unwrap_or_else(|| panic!("{rel} declares no class {class}"));
    decl::members(&src, &masked, block.body, Lang::CSharp, class, false, false)
}

// ── core vs fixture ────────────────────────────────────────────────────────

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

    // Each flow's params type is a record whose fields are compared below.
    let records: BTreeSet<String> = entries("records")
        .iter()
        .map(|e| field(e, "what"))
        .collect();
    for e in entries("flow_params") {
        let ty = field(&e, "dotnet");
        assert!(
            records.contains(&ty),
            "flow_params names `{ty}` but `records` has no entry comparing its fields"
        );
    }
}

/// Every public method of `DeRecProtocol` is named in the fixture and reaches
/// the SDKs through both an FFI and a WASM export.
#[test]
fn rust_protocol_methods_are_named_and_exported() {
    let rust = rust_impl_methods(&files_under("library/src/protocol", "rs"), "DeRecProtocol");
    assert!(
        rust.contains("process") && rust.contains("start"),
        "the DeRecProtocol method walk found {rust:?} — it is reading nothing"
    );
    let named: BTreeSet<String> = entries("protocol_methods")
        .iter()
        .map(|e| field(e, "rust"))
        .collect();
    let ffi = ffi_exports();
    let wasm = wasm_methods("DeRecProtocolWasm");

    let mut problems = Vec::new();
    for m in &rust {
        if allowed(UNEXPORTED, "rust", "DeRecProtocol", m) {
            continue;
        }
        if !named.contains(m) {
            problems.push(format!(
                "DeRecProtocol::{m} is public and api_surface.json does not name it"
            ));
        }
        if !ffi.contains(&format!("derec_protocol_{m}"))
            && !allowed(UNEXPORTED, "ffi", "DeRecProtocol", m)
        {
            problems.push(format!(
                "DeRecProtocol::{m} has no FFI export `derec_protocol_{m}`"
            ));
        }
        if !wasm.contains(m) && !allowed(UNEXPORTED, "wasm", "DeRecProtocol", m) {
            problems.push(format!(
                "DeRecProtocol::{m} has no method on the WASM DeRecProtocolWasm"
            ));
        }
    }
    for m in named.difference(&rust) {
        problems.push(format!(
            "api_surface.json names DeRecProtocol::{m}, which the core no longer defines"
        ));
    }
    for m in wasm.difference(&rust) {
        problems.push(format!(
            "DeRecProtocolWasm::{m} exports a method DeRecProtocol does not have"
        ));
    }
    fail_if(
        problems,
        "DeRecProtocol's public surface has drifted from its exports",
    );
}

/// Every `derec_protocol_*` export is named in the fixture.
///
/// The generated header is checked too, because it is what the React Native
/// binding compiles against: a Rust export missing from it is a stale header.
#[test]
fn fixture_covers_every_ffi_protocol_export() {
    // Expressed as a constructor and a disposer in each SDK, and the protocol
    // version helper, rather than as methods.
    const NOT_METHODS: &[&str] = &["new", "free", "version"];

    let header = read("packages/react-native/cpp/derec_ffi.h");
    let mut in_header: BTreeSet<String> = BTreeSet::new();
    for tok in header.split(|c: char| !c.is_alphanumeric() && c != '_') {
        if let Some(rest) = tok.strip_prefix("derec_protocol_")
            && !rest.is_empty()
        {
            in_header.insert(rest.to_owned());
        }
    }
    let exported: BTreeSet<String> = ffi_exports()
        .iter()
        .filter_map(|e| e.strip_prefix("derec_protocol_").map(str::to_owned))
        .collect();
    assert_eq!(
        exported.difference(&in_header).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "the FFI exports these and derec_ffi.h does not declare them; regenerate the header"
    );
    let named: BTreeSet<String> = entries("protocol_methods")
        .iter()
        .map(|e| field(e, "rust"))
        .collect();

    let missing: Vec<&String> = exported
        .iter()
        .filter(|e| !NOT_METHODS.contains(&e.as_str()) && !named.contains(*e))
        .collect();
    assert!(
        missing.is_empty(),
        "the FFI exports these and api_surface.json does not name them: {missing:?}\n\
         Add a row with each SDK's spelling, then update the SDKs until the \
         parity tests pass."
    );
}

/// Every field an application can set through the FFI config is named in the
/// fixture.
#[test]
fn fixture_covers_every_config_option() {
    let fields = rust_struct_fields(
        "library/src/interop/ffi/protocol/handle/mod.rs",
        "ProtocolConfig",
    );

    // Taken as the builder's constructor argument in every SDK rather than as
    // a setter, so it has no `builder_options` row.
    const CONSTRUCTOR_ARGS: &[&str] = &["secret_id"];

    let named: BTreeSet<String> = entries("builder_options")
        .iter()
        .map(|e| field(e, "rust"))
        .chain(CONSTRUCTOR_ARGS.iter().map(|s| (*s).to_owned()))
        .collect();
    let fields: BTreeSet<String> = fields.into_iter().collect();
    assert!(
        fields.contains("threshold"),
        "ProtocolConfig walk found {fields:?}"
    );
    assert_eq!(
        fields.difference(&named).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "ProtocolConfig has these fields and api_surface.json does not name them"
    );
    assert_eq!(
        named.difference(&fields).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "api_surface.json names builder options ProtocolConfig no longer carries"
    );
}

/// Every public `DeRecProtocolBuilder` method is named in the fixture, and the
/// WASM builder exports exactly the same set.
#[test]
fn rust_builder_methods_are_named_and_exported() {
    let rust = rust_impl_methods(
        &["library/src/protocol/builder.rs".to_owned()],
        "DeRecProtocolBuilder",
    );
    assert!(rust.contains("build"), "the builder walk found {rust:?}");
    let options: BTreeSet<String> = entries("builder_options")
        .iter()
        .map(|e| format!("with_{}", field(e, "rust")))
        .collect();
    let wiring: BTreeSet<String> = entries("builder_wiring")
        .iter()
        .map(|e| field(e, "rust"))
        .collect();
    let lifecycle: BTreeSet<String> = ["new", "build"].iter().map(|s| (*s).to_owned()).collect();
    let named: BTreeSet<String> = options.union(&wiring).cloned().chain(lifecycle).collect();

    let mut problems = Vec::new();
    for m in rust.difference(&named) {
        problems.push(format!(
            "DeRecProtocolBuilder::{m} is public and api_surface.json does not name it"
        ));
    }
    for m in named.difference(&rust) {
        problems.push(format!(
            "api_surface.json names DeRecProtocolBuilder::{m}, which the core does not define"
        ));
    }
    let wasm = wasm_methods("DeRecProtocolBuilderWasm");
    for m in rust.symmetric_difference(&wasm) {
        problems.push(format!(
            "DeRecProtocolBuilder::{m} is in {} only — the WASM builder must mirror the core's",
            if rust.contains(m) {
                "the core"
            } else {
                "the WASM builder"
            }
        ));
    }
    // The FFI builder takes options as ProtocolConfig fields (checked above)
    // and stores as callback tables on derec_protocol_new.
    let handle = read("library/src/interop/ffi/protocol/handle/mod.rs");
    for w in &wiring {
        let cb = format!("{}_cb", w.trim_start_matches("with_"));
        if !handle.contains(&format!("{cb}: *const")) {
            problems.push(format!(
                "derec_protocol_new takes no `{cb}` for DeRecProtocolBuilder::{w}"
            ));
        }
    }
    fail_if(
        problems,
        "DeRecProtocolBuilder's public surface has drifted",
    );
}

/// Every store trait, method and parameter is named in the fixture.
#[test]
fn fixture_matches_every_store_trait() {
    let src = read("library/src/protocol/traits.rs");
    let traits: BTreeSet<String> = src
        .lines()
        .filter_map(|l| l.strip_prefix("pub trait "))
        .map(|r| {
            r.split([' ', ':', '{', '<'])
                .next()
                .unwrap_or("")
                .to_owned()
        })
        .filter(|n| n.starts_with("DeRec"))
        .collect();
    let stores = entries("stores");
    let named: BTreeSet<String> = stores.iter().map(|s| field(s, "trait")).collect();
    let mut problems = Vec::new();
    for t in traits.symmetric_difference(&named) {
        problems.push(format!(
            "store trait `{t}` is in {} only",
            if traits.contains(t) {
                "traits.rs"
            } else {
                "api_surface.json"
            }
        ));
    }
    for s in &stores {
        let t = field(s, "trait");
        if !traits.contains(&t) {
            continue;
        }
        let rust = rust_trait(&t);
        let methods = s["methods"].as_array().expect("stores[].methods");
        let in_fixture: BTreeSet<String> = methods.iter().map(|m| field(m, "rust")).collect();
        let in_rust: BTreeSet<String> = rust.keys().cloned().collect();
        for m in in_rust.symmetric_difference(&in_fixture) {
            problems.push(format!(
                "{t}::{m} is in {} only",
                if in_rust.contains(m) {
                    "traits.rs"
                } else {
                    "api_surface.json"
                }
            ));
        }
        for m in methods {
            let name = field(m, "rust");
            if let Some(params) = rust.get(&name) {
                let want = str_list(m, "rust_params");
                if *params != want {
                    problems.push(format!(
                        "{t}::{name} takes {params:?} in traits.rs; api_surface.json records {want:?}"
                    ));
                }
            }
        }
    }
    fail_if(
        problems,
        "the store traits have drifted from api_surface.json",
    );
}

/// Every public primitive is named in the fixture with the FFI and WASM
/// exports that carry it, and both exports exist.
#[test]
fn rust_primitives_are_named_and_exported() {
    let mut rust: BTreeSet<String> = BTreeSet::new();
    for rel in files_under("library/src/primitives", "rs") {
        let module = rel
            .trim_start_matches("library/src/")
            .trim_end_matches(".rs")
            .trim_end_matches("/mod")
            .replace('/', "::");
        for line in read(&rel).lines() {
            if let Some(rest) = line
                .strip_prefix("pub fn ")
                .or_else(|| line.strip_prefix("pub async fn "))
            {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                rust.insert(format!("{module}::{name}"));
            }
        }
    }
    assert!(rust.len() > 20, "the primitives walk found {rust:?}");

    let prims = entries("primitives");
    let named: BTreeSet<String> = prims.iter().map(|p| field(p, "rust")).collect();
    let ffi = ffi_exports();
    let wasm = wasm_exports();
    let mut problems = Vec::new();
    for p in rust.difference(&named) {
        if !allowed(UNEXPORTED, "rust", "primitives", p) {
            problems.push(format!(
                "{p} is public and api_surface.json does not name it"
            ));
        }
    }
    for p in &prims {
        let path = field(p, "rust");
        // Entries outside `primitives::` name the module file they live in.
        if !path.starts_with("primitives::") {
            let (module, name) = path.rsplit_once("::").expect("a module path");
            let rel = format!("library/src/{}/mod.rs", module.replace("::", "/"));
            if !read(&rel)
                .lines()
                .any(|l| l.starts_with(&format!("pub fn {name}(")))
            {
                problems.push(format!(
                    "api_surface.json names {path}, which {rel} does not define"
                ));
            }
        } else if !rust.contains(&path) {
            problems.push(format!(
                "api_surface.json names {path}, which the core does not define"
            ));
        }
        let f = field(p, "ffi");
        if !ffi.contains(&f) {
            problems.push(format!("{path}: no FFI export `{f}`"));
        }
        let w = field(p, "wasm");
        if !wasm.contains(&w) {
            problems.push(format!("{path}: no WASM export `{w}`"));
        }
    }
    fail_if(problems, "the primitives have drifted from their exports");
}

/// Every FFI and WASM export backs something the fixture names, or is
/// infrastructure listed with its reason. An export nothing names is surface
/// no parity check can see.
#[test]
fn every_export_is_named() {
    let mut named: BTreeSet<String> = BTreeSet::new();
    for p in entries("primitives") {
        named.insert(field(&p, "ffi"));
        named.insert(field(&p, "wasm"));
    }
    for m in entries("protocol_methods") {
        named.insert(format!("derec_protocol_{}", field(&m, "rust")));
    }
    for h in entries("sdk_helpers") {
        named.extend(opt_field(&h, "ffi"));
        named.extend(opt_field(&h, "wasm"));
    }
    let mut problems = Vec::new();
    for e in ffi_exports() {
        if !named.contains(&e) && !allowed(INFRASTRUCTURE_EXPORTS, "ffi", "", &e) {
            problems.push(format!(
                "FFI export `{e}` backs nothing api_surface.json names"
            ));
        }
    }
    for e in wasm_exports() {
        if !named.contains(&e) && !allowed(INFRASTRUCTURE_EXPORTS, "wasm", "", &e) {
            problems.push(format!(
                "WASM export `{e}` backs nothing api_surface.json names"
            ));
        }
    }
    fail_if(problems, "exports reach the SDKs without a parity check");
    assert_all_used("INFRASTRUCTURE_EXPORTS", INFRASTRUCTURE_EXPORTS);
}

// ── fixture vs SDKs ────────────────────────────────────────────────────────

/// Each store interface, in each SDK, declares exactly the trait's methods,
/// with the trait's parameters.
#[test]
fn every_sdk_store_interface_matches_the_core() {
    let mut problems = Vec::new();
    for sdk in SDKS {
        let files = type_files(sdk);
        for s in entries("stores") {
            let iface = field(&s, key(sdk));
            let Some(members) = sdk_type(sdk, &iface, &files) else {
                problems.push(format!("{sdk}: declares no store interface `{iface}`"));
                continue;
            };
            let methods = s["methods"].as_array().expect("stores[].methods").clone();
            let expected: BTreeSet<String> = methods.iter().map(|m| field(m, key(sdk))).collect();
            let declared = public_names(&members);
            compare_members(&mut problems, sdk, &iface, &declared, &expected);
            for m in &methods {
                let name = field(m, key(sdk));
                let Some(member) = members.iter().find(|d| d.name == name) else {
                    continue;
                };
                let want: Vec<String> = match STORE_PARAMS
                    .iter()
                    .find(|(k, i, n, _, _)| *k == key(sdk) && *i == iface && *n == name)
                {
                    Some((k, i, n, params, _)) => {
                        allowed(&[(k, i, n, "")], k, i, n);
                        params.iter().map(|p| (*p).to_owned()).collect()
                    }
                    None => str_list(m, "params"),
                };
                let got: Vec<String> = member.params.iter().map(|p| norm(p)).collect();
                let want_n: Vec<String> = want.iter().map(|p| norm(p)).collect();
                if got != want_n {
                    problems.push(format!(
                        "{sdk}: {iface}.{name} takes {:?}; expected {want:?}",
                        member.params
                    ));
                }
            }
        }
    }
    fail_if(
        problems,
        "SDK store interfaces have drifted from the core's traits",
    );
    let as_allow: Vec<Allow> = STORE_PARAMS
        .iter()
        .map(|(k, i, n, _, why)| (*k, *i, *n, *why))
        .collect();
    assert_all_used("STORE_PARAMS", &as_allow);
}

/// Each SDK's store bridge calls every member of every store interface, and
/// calls nothing the interface does not declare.
///
/// A declared member nothing calls is a requirement imposed on every
/// application for no effect — or a core call the bridge silently drops.
#[test]
fn every_sdk_bridge_invokes_every_store_member() {
    let stores = entries("stores");
    let mut problems = Vec::new();
    let mut check =
        |sdk: &str, iface: &str, declared: BTreeSet<String>, invoked: BTreeSet<String>| {
            for m in declared.difference(&invoked) {
                problems.push(format!(
                    "{sdk}: {iface}.{m} is declared and the bridge never calls it"
                ));
            }
            for m in invoked.difference(&declared) {
                problems.push(format!(
                    "{sdk}: the bridge calls {iface}.{m}, which the interface does not declare"
                ));
            }
        };

    // .NET: DeRecProtocol.cs forwards each callback to `_<store>.<Member>(`.
    let cs = read("packages/dotnet/DeRec.Library/src/Protocol/DeRecProtocol.cs");
    let cs_masked = decl::mask(&cs, Lang::CSharp);
    // Go: internal/native dispatches each callback to `s.<store>.<Member>(`.
    let go: String = go_package("packages/go/internal/native")
        .into_iter()
        .map(|(_, s)| decl::mask(&s, Lang::Go))
        .collect::<Vec<_>>()
        .join("\n");
    // WASM: each `impl DeRec<Trait> for Js<Type>` calls `&obj, "<member>"`.
    let wasm = read("library/src/interop/wasm/protocol/stores.rs");
    let wasm_masked = decl::mask(&wasm, Lang::Rust);
    // React Native: each `<store><Member>` callback calls
    // `getPropertyAsFunction(rt, "<member>")`.
    let cpp = read("packages/react-native/cpp/StoreCallbacks.cpp");
    let cpp_masked = decl::mask(&cpp, Lang::CSharp);

    for s in &stores {
        let t = field(s, "trait");
        let methods = s["methods"].as_array().expect("stores[].methods");
        let names = |k: &str| -> BTreeSet<String> { methods.iter().map(|m| field(m, k)).collect() };
        let (cs_field, go_field, cpp_prefix) = match t.as_str() {
            "DeRecChannelStore" => ("_channelStore", "s.channel", "channelStore"),
            "DeRecSecretStore" => ("_secretStore", "s.secret", "secretStore"),
            "DeRecShareStore" => ("_shareStore", "s.share", "shareStore"),
            "DeRecUserSecretStore" => ("_userSecretStore", "s.userSecret", "userSecretStore"),
            "DeRecStateStore" => ("_stateStore", "s.state", "stateStore"),
            "DeRecTransport" => ("_transport", "s.transport", "transport"),
            other => panic!("no bridge locator for {other}"),
        };
        let calls_after = |masked: &str, prefix: &str| -> BTreeSet<String> {
            masked
                .match_indices(&format!("{prefix}."))
                .filter(|(i, _)| *i == 0 || !decl::is_ident(masked.as_bytes()[i - 1]))
                .filter_map(|(i, _)| {
                    let rest = &masked[i + prefix.len() + 1..];
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    rest[name.len()..].starts_with('(').then_some(name)
                })
                .collect()
        };
        check(
            "dotnet",
            &field(s, "dotnet"),
            names("dotnet"),
            calls_after(&cs_masked, cs_field),
        );
        check(
            "go",
            &field(s, "go"),
            names("go"),
            calls_after(&go, go_field),
        );

        // The WASM adapter block for this trait.
        let header = format!("impl {t} for ");
        let at = wasm_masked
            .find(&header)
            .unwrap_or_else(|| panic!("stores.rs has no `{header}`"));
        let open = at + wasm_masked[at..].find('{').expect("impl body");
        let close = decl::matching(&wasm_masked, open).expect("impl body closes");
        let invoked: BTreeSet<String> = wasm[open..close]
            .match_indices("&obj, \"")
            .map(|(i, m)| {
                wasm[open + i + m.len()..]
                    .split('"')
                    .next()
                    .unwrap_or("")
                    .to_owned()
            })
            .collect();
        for sdk in ["nodejs", "web"] {
            check(sdk, &field(s, "ts"), names("ts"), invoked.clone());
        }

        let mut rn_invoked = BTreeSet::new();
        for (at, _) in cpp_masked.match_indices(&format!(" {cpp_prefix}")) {
            let rest = &cpp_masked[at + 1 + cpp_prefix.len()..];
            if !rest.starts_with(|c: char| c.is_ascii_uppercase()) {
                continue;
            }
            let line_start = cpp_masked[..at].rfind('\n').map_or(0, |i| i + 1);
            if !cpp_masked[line_start..at].starts_with("extern \"") {
                continue;
            }
            let Some(open) = cpp_masked[at..].find('{').map(|i| at + i) else {
                continue;
            };
            let Some(close) = decl::matching(&cpp_masked, open) else {
                continue;
            };
            for (i, m) in cpp[open..close].match_indices("getPropertyAsFunction(rt, \"") {
                rn_invoked.insert(
                    cpp[open + i + m.len()..]
                        .split('"')
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                );
            }
        }
        check("react-native", &field(s, "ts"), names("ts"), rn_invoked);
    }
    fail_if(problems, "store bridges and interfaces disagree");
}

/// Each SDK's protocol class declares exactly the core's protocol methods,
/// plus its language's lifecycle members.
#[test]
fn every_sdk_protocol_class_matches_the_core() {
    let methods = entries("protocol_methods");
    let mut problems = Vec::new();
    for sdk in SDKS {
        let declared: BTreeSet<String> = match *sdk {
            "dotnet" => public_names(&dotnet_class(
                "packages/dotnet/DeRec.Library/src/Protocol/DeRecProtocol.cs",
                "DeRecProtocol",
            )),
            "go" => decl::go_methods(&go_package("packages/go/protocol"), "DeRecProtocol")
                .into_iter()
                .filter(|m| m.public)
                .map(|m| m.name)
                .collect(),
            _ => public_names(&ts_class(sdk, "DeRecProtocol")),
        };
        let expected: BTreeSet<String> = methods
            .iter()
            .map(|m| field(m, key(sdk)))
            .chain(
                lifecycle(sdk, "DeRecProtocol")
                    .iter()
                    .map(|s| (*s).to_owned()),
            )
            .collect();
        compare_members(&mut problems, sdk, "DeRecProtocol", &declared, &expected);
    }
    fail_if(problems, "SDK protocol classes have drifted from the core");
}

/// Each SDK's builder declares exactly the core's options, store wiring and
/// `build`, plus its language's lifecycle members.
#[test]
fn every_sdk_builder_matches_the_core() {
    let options = entries("builder_options");
    let wiring = entries("builder_wiring");
    let mut problems = Vec::new();
    for sdk in SDKS {
        if *sdk == "go" {
            // Go's builder is a `Config` struct handed to `New` with the stores.
            let files = go_package("packages/go/protocol");
            let config: BTreeSet<String> = decl::go_fields(&files, "Config")
                .expect("go declares Config")
                .into_iter()
                .collect();
            let expected: BTreeSet<String> = options
                .iter()
                .map(|o| field(o, "go"))
                .chain(["SecretID".to_owned()])
                .collect();
            compare_members(&mut problems, "go", "Config", &config, &expected);
            let new = decl::go_funcs(&files)
                .into_iter()
                .find(|f| f.name == "New")
                .expect("go declares func New");
            let got: BTreeSet<String> = new.params.into_iter().collect();
            let want: BTreeSet<String> = wiring
                .iter()
                .map(|w| field(w, "go"))
                .chain(["config".to_owned()])
                .collect();
            compare_members(&mut problems, "go", "New", &got, &want);
            continue;
        }
        let members = if *sdk == "dotnet" {
            dotnet_class(
                "packages/dotnet/DeRec.Library/src/Protocol/DeRecProtocolBuilder.cs",
                "DeRecProtocolBuilder",
            )
        } else {
            ts_class(sdk, "DeRecProtocolBuilder")
        };
        let build = if *sdk == "dotnet" { "Build" } else { "build" };
        let expected: BTreeSet<String> = options
            .iter()
            .chain(wiring.iter())
            .map(|o| field(o, key(sdk)))
            .chain([build.to_owned()])
            .chain(
                lifecycle(sdk, "DeRecProtocolBuilder")
                    .iter()
                    .map(|s| (*s).to_owned()),
            )
            .collect();
        compare_members(
            &mut problems,
            sdk,
            "DeRecProtocolBuilder",
            &public_names(&members),
            &expected,
        );
        // Constructed from the secret id, as the core's `new(secret_id)`.
        let ctor = members
            .iter()
            .find(|m| m.kind == Kind::Constructor && m.public);
        match ctor {
            Some(c) if c.params.iter().map(|p| norm(p)).eq(["secretid".to_owned()]) => {}
            Some(c) => problems.push(format!(
                "{sdk}: DeRecProtocolBuilder's constructor takes {:?}; expected [secretId]",
                c.params
            )),
            None => problems.push(format!(
                "{sdk}: DeRecProtocolBuilder has no public constructor"
            )),
        }
    }
    fail_if(problems, "SDK builders have drifted from the core");
}

/// Each flow-params type, store record and config record declares exactly the
/// fields of the Rust struct it mirrors, modulo casing.
#[test]
fn every_sdk_record_matches_the_core() {
    let mut problems = Vec::new();
    let files: BTreeMap<&str, Vec<(String, String)>> =
        SDKS.iter().map(|s| (*s, type_files(s))).collect();
    for r in entries("records") {
        let what = field(&r, "what");
        let rust: BTreeSet<String> = match (opt_field(&r, "rust_file"), opt_field(&r, "rust")) {
            (Some(file), Some(name)) => rust_struct_fields(&file, &name)
                .iter()
                .map(|f| norm(f))
                .collect(),
            _ => BTreeSet::new(),
        };
        for sdk in SDKS {
            let Some(name) = opt_field(&r, key(sdk)) else {
                if !allowed(UNNAMED_RECORDS, sdk, &what, "") {
                    problems.push(format!("{sdk}: no type is named for {what}"));
                }
                continue;
            };
            let Some(members) = sdk_type(sdk, &name, &files[sdk]) else {
                problems.push(format!("{sdk}: declares no type `{name}` (mirrors {what})"));
                continue;
            };
            let mut declared: BTreeSet<String> = members
                .iter()
                .filter(|m| m.public && !m.is_static && m.kind == Kind::Field)
                .map(|m| norm(&m.name))
                .collect();
            // Fields an SDK names differently, read back to the core's name.
            for (s, o, m, _) in RECORD_FIELDS {
                if let Some((core, local)) = m.split_once('=')
                    && *s == *sdk
                    && *o == what
                    && rust.contains(core)
                    && declared.remove(local)
                {
                    allowed(RECORD_FIELDS, sdk, &what, m);
                    declared.insert(core.to_owned());
                }
            }
            for f in rust.difference(&declared) {
                if !allowed(RECORD_FIELDS, sdk, &what, f) {
                    problems.push(format!(
                        "{sdk}: {name} has no field for `{f}` (mirrors {what})"
                    ));
                }
            }
            for f in declared.difference(&rust) {
                if !allowed(RECORD_FIELDS, sdk, &what, f) {
                    problems.push(format!(
                        "{sdk}: {name} declares `{f}`, which the core's {what} does not have"
                    ));
                }
            }
        }
    }
    fail_if(problems, "SDK records have drifted from the core's structs");
    assert_all_used("RECORD_FIELDS", RECORD_FIELDS);
    assert_all_used("UNNAMED_RECORDS", UNNAMED_RECORDS);
}

/// A primitive's location in one SDK: the members of its owning class or
/// object, and the declaration of the primitive itself.
struct Located {
    owner: String,
    siblings: BTreeSet<String>,
    member: Option<Member>,
}

/// `Pairing.Request.Produce` in .NET: nested static classes, possibly
/// `partial` across files.
fn locate_dotnet(path: &str) -> Located {
    let segs: Vec<&str> = path.split('.').collect();
    let (owners, leaf) = segs.split_at(segs.len() - 1);
    let mut files = files_under("packages/dotnet/DeRec.Library/src/Primitives", "cs");
    files.push("packages/dotnet/DeRec.Library/src/Envelope.cs".to_owned());
    let mut siblings = BTreeSet::new();
    let mut member: Option<Member> = None;
    for rel in files {
        let src = read(&rel);
        let masked = decl::mask(&src, Lang::CSharp);
        let mut range = 0..masked.len();
        let mut found = true;
        for o in owners {
            match decl::find_block_in(&masked, range.clone(), &["class"], o) {
                Some(b) => range = b.body,
                None => {
                    found = false;
                    break;
                }
            }
        }
        if !found {
            continue;
        }
        for m in decl::members(
            &src,
            &masked,
            range,
            Lang::CSharp,
            owners.last().unwrap(),
            false,
            false,
        ) {
            if !(m.public && m.kind == Kind::Method) {
                continue;
            }
            siblings.insert(m.name.clone());
            if m.name == leaf[0] {
                // Overloads accumulate, so a check on what the primitive
                // forwards to sees every one of them.
                match &mut member {
                    Some(prev) => prev.text.push_str(&m.text),
                    None => member = Some(m),
                }
            }
        }
    }
    Located {
        owner: owners.join("."),
        siblings,
        member,
    }
}

/// `pairing.Request.Produce` in Go: a method on the type of package var
/// `Request`; `pairing.Fingerprint`: a package-level function.
fn locate_go(path: &str) -> Located {
    let segs: Vec<&str> = path.split('.').collect();
    let files = go_package(&format!("packages/go/primitives/{}", segs[0]));
    if segs.len() == 2 {
        let funcs = decl::go_funcs(&files);
        return Located {
            owner: segs[0].to_owned(),
            siblings: funcs.iter().map(|f| f.name.clone()).collect(),
            member: funcs.into_iter().find(|f| f.name == segs[1]),
        };
    }
    let var = segs[1];
    let ty = files
        .iter()
        .find_map(|(_, src)| {
            src.lines()
                .find_map(|l| l.strip_prefix(&format!("var {var} ")))
                .map(|t| t.trim().to_owned())
        })
        .unwrap_or_default();
    let methods = decl::go_methods(&files, &ty);
    Located {
        owner: format!("{}.{var}", segs[0]),
        siblings: methods
            .iter()
            .filter(|m| m.public)
            .map(|m| m.name.clone())
            .collect(),
        member: methods.into_iter().find(|m| m.name == segs[2]),
    }
}

/// `primitives.pairing.request.produce` in a TypeScript declaration or
/// runtime file: nested object literals or type literals, where a shorthand
/// member resolves to the file-level `const` of that name.
fn locate_ts(rel: &str, path: &str) -> Located {
    let src = read(rel);
    let masked = decl::mask(&src, Lang::Ts);
    let segs: Vec<&str> = path.split('.').collect();
    let (owners, leaf) = segs.split_at(segs.len() - 1);
    let const_block = |name: &str| -> Option<std::ops::Range<usize>> {
        decl::word_positions(&masked, "const")
            .into_iter()
            .find_map(|at| {
                let rest = masked[at + 5..].trim_start();
                let r = rest.strip_prefix(name)?;
                if r.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
                    return None;
                }
                let r = r.trim_start();
                if !(r.starts_with('=') || r.starts_with(':')) {
                    return None;
                }
                let r2 = r[1..].trim_start();
                if !r2.starts_with('{') {
                    return None;
                }
                let open = masked.len() - r2.len();
                Some(open + 1..decl::matching(&masked, open)?)
            })
    };
    let mut range = const_block(owners[0]);
    for o in &owners[1..] {
        let Some(r) = range.clone() else { break };
        let stmt = decl::statements(&masked, r, true, false)
            .into_iter()
            .find(|s| {
                let t = masked[s.clone()].trim_start();
                t.starts_with(o)
                    && !t[o.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
            });
        range = match stmt {
            Some(s) => match masked[s.clone()].find('{') {
                Some(i) => {
                    let open = s.start + i;
                    decl::matching(&masked, open).map(|c| open + 1..c)
                }
                // A shorthand member names a file-level const.
                None => const_block(o),
            },
            None => None,
        };
    }
    let Some(range) = range else {
        return Located {
            owner: owners.join("."),
            siblings: BTreeSet::new(),
            member: None,
        };
    };
    let members = decl::members(
        &src,
        &masked,
        range,
        Lang::Ts,
        owners.last().unwrap(),
        true,
        true,
    );
    // Nested objects are owners, not primitives.
    let siblings = members
        .iter()
        .filter(|m| {
            !(m.kind == Kind::Field
                && m.text
                    .split_once(':')
                    .is_some_and(|(_, v)| v.trim_start().starts_with('{')))
        })
        .map(|m| m.name.clone())
        .collect();
    Located {
        owner: owners.join("."),
        siblings,
        member: members.into_iter().find(|m| m.name == leaf[0]),
    }
}

/// Each primitive is declared in each SDK, and each SDK's owning class or
/// object declares no primitive the core does not have. Where a binding's
/// source shows what a primitive forwards to, that is checked too: the
/// TypeScript runtimes map each one to its WASM export, React Native and
/// .NET call its FFI export.
#[test]
fn every_sdk_declares_every_primitive() {
    let prims = entries("primitives");
    let mut problems = Vec::new();
    // owner -> (declared siblings, expected members), per sdk.
    let mut owners: BTreeMap<(String, String), (BTreeSet<String>, BTreeSet<String>)> =
        BTreeMap::new();
    let mut note = |sdk: &str, path: &str, loc: &Located, problems: &mut Vec<String>| {
        let leaf = path.rsplit('.').next().unwrap_or(path).to_owned();
        let e = owners
            .entry((sdk.to_owned(), loc.owner.clone()))
            .or_insert_with(|| (loc.siblings.clone(), BTreeSet::new()));
        e.1.insert(leaf);
        if loc.member.is_none() {
            problems.push(format!("{sdk}: does not declare primitive `{path}`"));
        }
    };
    for p in &prims {
        let rust = field(p, "rust");
        let ffi = field(p, "ffi");
        let wasm = field(p, "wasm");

        let path = field(p, "dotnet");
        let loc = locate_dotnet(&path);
        if let Some(m) = &loc.member
            && !m.text.contains(&format!("{ffi}("))
        {
            problems.push(format!(
                "dotnet: {path} does not call the FFI export `{ffi}` ({rust})"
            ));
        }
        note("dotnet", &path, &loc, &mut problems);

        let path = field(p, "go");
        let loc = locate_go(&path);
        note("go", &path, &loc, &mut problems);

        let path = field(p, "ts");
        for (sdk, dts, js) in [
            (
                "nodejs",
                "packages/nodejs/index.d.ts",
                "packages/nodejs/index.js",
            ),
            ("web", "packages/web/index.d.ts", "packages/web/index.js"),
        ] {
            let loc = locate_ts(dts, &path);
            note(sdk, &path, &loc, &mut problems);
            let rt = locate_ts(js, &path);
            match &rt.member {
                Some(m) if m.text.trim_end().ends_with(&wasm) => {}
                Some(_) => problems.push(format!(
                    "{sdk}: {js} maps {path} to something other than `{wasm}`"
                )),
                None => problems.push(format!("{sdk}: {js} does not provide {path}")),
            }
        }
        let loc = locate_ts("packages/react-native/src/primitives.ts", &path);
        if let Some(m) = &loc.member
            && !m.text.contains(&format!("'{ffi}'"))
        {
            problems.push(format!(
                "react-native: {path} does not call the FFI export `{ffi}`"
            ));
        }
        note("react-native", &path, &loc, &mut problems);
    }
    for ((sdk, owner), (declared, expected)) in &owners {
        for m in declared.difference(expected) {
            if !allowed(EXTRA_MEMBERS, sdk, owner, m) {
                problems.push(format!(
                    "{sdk}: {owner} declares `{m}`, which the core has no primitive for"
                ));
            }
        }
    }
    fail_if(problems, "SDK primitives have drifted from the core");
}

/// Conveniences every SDK must offer that the core does not define, so no
/// other check would notice one going missing.
///
/// .NET and Go name the owning type where the helper is a member
/// (`ChannelFilter.Matches`); the TypeScript SDKs export each as a top-level
/// function, which the runtime file must define and export too.
#[test]
fn every_sdk_declares_every_shared_helper() {
    let mut problems = Vec::new();
    let dotnet = type_files("dotnet");
    let mut go = type_files("go");
    go.extend(go_package("packages/go/derecpb"));
    for h in entries("sdk_helpers") {
        let what = field(&h, "what");

        let loc = field(&h, "dotnet");
        let ok = match loc.split_once('.') {
            Some((owner, member)) => sdk_type("dotnet", owner, &dotnet)
                .is_some_and(|ms| ms.iter().any(|m| m.public && m.name == member)),
            None => sdk_type("dotnet", &loc, &dotnet).is_some(),
        };
        if !ok {
            problems.push(format!("dotnet: does not declare `{loc}` ({what})"));
        }

        let loc = field(&h, "go");
        let ok = match loc.split_once('.') {
            Some((recv, method)) => decl::go_methods(&go, recv).iter().any(|m| m.name == method),
            None => {
                decl::go_funcs(&go).iter().any(|f| f.name == loc)
                    || decl::go_type_block(&go, &loc, "struct").is_some()
            }
        };
        if !ok {
            problems.push(format!("go: does not declare `{loc}` ({what})"));
        }

        let name = field(&h, "ts");
        for (sdk, dts, js) in [
            (
                "nodejs",
                "packages/nodejs/index.d.ts",
                Some("packages/nodejs/index.js"),
            ),
            (
                "web",
                "packages/web/index.d.ts",
                Some("packages/web/index.js"),
            ),
            ("react-native", "packages/react-native/src/types.ts", None),
        ] {
            let top = |rel: &str| -> BTreeSet<String> {
                let src = read(rel);
                let masked = decl::mask(&src, Lang::Ts);
                decl::members(&src, &masked, 0..masked.len(), Lang::Ts, "", true, false)
                    .into_iter()
                    .filter(|m| m.kind == Kind::Method && m.text.contains("function"))
                    .map(|m| m.name)
                    .collect()
            };
            if !top(dts).contains(&name) {
                problems.push(format!(
                    "{sdk}: {dts} does not declare function `{name}` ({what})"
                ));
            }
            if let Some(js) = js {
                let src = read(js);
                let exported = top(js).contains(&name)
                    && (src.contains(&format!("export function {name}("))
                        || src
                            .split_once("module.exports = {")
                            .is_some_and(|(_, rest)| {
                                rest.lines().any(|l| l.trim() == format!("{name},"))
                            }));
                if !exported {
                    problems.push(format!(
                        "{sdk}: {js} does not define and export `{name}` ({what})"
                    ));
                }
            }
        }
    }
    fail_if(problems, "SDKs are missing shared helpers");
}

/// Every flow's params type is declared as a type in every SDK.
#[test]
fn every_sdk_declares_every_flow_params_type() {
    let mut problems = Vec::new();
    for sdk in SDKS {
        let files = type_files(sdk);
        for e in entries("flow_params") {
            let name = field(&e, key(sdk));
            if sdk_type(sdk, &name, &files).is_none() {
                problems.push(format!("{sdk}: declares no type `{name}`"));
            }
        }
    }
    fail_if(problems, "SDKs are missing flow params types");
}

/// The allow-lists consulted by more than one test are checked once every
/// test that consults them has run, in this single test, so a stale entry
/// fails regardless of test order.
#[test]
fn allow_lists_have_no_stale_entries() {
    every_sdk_protocol_class_matches_the_core();
    every_sdk_builder_matches_the_core();
    every_sdk_declares_every_primitive();
    rust_protocol_methods_are_named_and_exported();
    rust_primitives_are_named_and_exported();
    assert_all_used("EXTRA_MEMBERS", EXTRA_MEMBERS);
    assert_all_used("UNEXPORTED", UNEXPORTED);
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
///
/// A `null` horizon means no wave is open, and then nothing may be deprecated:
/// a deprecation without a declared removal version is the same defect with
/// no version at all.
#[test]
fn every_deprecation_shares_the_release_horizon() {
    let horizon = &fixture()["documented_api"]["deprecation_horizon"];
    let found = deprecations();

    if horizon.is_null() {
        assert!(
            found.is_empty(),
            "these symbols are deprecated but no deprecation wave is open:\n  {}\n\n\
             Declare `documented_api.deprecation_horizon` in api_surface.json \
             with the version they are removed at.",
            found
                .iter()
                .map(|(rel, symbol, _)| format!("{rel}: `{symbol}`"))
                .collect::<Vec<_>>()
                .join("\n  ")
        );
        return;
    }

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

    for (rel, symbol, attr) in &found {
        if exceptions.contains(symbol) {
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
        !found.is_empty(),
        "a deprecation wave is open but no `#[deprecated]` attributes were found; \
         set `documented_api.deprecation_horizon` to null once the wave is removed"
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
    let sources = rust_sources("library/src");
    assert!(
        !sources.is_empty(),
        "no library sources were found — the walk is reading nothing"
    );
    for rel in sources {
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
