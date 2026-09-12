// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Drives `fixtures/channel_filter.json` against [`ChannelFilter::matches`].
//!
//! A channel store may push the filter into its query rather than returning
//! every row. That is an optimization, and it is the store's to verify: the
//! library re-applies the filter to whatever a listing returns, which drops
//! rows the filter excludes but cannot recover a row that was never returned.
//! An over-selecting pushdown therefore costs only bandwidth, while an
//! under-selecting one is undetectable at runtime — no exception, no event, no
//! log line, just a share that was never published.
//!
//! A contract that the party who must satisfy it cannot check is not a
//! contract, so the cases live in a fixture every binding can read. This file
//! holds the fixture to the core's own predicate; each SDK's suite holds its
//! own helper to the same table. When they disagree, the fixture says which is
//! wrong.

use derec_library::protocol::types::{ChannelFilter, ChannelStatus, ReplicaRole};
use derec_library::types::{ChannelId, ReplicaId};
use derec_proto::SenderKind;

fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/channel_filter.json"
    );
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {path}: {e}"))
}

fn strings(v: &serde_json::Value, key: &str) -> Vec<String> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("`{key}` is an array"))
        .iter()
        .map(|s| s.as_str().expect("a decimal id string").to_owned())
        .collect()
}

fn status_of(name: &str) -> ChannelStatus {
    match name {
        "Pending" => ChannelStatus::Pending,
        "Paired" => ChannelStatus::Paired,
        "Unpairing" => ChannelStatus::Unpairing,
        other => panic!("fixture names an unknown ChannelStatus: {other}"),
    }
}

fn sender_kind_of(name: &str) -> SenderKind {
    match name {
        "Owner" => SenderKind::Owner,
        "Helper" => SenderKind::Helper,
        "ReplicaSource" => SenderKind::ReplicaSource,
        "ReplicaDestination" => SenderKind::ReplicaDestination,
        other => panic!("fixture names an unknown SenderKind: {other}"),
    }
}

fn replica_role_of(name: &str) -> ReplicaRole {
    match name {
        "Source" => ReplicaRole::Source,
        "Destination" => ReplicaRole::Destination,
        other => panic!("fixture names an unknown ReplicaRole: {other}"),
    }
}

/// Run one section of the fixture, converting ids and roles with the closures
/// the section's key type needs.
fn run_section<Role, Id>(
    section: &str,
    parse_id: impl Fn(&str) -> Id,
    parse_role: impl Fn(&str) -> Role,
) where
    Role: PartialEq,
    Id: PartialEq + std::fmt::Debug,
{
    let doc = fixture();
    let records = doc[section]["records"]
        .as_array()
        .unwrap_or_else(|| panic!("`{section}.records` is an array"))
        .clone();

    for case in doc[section]["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("`{section}.cases` is an array"))
    {
        let name = case["name"].as_str().expect("every case is named");
        let f = &case["filter"];

        let filter = ChannelFilter::<Role, Id> {
            ids: strings(f, "ids").iter().map(|s| parse_id(s)).collect(),
            status: strings(f, "status").iter().map(|s| status_of(s)).collect(),
            role: f["role"].as_str().map(&parse_role),
            exclude: strings(f, "exclude").iter().map(|s| parse_id(s)).collect(),
        };

        let survivors: Vec<String> = records
            .iter()
            .filter(|r| {
                let id = parse_id(r["id"].as_str().expect("record id"));
                let status = status_of(r["status"].as_str().expect("record status"));
                let role = parse_role(r["role"].as_str().expect("record role"));
                filter.matches(&id, status, &role)
            })
            .map(|r| r["id"].as_str().expect("record id").to_owned())
            .collect();

        let expected: Vec<String> = case["expected"]
            .as_array()
            .expect("every case states what survives")
            .iter()
            .map(|s| s.as_str().expect("a decimal id string").to_owned())
            .collect();

        assert_eq!(
            survivors,
            expected,
            "\n{section} case `{name}` disagrees with ChannelFilter::matches.\n  \
             why it is in the fixture: {}\n  \
             If the core is right, fix the fixture and then every SDK until its \
             tests pass again.",
            case["why"].as_str().unwrap_or("(not stated)")
        );
    }
}

#[test]
fn helper_filter_matches_the_fixture() {
    run_section::<SenderKind, ChannelId>(
        "helpers",
        |s| ChannelId(s.parse().expect("a u64 id")),
        sender_kind_of,
    );
}

#[test]
fn replica_filter_matches_the_fixture() {
    run_section::<ReplicaRole, ReplicaId>(
        "replicas",
        |s| ReplicaId::try_from(s.parse::<u64>().expect("a u64 id")).expect("a non-zero id"),
        replica_role_of,
    );
}

/// The fixture has to keep exercising every clause, not just the ones that
/// were easy to write. A case removed here would fail nothing otherwise.
#[test]
fn the_fixture_covers_every_clause() {
    let doc = fixture();
    let mut saw_empty_ids = false;
    let mut saw_empty_status = false;
    let mut saw_null_role = false;
    let mut saw_exclude_overriding_ids = false;
    let mut saw_large_id = false;

    for section in ["helpers", "replicas"] {
        for case in doc[section]["cases"].as_array().expect("cases") {
            let f = &case["filter"];
            let ids = strings(f, "ids");
            let exclude = strings(f, "exclude");
            saw_empty_ids |= ids.is_empty() && !strings(f, "status").is_empty();
            saw_empty_status |= strings(f, "status").is_empty() && !ids.is_empty();
            saw_null_role |= f["role"].is_null();
            saw_exclude_overriding_ids |= exclude.iter().any(|e| ids.contains(e));
            saw_large_id |= ids.iter().chain(exclude.iter()).any(|i| i.len() > 16);
        }
    }

    assert!(saw_empty_ids, "no case pins empty `ids` as unrestricted");
    assert!(
        saw_empty_status,
        "no case pins empty `status` as unrestricted"
    );
    assert!(saw_null_role, "no case pins a null `role` as unrestricted");
    assert!(
        saw_exclude_overriding_ids,
        "no case pins `exclude` applying after — and overriding — `ids`"
    );
    assert!(
        saw_large_id,
        "no case pins an id above 2^53, where a binding that parses ids as \
         numbers instead of strings silently matches the wrong record"
    );
}
