// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
// Drives library/tests/fixtures/channel_filter.json against
// ChannelFilter<TRole>.Matches.
//
// A channel store may push the filter into its query rather than returning
// every row. That is an optimization and it is the store's to verify: the core
// re-applies the filter to whatever a listing returns, which drops rows the
// filter excludes but cannot recover a row that was never returned. An
// over-selecting pushdown costs bandwidth; an under-selecting one is
// undetectable at runtime.
//
// The same table drives the Rust, Go and TypeScript suites. When two bindings
// disagree, the fixture says which is wrong.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using DeRec.Library.Orchestrator;
using DeRec.Library.Primitives;

namespace DeRec.Bindings.Smoke;

internal static class ChannelFilterConformance
{
    private static JsonElement LoadFixture()
    {
        // Walk up to the repository root rather than hard-coding a depth: the
        // binary runs from bin/Release/<tfm>/ and the relative depth of that
        // path is a build detail, not something this test should encode.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Cargo.toml")))
        {
            dir = dir.Parent;
        }
        if (dir is null)
        {
            throw new InvalidOperationException(
                "could not find the repository root above " + AppContext.BaseDirectory);
        }

        string path = Path.Combine(
            dir.FullName, "library", "tests", "fixtures", "channel_filter.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.Clone();
    }

    private static ChannelStatus StatusByName(string name) => name switch
    {
        "Pending" => ChannelStatus.Pending,
        "Paired" => ChannelStatus.Paired,
        "Unpairing" => ChannelStatus.Unpairing,
        _ => throw new InvalidOperationException($"fixture names an unknown ChannelStatus: {name}"),
    };

    private static Pairing.SenderKind SenderKindByName(string name) => name switch
    {
        "Owner" => Pairing.SenderKind.Owner,
        "Helper" => Pairing.SenderKind.Helper,
        "ReplicaSource" => Pairing.SenderKind.ReplicaSource,
        "ReplicaDestination" => Pairing.SenderKind.ReplicaDestination,
        _ => throw new InvalidOperationException($"fixture names an unknown SenderKind: {name}"),
    };

    private static ReplicaRole ReplicaRoleByName(string name) => name switch
    {
        "Source" => ReplicaRole.Source,
        "Destination" => ReplicaRole.Destination,
        _ => throw new InvalidOperationException($"fixture names an unknown ReplicaRole: {name}"),
    };

    private static List<string> Strings(JsonElement e, string key) =>
        e.GetProperty(key).EnumerateArray().Select(v => v.GetString()!).ToList();

    private static List<ulong> Ids(JsonElement e, string key) =>
        Strings(e, key).Select(ulong.Parse).ToList();

    private static void RunSection<TRole>(
        JsonElement section,
        string label,
        Func<string, TRole> roleByName,
        Func<IReadOnlyList<ulong>, IReadOnlyList<ChannelStatus>, TRole?, IReadOnlyList<ulong>,
             ChannelFilter<TRole>> build)
        where TRole : struct
    {
        JsonElement records = section.GetProperty("records");

        foreach (JsonElement c in section.GetProperty("cases").EnumerateArray())
        {
            string name = c.GetProperty("name").GetString()!;
            JsonElement f = c.GetProperty("filter");

            JsonElement roleEl = f.GetProperty("role");
            TRole? role = roleEl.ValueKind == JsonValueKind.Null
                ? null
                : roleByName(roleEl.GetString()!);

            ChannelFilter<TRole> filter = build(
                Ids(f, "ids"),
                Strings(f, "status").Select(StatusByName).ToList(),
                role,
                Ids(f, "exclude"));

            var survivors = records.EnumerateArray()
                .Where(r => filter.Matches(
                    ulong.Parse(r.GetProperty("id").GetString()!),
                    StatusByName(r.GetProperty("status").GetString()!),
                    roleByName(r.GetProperty("role").GetString()!)))
                .Select(r => r.GetProperty("id").GetString()!)
                .ToList();

            var expected = c.GetProperty("expected").EnumerateArray()
                .Select(v => v.GetString()!)
                .ToList();

            if (!survivors.SequenceEqual(expected))
            {
                string why = c.TryGetProperty("why", out JsonElement w)
                    ? w.GetString()!
                    : "(not stated)";
                throw new InvalidOperationException(
                    $"{label} case `{name}` disagrees with ChannelFilter.Matches:\n"
                    + $"  got:  [{string.Join(", ", survivors)}]\n"
                    + $"  want: [{string.Join(", ", expected)}]\n"
                    + $"  why this case exists: {why}");
            }
        }
    }

    public static void RunAll()
    {
        Console.WriteLine("=== Channel filter conformance ===");
        JsonElement fixture = LoadFixture();

        RunSection<Pairing.SenderKind>(
            fixture.GetProperty("helpers"),
            "helpers",
            SenderKindByName,
            (ids, status, role, exclude) => new HelperFilter(ids, status, role, exclude));

        RunSection<ReplicaRole>(
            fixture.GetProperty("replicas"),
            "replicas",
            ReplicaRoleByName,
            (ids, status, role, exclude) => new ReplicaFilter(ids, status, role, exclude));

        Console.WriteLine("Channel filter conformance passed.");
    }
}
