// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
// Drives library/tests/fixtures/events_golden.json through the SDK's event
// decoder.
//
// Rust writes one sample of every event exactly as the FFI hands it over,
// with every optional field present and every value different from its type's
// default. Each sample is decoded the way DeRecProtocol decodes a call's
// events, and every JSON field must reach a property of the typed event with
// the same value. A field the decoder drops, defaults or misreads therefore
// fails here, and so does a JSON field with no property to land on or a
// property no JSON field fills.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using DeRec.Library;
using DeRec.Library.Orchestrator;

namespace DeRec.Bindings.Smoke;

internal static class EventGolden
{
    private static string FixturePath(string name)
    {
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
        return Path.Combine(dir.FullName, "library", "tests", "fixtures", name);
    }

    /// <summary><c>peer_communication_info</c> → <c>PeerCommunicationInfo</c>.</summary>
    private static string PropertyName(string jsonKey) =>
        string.Concat(jsonKey.Split('_').Select(p => char.ToUpperInvariant(p[0]) + p[1..]));

    private static IEnumerable<PropertyInfo> DataProperties(Type type) =>
        type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.Name != nameof(DeRecEvent.EventType));

    private static void Fail(string path, string why) =>
        throw new InvalidOperationException($"{path}: {why}");

    private static void AssertSame(JsonElement expected, object? actual, string path)
    {
        switch (expected.ValueKind)
        {
            case JsonValueKind.Null:
                if (actual is not null)
                    Fail(path, $"fixture is null, decoded {actual}");
                return;

            case JsonValueKind.String:
            {
                string want = expected.GetString()!;
                switch (actual)
                {
                    case null:
                        Fail(path, $"fixture is \"{want}\", decoded null");
                        return;
                    case ulong id:
                        if (id.ToString() != want)
                            Fail(path, $"fixture is id {want}, decoded {id}");
                        return;
                    case string s:
                        if (s != want)
                            Fail(path, $"fixture is \"{want}\", decoded \"{s}\"");
                        return;
                    case Enum e:
                        // The JSON carries the variant name; .NET casing may
                        // differ (transport protocol "https" is Protocol.Https).
                        if (!string.Equals(e.ToString(), want, StringComparison.OrdinalIgnoreCase))
                            Fail(path, $"fixture is \"{want}\", decoded {e.GetType().Name}.{e}");
                        return;
                    default:
                        Fail(path, $"fixture is a string, decoded a {actual.GetType().Name}");
                        return;
                }
            }

            case JsonValueKind.Number:
            {
                long want = expected.GetInt64();
                long got = actual switch
                {
                    null => throw new InvalidOperationException($"{path}: fixture is {want}, decoded null"),
                    Enum e => Convert.ToInt64(e),
                    uint or ulong or int or long => Convert.ToInt64(actual),
                    _ => throw new InvalidOperationException(
                        $"{path}: fixture is a number, decoded a {actual.GetType().Name}"),
                };
                if (got != want)
                    Fail(path, $"fixture is {want}, decoded {got}");
                return;
            }

            case JsonValueKind.True:
            case JsonValueKind.False:
                if (actual is not bool b || b != expected.GetBoolean())
                    Fail(path, $"fixture is {expected.GetBoolean()}, decoded {actual ?? "null"}");
                return;

            case JsonValueKind.Array:
            {
                var want = expected.EnumerateArray().ToList();
                if (actual is byte[] bytes)
                {
                    var wantBytes = want.Select(v => v.GetByte()).ToArray();
                    if (!bytes.SequenceEqual(wantBytes))
                        Fail(path, $"fixture is [{string.Join(", ", wantBytes)}], decoded [{string.Join(", ", bytes)}]");
                    return;
                }
                if (actual is not IEnumerable items || actual is string)
                {
                    Fail(path, $"fixture is an array, decoded {actual?.GetType().Name ?? "null"}");
                    return;
                }
                var got = items.Cast<object?>().ToList();
                if (got.Count != want.Count)
                    Fail(path, $"fixture has {want.Count} entries, decoded {got.Count}");
                for (int i = 0; i < want.Count; i++)
                    AssertSame(want[i], got[i], $"{path}[{i}]");
                return;
            }

            case JsonValueKind.Object:
            {
                if (actual is null)
                {
                    Fail(path, "fixture is an object, decoded null");
                    return;
                }
                if (actual is IDictionary<string, string> map)
                {
                    var want = expected.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);
                    if (map.Count != want.Count || want.Any(kv => !map.TryGetValue(kv.Key, out var v) || v != kv.Value))
                        Fail(path, $"fixture is {{{string.Join(", ", want.Select(kv => $"{kv.Key}={kv.Value}"))}}}, "
                            + $"decoded {{{string.Join(", ", map.Select(kv => $"{kv.Key}={kv.Value}"))}}}");
                    return;
                }
                AssertObject(expected, actual, path, skip: null);
                return;
            }

            default:
                Fail(path, $"unexpected fixture value kind {expected.ValueKind}");
                return;
        }
    }

    /// <summary>
    /// Every JSON field lands on a property with the same value, and every
    /// property is filled by a JSON field.
    /// </summary>
    private static void AssertObject(JsonElement expected, object actual, string path, string? skip)
    {
        Type type = actual.GetType();
        var properties = DataProperties(type).ToDictionary(p => p.Name);
        var covered = new HashSet<string>();
        foreach (JsonProperty field in expected.EnumerateObject())
        {
            if (field.Name == skip) continue;
            string name = PropertyName(field.Name);
            if (!properties.TryGetValue(name, out var property))
            {
                Fail($"{path}.{field.Name}", $"{type.Name} has no {name} property, so the field is dropped");
                return;
            }
            covered.Add(name);
            AssertSame(field.Value, property.GetValue(actual), $"{path}.{field.Name}");
        }
        var unfilled = properties.Keys.Where(k => !covered.Contains(k)).ToList();
        if (unfilled.Count > 0)
            Fail(path, $"{type.Name} declares [{string.Join(", ", unfilled)}], which no fixture field fills");
    }

    public static void RunAll()
    {
        Console.WriteLine("=== Event golden test ===");

        string json = File.ReadAllText(FixturePath("events_golden.json"));
        using var doc = JsonDocument.Parse(json);
        var samples = doc.RootElement.GetProperty("events").EnumerateArray().ToList();

        // The same call DeRecProtocol makes on every event list the FFI returns.
        var decoded = JsonSerializer.Deserialize<List<DeRecEvent>>(
            doc.RootElement.GetProperty("events").GetRawText(), DeRecJsonOptions.Wire)
            ?? throw new InvalidOperationException("the events array decoded to null");
        if (decoded.Count != samples.Count)
            throw new InvalidOperationException($"fixture has {samples.Count} events, decoded {decoded.Count}");

        var types = new HashSet<string>();
        for (int i = 0; i < samples.Count; i++)
        {
            string type = samples[i].GetProperty("type").GetString()!;
            DeRecEvent ev = decoded[i];
            if (ev is UnmappedEvent)
                throw new InvalidOperationException($"{type}: decoded to UnmappedEvent; the SDK has no type for it");
            if (ev.EventType != type)
                throw new InvalidOperationException($"{type}: decoded to {ev.GetType().Name} ({ev.EventType})");
            AssertObject(samples[i], ev, $"{type}[{i}]", skip: "type");
            types.Add(type);
        }

        Console.WriteLine($"  {samples.Count} samples ({types.Count} event types) decode with every field intact  ✓");
        Console.WriteLine("Event golden test passed.\n");
    }
}
