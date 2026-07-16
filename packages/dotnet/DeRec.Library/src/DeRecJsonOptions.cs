// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DeRec.Library;

/// <summary>
/// <see cref="JsonSerializerOptions"/> tuned to the on-the-wire
/// conventions used by the DeRec FFI boundary. Apps that decode or
/// emit DeRec wire JSON outside <c>DeRecProtocol</c> (custom stores,
/// inspection tools, manual flow params) should use
/// <see cref="Wire"/> so the byte-array and null-handling rules match
/// what the Rust side expects.
/// </summary>
/// <remarks>
/// <para>
/// Conventions encoded here:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <c>byte[]</c> rides as a JSON array of numbers (`[0, 1, 255, ...]`),
///     matching Rust's <c>serde_json</c> default for <c>Vec&lt;u8&gt;</c>.
///     The .NET default (base64 string) would round-trip within .NET but
///     does not match what the Rust deserializer expects.
///   </description></item>
///   <item><description>
///     Properties with a <c>null</c> value are dropped on serialize so
///     <c>#[serde(default)]</c> / <c>Option&lt;T&gt;</c> fields on the
///     Rust side never see a literal <c>null</c>.
///   </description></item>
///   <item><description>
///     Property names round-trip verbatim — no naming-policy conversion.
///     Records / DTOs are expected to carry <c>[JsonPropertyName]</c>
///     attributes if their wire shape differs from C# convention.
///   </description></item>
/// </list>
/// </remarks>
public static class DeRecJsonOptions
{
    /// <summary>
    /// Shared, frozen <see cref="JsonSerializerOptions"/> for DeRec
    /// wire-JSON serialization. Reuse this instance instead of
    /// creating new ones — System.Text.Json caches reflection per
    /// options instance.
    /// </summary>
    public static readonly JsonSerializerOptions Wire = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = null,
        Converters = { new ByteArrayJsonNumberConverter() },
    };

    /// <summary>
    /// Serializes <c>byte[]</c> as a JSON array of numbers — see the
    /// remarks on <see cref="DeRecJsonOptions"/> for the rationale.
    /// </summary>
    public sealed class ByteArrayJsonNumberConverter : JsonConverter<byte[]>
    {
        public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartArray)
                throw new JsonException($"expected StartArray for byte[], got {reader.TokenType}");
            var list = new List<byte>(32);
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndArray)
                    return list.ToArray();
                list.Add(reader.GetByte());
            }
            throw new JsonException("unterminated byte[] JSON array");
        }

        public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
        {
            writer.WriteStartArray();
            foreach (byte b in value) writer.WriteNumberValue(b);
            writer.WriteEndArray();
        }
    }
}
