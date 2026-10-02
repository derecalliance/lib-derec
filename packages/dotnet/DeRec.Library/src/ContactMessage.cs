// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System.Globalization;
using System.Text.Json;

namespace DeRec.Library;

/// <summary>
/// Decoded representation of a DeRec <c>ContactMessage</c>, exchanged out-of-band
/// before pairing begins.
/// </summary>
/// <param name="ChannelId">
/// Channel identifier the initiator expects to use for the new pairing session.
/// </param>
/// <param name="ContactMode">
/// Selects how the public encryption material is delivered. See
/// <see cref="ContactMode"/>.
/// </param>
/// <param name="Nonce">
/// Random nonce that binds the pairing request to this contact exchange.
/// </param>
/// <param name="MlkemEncapsulationKey">
/// Serialized ML-KEM-768 encapsulation key. Present only when
/// <see cref="ContactMode"/> is <see cref="ContactMode.InlineKeys"/>.
/// </param>
/// <param name="EciesPublicKey">
/// Serialized ECIES public key. Present only when
/// <see cref="ContactMode"/> is <see cref="ContactMode.InlineKeys"/>.
/// </param>
/// <param name="ContactBindingHash">
/// SHA-384 commitment to the public encryption material. Present only when
/// <see cref="ContactMode"/> is <see cref="ContactMode.HashedKeys"/>. Validated
/// by the scanner after it receives the keys via <c>PrePair</c>.
/// </param>
public sealed record ContactMessage(
    ulong ChannelId,
    ContactMode ContactMode,
    ulong Nonce,
    byte[]? MlkemEncapsulationKey,
    byte[]? EciesPublicKey,
    byte[]? ContactBindingHash
)
{
    /// <summary>
    /// Every transport endpoint the creator of this contact can be reached on,
    /// in its own preference order.
    /// </summary>
    /// <remarks>
    /// Preserved across a decode/encode round trip, so a contact this SDK
    /// parses and hands back to <c>Pairing.Request.Produce</c> still
    /// advertises every endpoint the creator offered.
    /// </remarks>
    public IReadOnlyList<TransportProtocol> SupportedTransports { get; init; } =
        Array.Empty<TransportProtocol>();

    /// <summary>
    /// The endpoints this contact advertises, in the creator's own order.
    /// </summary>
    /// <remarks>
    /// Reports what was advertised, not what is acceptable; nothing here is
    /// validated.
    /// </remarks>
    public IReadOnlyList<TransportProtocol> AdvertisedEndpoints() => SupportedTransports;

    /// <summary>
    /// When the creator produced this contact, or <c>null</c> if unset.
    /// </summary>
    public Timestamp? Timestamp { get; init; }

    /// <summary>
    /// The JSON shape <c>encode_contact_message</c> reads and
    /// <c>decode_contact_message</c> writes. Encoding and decoding the wire
    /// bytes, and enforcing the contact's mode invariants, happen in the
    /// core: see <see cref="Primitives.Pairing.Request.EncodeContact"/> and
    /// <see cref="Primitives.Pairing.Request.DecodeContact"/>.
    /// </summary>
    internal byte[] ToWireJson()
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("channel_id", ChannelId.ToString(CultureInfo.InvariantCulture));
            writer.WriteString("nonce", Nonce.ToString(CultureInfo.InvariantCulture));
            writer.WriteNumber("contact_mode", (int)ContactMode);
            WriteBytes(writer, "mlkem_encapsulation_key", MlkemEncapsulationKey);
            WriteBytes(writer, "ecies_public_key", EciesPublicKey);
            WriteBytes(writer, "contact_binding_hash", ContactBindingHash);
            if (Timestamp is { } ts)
            {
                writer.WriteStartObject("timestamp");
                writer.WriteNumber("seconds", ts.Seconds);
                writer.WriteNumber("nanos", ts.Nanos);
                writer.WriteEndObject();
            }
            writer.WriteStartArray("supported_transports");
            foreach (TransportProtocol endpoint in SupportedTransports)
            {
                writer.WriteStartObject();
                writer.WriteString("uri", endpoint.Uri);
                writer.WriteNumber("protocol", (int)endpoint.Protocol);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return buffer.ToArray();
    }

    /// <summary>Reads the JSON <see cref="ToWireJson"/> writes.</summary>
    internal static ContactMessage FromWireJson(byte[] json)
    {
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;
        return new ContactMessage(
            ChannelId: ulong.Parse(root.GetProperty("channel_id").GetString()!, CultureInfo.InvariantCulture),
            ContactMode: (ContactMode)root.GetProperty("contact_mode").GetInt32(),
            Nonce: ulong.Parse(root.GetProperty("nonce").GetString()!, CultureInfo.InvariantCulture),
            MlkemEncapsulationKey: ReadBytes(root, "mlkem_encapsulation_key"),
            EciesPublicKey: ReadBytes(root, "ecies_public_key"),
            ContactBindingHash: ReadBytes(root, "contact_binding_hash")
        )
        {
            SupportedTransports = root.GetProperty("supported_transports")
                .EnumerateArray()
                .Select(t => new TransportProtocol(
                    t.GetProperty("uri").GetString()!,
                    (Protocol)t.GetProperty("protocol").GetInt32()))
                .ToList(),
            Timestamp = root.TryGetProperty("timestamp", out JsonElement ts) && ts.ValueKind == JsonValueKind.Object
                ? new Timestamp(ts.GetProperty("seconds").GetInt64(), ts.GetProperty("nanos").GetInt32())
                : null,
        };
    }

    private static void WriteBytes(Utf8JsonWriter writer, string name, byte[]? value)
    {
        if (value is null)
        {
            return;
        }
        writer.WriteStartArray(name);
        foreach (byte b in value)
        {
            writer.WriteNumberValue(b);
        }
        writer.WriteEndArray();
    }

    private static byte[]? ReadBytes(JsonElement root, string name) =>
        root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Select(b => b.GetByte()).ToArray()
            : null;
}
