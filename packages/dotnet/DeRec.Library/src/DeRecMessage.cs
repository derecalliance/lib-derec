// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library;

/// <summary>
/// Decoded representation of a DeRec outer <c>DeRecMessage</c> envelope.
///
/// The encrypted inner payload is preserved opaquely and round-trips through the
/// library via <see cref="ToProtoBytes"/> / <see cref="FromProtoBytes"/>.
/// </summary>
public sealed class DeRecMessage
{
    public uint ProtocolVersionMajor { get; }
    public uint ProtocolVersionMinor { get; }
    public uint Sequence { get; }
    public ulong ChannelId { get; }

    private readonly byte[] _protoBytes;

    private DeRecMessage(byte[] protoBytes, Org.Derecalliance.Derec.Protobuf.DeRecMessage proto)
    {
        _protoBytes = protoBytes;
        ProtocolVersionMajor = proto.ProtocolVersionMajor;
        ProtocolVersionMinor = proto.ProtocolVersionMinor;
        Sequence = proto.Sequence;
        ChannelId = proto.ChannelId;
    }

    /// <summary>Serializes this envelope back to protobuf wire bytes.</summary>
    public byte[] ToProtoBytes() => _protoBytes;

    /// <summary>
    /// Deserializes a <see cref="DeRecMessage"/> from protobuf wire bytes.
    /// </summary>
    /// <remarks>
    /// The library does not enforce an upper bound on
    /// <paramref name="bytes"/>.<c>Length</c>: legitimate envelopes range
    /// from tens of bytes (acks) to many MB (replica vault sync). Callers
    /// MUST bound inbound size at the transport layer before reaching this
    /// method, consistent with their deployment's maximum secret size,
    /// helper count, and replica fan-out.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown if <paramref name="bytes"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="Google.Protobuf.InvalidProtocolBufferException">
    /// Thrown if <paramref name="bytes"/> is not a well-formed
    /// <c>DeRecMessage</c> envelope.
    /// </exception>
    public static DeRecMessage FromProtoBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        var proto = Org.Derecalliance.Derec.Protobuf.DeRecMessage.Parser.ParseFrom(bytes);
        return new DeRecMessage(bytes, proto);
    }
}
