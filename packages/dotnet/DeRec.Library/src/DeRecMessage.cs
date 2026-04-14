// SPDX-License-Identifier: Apache-2.0

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
    internal byte[] ToProtoBytes() => _protoBytes;

    /// <summary>Deserializes a <see cref="DeRecMessage"/> from protobuf wire bytes.</summary>
    internal static DeRecMessage FromProtoBytes(byte[] bytes)
    {
        var proto = Org.Derecalliance.Derec.Protobuf.DeRecMessage.Parser.ParseFrom(bytes);
        return new DeRecMessage(bytes, proto);
    }
}
