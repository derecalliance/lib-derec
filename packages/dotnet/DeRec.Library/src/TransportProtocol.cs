// SPDX-License-Identifier: Apache-2.0

using Google.Protobuf;

namespace DeRec.Library;

/// <summary>
/// Supported transport protocols for DeRec communication.
/// </summary>
public enum Protocol
{
    /// <summary>HTTPS-based transport (default).</summary>
    Https = 0,
}

/// <summary>
/// Describes how a DeRec participant can be reached over the network.
/// </summary>
/// <param name="Uri">
/// The transport endpoint URI (e.g. <c>"https://example.com/derec"</c>).
/// </param>
/// <param name="Protocol">
/// The transport protocol. Defaults to <see cref="Protocol.Https"/>.
/// </param>
public sealed record TransportProtocol(string Uri, Protocol Protocol = Protocol.Https)
{
    /// <summary>Serializes this value to protobuf wire bytes for FFI.</summary>
    internal byte[] ToProtoBytes()
    {
        var proto = new Org.Derecalliance.Derec.Protobuf.TransportProtocol
        {
            Uri = Uri,
            Protocol = (Org.Derecalliance.Derec.Protobuf.Protocol)(int)Protocol,
        };
        return proto.ToByteArray();
    }

    /// <summary>Deserializes a <see cref="TransportProtocol"/> from protobuf wire bytes.</summary>
    internal static TransportProtocol FromProtoBytes(byte[] bytes)
    {
        var proto = Org.Derecalliance.Derec.Protobuf.TransportProtocol.Parser.ParseFrom(bytes);
        return new TransportProtocol(
            Uri: proto.Uri,
            Protocol: (Protocol)(int)proto.Protocol
        );
    }
}
