// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System.Text.Json.Serialization;

using Google.Protobuf;

namespace DeRec.Library;

/// <summary>
/// Supported transport protocols for DeRec communication.
/// </summary>
public enum Protocol
{
    /// <summary>HTTPS-based transport (default).</summary>
    Https = 0,

    /// <summary>gRPC-based transport. URIs are grpcs:// or grpc://.</summary>
    Grpc = 1,
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
public sealed record TransportProtocol(
    [property: JsonPropertyName("uri")] string Uri,
    [property: JsonPropertyName("protocol")] Protocol Protocol = Protocol.Https)
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

    /// <summary>
    /// Frames a preference-ordered list of endpoints for the FFI seam: each
    /// entry preceded by its protobuf varint byte length, which is the same
    /// framing protobuf itself uses for a repeated embedded message field.
    /// Order is preserved exactly.
    /// </summary>
    internal static byte[] ToProtoBytesList(IReadOnlyList<TransportProtocol> transports)
    {
        using var buffer = new MemoryStream();
        foreach (var transport in transports)
        {
            byte[] entry = transport.ToProtoBytes();
            ulong remaining = (ulong)entry.Length;
            do
            {
                byte b = (byte)(remaining & 0x7F);
                remaining >>= 7;
                if (remaining != 0)
                {
                    b |= 0x80;
                }
                buffer.WriteByte(b);
            } while (remaining != 0);
            buffer.Write(entry, 0, entry.Length);
        }
        return buffer.ToArray();
    }

    /// <summary>
    /// Reads the framing <see cref="ToProtoBytesList"/> writes. Order is the
    /// sender's and is preserved exactly; the library filters a peer's
    /// endpoints but never ranks them, so choosing between the survivors
    /// belongs to the caller.
    /// </summary>
    internal static IReadOnlyList<TransportProtocol> FromProtoBytesList(byte[] framed)
    {
        var endpoints = new List<TransportProtocol>();
        int offset = 0;
        while (offset < framed.Length)
        {
            int size = 0;
            int shift = 0;
            while (true)
            {
                if (offset >= framed.Length)
                {
                    throw new InvalidOperationException(
                        "truncated transport list: length prefix runs past the end");
                }
                byte b = framed[offset++];
                size |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }
            if (size < 0 || offset + size > framed.Length)
            {
                throw new InvalidOperationException(
                    "truncated transport list: entry runs past the end");
            }
            var entry = new byte[size];
            Array.Copy(framed, offset, entry, 0, size);
            offset += size;
            endpoints.Add(FromProtoBytes(entry));
        }
        return endpoints;
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

    /// <summary>
    /// Convert a wire <c>TransportProtocol</c> proto field (optional) to
    /// a typed <see cref="TransportProtocol"/>. Returns <c>null</c> when
    /// the proto field is unset.
    /// </summary>
    internal static TransportProtocol? FromProto(Org.Derecalliance.Derec.Protobuf.TransportProtocol? proto) =>
        proto is null
            ? null
            : new TransportProtocol(proto.Uri, (Protocol)(int)proto.Protocol);

    /// <summary>
    /// Convert a present wire <c>TransportProtocol</c> to a typed
    /// <see cref="TransportProtocol"/>. For elements of a repeated field,
    /// where absence is expressed by the list being empty rather than by a
    /// null element.
    /// </summary>
    internal static TransportProtocol FromProtoValue(Org.Derecalliance.Derec.Protobuf.TransportProtocol proto) =>
        new(proto.Uri, (Protocol)(int)proto.Protocol);

    /// <summary>
    /// Resolve a request's <c>replyTo</c> / <c>replyToTransports</c> pair into
    /// the endpoints the requester asked to be answered on, in its own order.
    /// </summary>
    /// <remarks>
    /// Yields <paramref name="list"/> when it is non-empty, and otherwise the
    /// singular <paramref name="legacy"/> — which is how every implementation
    /// predating the list asks, and the reason this is a method rather than a
    /// property read. An empty result means the requester named no endpoint at
    /// all, which tells the responder to answer on the endpoints recorded for
    /// the channel.
    /// </remarks>
    internal static IReadOnlyList<TransportProtocol> ResolveReplyTo(
        Org.Derecalliance.Derec.Protobuf.TransportProtocol? legacy,
        IEnumerable<Org.Derecalliance.Derec.Protobuf.TransportProtocol> list)
    {
        var resolved = list.Select(FromProtoValue).ToList();
        if (resolved.Count > 0)
        {
            return resolved;
        }
        return legacy is null
            ? Array.Empty<TransportProtocol>()
            : new[] { FromProtoValue(legacy) };
    }
}
