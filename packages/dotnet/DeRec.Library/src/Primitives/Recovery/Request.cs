// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;

namespace DeRec.Library.Primitives;

public static partial class Recovery
{
    public static class Request
    {
        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            /// <summary>
            /// Inner <c>GetShareRequestMessage</c> proto bytes for chaining
            /// into <see cref="Response.Produce"/>.
            /// </summary>
            public required byte[] RequestProtoBytes { get; init; }
            /// <summary>
            /// Optional response endpoint advertised by the sender on
            /// the inner request. Mirrors the JS bridge surface.
            /// </summary>
            public TransportProtocol? ReplyTo { get; init; }
        }

        public static DeRecMessage Produce(
            ulong channelId,
            ulong secretId,
            uint version,
            byte[] sharedKey,
            TransportProtocol? replyTo = null
        )
        {
            byte[]? replyToBytes = replyTo?.ToProtoBytes();
            UIntPtr replyToLen = replyToBytes is null ? UIntPtr.Zero : (UIntPtr)replyToBytes.Length;

            Native.Recovery.ProduceGetShareRequestMessageResult nativeResult =
                Native.Recovery.produce_get_share_request_message(
                    channelId,
                    secretId,
                    version,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    replyToBytes,
                    replyToLen
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.RequestWireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestWireBytes);
            }
        }

        public static ExtractResult Extract(DeRecMessage request, byte[] sharedKey)
        {
            byte[] requestWireBytes = request.ToProtoBytes();

            Native.Recovery.ExtractGetShareRequestResult nativeResult =
                Native.Recovery.extract_get_share_request(
                    requestWireBytes,
                    (UIntPtr)requestWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                byte[] innerBytes = Utils.CopyBuffer(nativeResult.RequestProtoBytes);
                var inner = Org.Derecalliance.Derec.Protobuf.GetShareRequestMessage.Parser
                    .ParseFrom(innerBytes);
                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
                    RequestProtoBytes = innerBytes,
                    ReplyTo = TransportProtocol.FromProto(inner.ReplyTo),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestProtoBytes);
            }
        }
    }
}
