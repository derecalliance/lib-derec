// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Primitives;

public static partial class Unpairing
{
    public static class Request
    {
        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            public required string Memo { get; init; }
            /// <summary>
            /// Optional response endpoint advertised by the sender on
            /// the inner request. Mirrors the JS bridge surface.
            /// </summary>
            /// <summary>
            /// Every endpoint the requester asked to be answered on, in its
            /// own preference order. Empty means route to the endpoints
            /// recorded for the channel.
            /// </summary>
            public IReadOnlyList<TransportProtocol> ReplyTo { get; init; } =
                Array.Empty<TransportProtocol>();
        }

        public static DeRecMessage Produce(ulong channelId, string memo, byte[] sharedKey, IReadOnlyList<TransportProtocol>? replyTo = null)
        {
            byte[] memoBytes = System.Text.Encoding.UTF8.GetBytes(memo ?? string.Empty);
            byte[]? replyToBytes = replyTo is { Count: > 0 }
                ? TransportProtocol.ToProtoBytesList(replyTo)
                : null;
            UIntPtr replyToLen = replyToBytes is null ? UIntPtr.Zero : (UIntPtr)replyToBytes.Length;

            Native.Unpairing.ProduceUnpairRequestMessageResult nativeResult =
                Native.Unpairing.produce_unpair_request_message(
                    channelId,
                    memoBytes,
                    (UIntPtr)memoBytes.Length,
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
            byte[] requestBytes = request.ToProtoBytes();

            Native.Unpairing.ExtractUnpairRequestResult nativeResult =
                Native.Unpairing.extract_unpair_request(
                    requestBytes,
                    (UIntPtr)requestBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                string memo = nativeResult.Memo != IntPtr.Zero
                    ? Marshal.PtrToStringAnsi(nativeResult.Memo) ?? string.Empty
                    : string.Empty;
                byte[] innerBytes = Utils.CopyBuffer(nativeResult.RequestProtoBytes);
                var inner = Org.Derecalliance.Derec.Protobuf.UnpairRequestMessage.Parser
                    .ParseFrom(innerBytes);
                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
                    Memo = memo,
                    ReplyTo = inner.ReplyTo.Select(TransportProtocol.FromProtoValue).ToList(),
                };
            }
            finally
            {
                if (nativeResult.Memo != IntPtr.Zero)
                {
                    Native.Utils.derec_free_string(nativeResult.Memo);
                }
                Utils.FreeBuffer(nativeResult.RequestProtoBytes);
            }
        }
    }
}
