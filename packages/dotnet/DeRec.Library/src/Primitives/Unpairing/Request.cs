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
            /// <summary>
            /// The channel the request asks to unpair: <see cref="ChannelId"/>
            /// for an ordinary unpair, a channel linked to it for a linked
            /// unpair.
            /// </summary>
            public required ulong UnpairChannelId { get; init; }
            public required string Memo { get; init; }
            /// <summary>
            /// Every endpoint the requester asked to be answered on, in its
            /// own preference order. Empty means route to the endpoints
            /// recorded for the channel.
            /// </summary>
            public IReadOnlyList<TransportProtocol> ReplyTo { get; init; } =
                Array.Empty<TransportProtocol>();
        }

        /// <summary>
        /// <c>epoch</c> is the epoch of <c>sharedKey</c> in the channel's key chain,
        /// stamped into the envelope's <c>sequence</c>; 0 for a freshly paired channel.
        /// <c>unpairChannelId</c> is the channel to unpair: <c>channelId</c> for an
        /// ordinary unpair, or a channel linked to it for a linked unpair, where the
        /// request travels on <c>channelId</c> and asks the peer to unpair the linked
        /// channel.
        /// </summary>
        public static DeRecMessage Produce(ulong channelId, string memo, byte[] sharedKey, uint epoch, ulong unpairChannelId, IReadOnlyList<TransportProtocol>? replyTo = null)
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
                    epoch,
                    replyToBytes,
                    replyToLen,
                    unpairChannelId
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
                    ? Marshal.PtrToStringUTF8(nativeResult.Memo) ?? string.Empty
                    : string.Empty;
                byte[] innerBytes = Utils.CopyBuffer(nativeResult.RequestProtoBytes);
                var inner = Org.Derecalliance.Derec.Protobuf.UnpairRequestMessage.Parser
                    .ParseFrom(innerBytes);
                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
                    UnpairChannelId = inner.ChannelId,
                    Memo = memo,
                    ReplyTo = TransportProtocol.ResolveReplyTo(inner.ReplyToTransports),
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
