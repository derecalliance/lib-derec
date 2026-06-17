// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class Discovery
{
    public static class Request
    {
        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            /// <summary>
            /// Optional response endpoint advertised by the sender on
            /// the inner request. <c>null</c> when the sender did not set
            /// one. Mirrors the JS bridge surface.
            /// </summary>
            public TransportProtocol? ReplyTo { get; init; }
        }

        public static DeRecMessage Produce(ulong channelId, byte[] sharedKey, TransportProtocol? replyTo = null)
        {
            byte[]? replyToBytes = replyTo?.ToProtoBytes();
            UIntPtr replyToLen = replyToBytes is null ? UIntPtr.Zero : (UIntPtr)replyToBytes.Length;

            Native.Discovery.ProduceGetSecretIdsVersionsRequestMessageResult nativeResult =
                Native.Discovery.produce_get_secret_ids_versions_request_message(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    replyToBytes,
                    replyToLen
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.EnvelopeWireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.EnvelopeWireBytes);
            }
        }

        public static ExtractResult Extract(DeRecMessage request, byte[] sharedKey)
        {
            byte[] requestBytes = request.ToProtoBytes();

            Native.Discovery.ExtractGetSecretIdsVersionsRequestResult nativeResult =
                Native.Discovery.extract_get_secret_ids_versions_request(
                    requestBytes,
                    (UIntPtr)requestBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                byte[] innerBytes = Utils.CopyBuffer(nativeResult.RequestProtoBytes);
                var inner = Org.Derecalliance.Derec.Protobuf.GetSecretIdsVersionsRequestMessage.Parser
                    .ParseFrom(innerBytes);
                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
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
