// SPDX-License-Identifier: Apache-2.0

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
        }

        public static DeRecMessage Produce(
            ulong channelId,
            ulong secretId,
            uint version,
            byte[] sharedKey
        )
        {
            Native.Recovery.ProduceGetShareRequestMessageResult nativeResult =
                Native.Recovery.produce_get_share_request_message(
                    channelId,
                    secretId,
                    version,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
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
                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
                    RequestProtoBytes = Utils.CopyBuffer(nativeResult.RequestProtoBytes),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestProtoBytes);
            }
        }
    }
}
