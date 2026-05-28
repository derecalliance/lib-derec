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
        }

        public static DeRecMessage Produce(ulong channelId, byte[] sharedKey)
        {
            Native.Discovery.ProduceGetSecretIdsVersionsRequestMessageResult nativeResult =
                Native.Discovery.produce_get_secret_ids_versions_request_message(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
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

            Utils.ThrowIfError(nativeResult.Error);
            return new ExtractResult { ChannelId = nativeResult.ChannelId };
        }
    }
}
