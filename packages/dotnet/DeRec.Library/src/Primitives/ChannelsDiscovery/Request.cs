// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class ChannelsDiscovery
{
    public static class Request
    {
        public sealed class ExtractResult
        {
            public int LastBatchIndex { get; init; }
        }

        /// <summary>
        /// Produces a channels discovery request envelope.
        /// </summary>
        public static DeRecMessage Produce(ulong channelId, byte[] sharedKey, int lastBatchIndex)
        {
            Native.ChannelsDiscovery.ProduceChannelsDiscoveryRequestResult nativeResult =
                Native.ChannelsDiscovery.produce_channels_discovery_request(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    lastBatchIndex
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.RequestWireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestWireBytes);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        /// <summary>
        /// Decodes and decrypts a channels discovery request.
        /// </summary>
        public static ExtractResult Extract(DeRecMessage request, byte[] sharedKey)
        {
            byte[] requestWireBytes = request.ToProtoBytes();

            Native.ChannelsDiscovery.ExtractChannelsDiscoveryRequestResult nativeResult =
                Native.ChannelsDiscovery.extract_channels_discovery_request(
                    requestWireBytes,
                    (UIntPtr)requestWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new ExtractResult
                {
                    LastBatchIndex = nativeResult.LastBatchIndex,
                };
            }
            finally
            {
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
