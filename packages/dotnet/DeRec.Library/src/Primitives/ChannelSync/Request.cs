// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class ChannelSync
{
    public static class Request
    {
        public sealed class ExtractResult
        {
            public ulong ChannelId { get; init; }
            public byte[] SharedKey { get; init; } = Array.Empty<byte>();
        }

        /// <summary>
        /// Produces a channel sync request envelope.
        /// </summary>
        public static DeRecMessage Produce(ulong channelId, byte[] sharedKey, ulong newChannelId, byte[] newSharedKey)
        {
            Native.ChannelSync.ProduceChannelSyncRequestResult nativeResult =
                Native.ChannelSync.produce_channel_sync_request(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    newChannelId,
                    newSharedKey,
                    (UIntPtr)newSharedKey.Length
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
        /// Decodes and decrypts a channel sync request.
        /// </summary>
        public static ExtractResult Extract(DeRecMessage request, byte[] sharedKey)
        {
            byte[] requestWireBytes = request.ToProtoBytes();

            Native.ChannelSync.ExtractChannelSyncRequestResult nativeResult =
                Native.ChannelSync.extract_channel_sync_request(
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
                    ChannelId = nativeResult.ChannelId,
                    SharedKey = Utils.CopyBuffer(nativeResult.SharedKey),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SharedKey);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
