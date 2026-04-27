// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class ChannelSync
{
    public static class Response
    {
        /// <summary>
        /// Produces a channel sync response envelope.
        /// </summary>
        public static DeRecMessage Produce(ulong channelId, byte[] sharedKey)
        {
            Native.ChannelSync.ProduceChannelSyncResponseResult nativeResult =
                Native.ChannelSync.produce_channel_sync_response(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.ResponseWireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.ResponseWireBytes);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        /// <summary>
        /// Decodes, decrypts, and processes a channel sync response.
        /// </summary>
        public static void Process(DeRecMessage response, byte[] sharedKey)
        {
            byte[] responseWireBytes = response.ToProtoBytes();

            Native.ChannelSync.ProcessChannelSyncResponseResult nativeResult =
                Native.ChannelSync.process_channel_sync_response(
                    responseWireBytes,
                    (UIntPtr)responseWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);
            }
            finally
            {
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
