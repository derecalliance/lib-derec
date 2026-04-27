// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class SecretSync
{
    public static class Response
    {
        /// <summary>
        /// Produces a secret sync response envelope.
        /// </summary>
        public static DeRecMessage Produce(ulong channelId, byte[] sharedKey)
        {
            Native.SecretSync.ProduceSecretSyncResponseResult nativeResult =
                Native.SecretSync.produce_secret_sync_response(
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
        /// Decodes, decrypts, and processes a secret sync response.
        /// </summary>
        public static void Process(DeRecMessage response, byte[] sharedKey)
        {
            byte[] responseWireBytes = response.ToProtoBytes();

            Native.SecretSync.ProcessSecretSyncResponseResult nativeResult =
                Native.SecretSync.process_secret_sync_response(
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
