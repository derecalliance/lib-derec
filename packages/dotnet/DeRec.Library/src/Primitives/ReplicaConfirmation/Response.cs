// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class ReplicaConfirmation
{
    public static class Response
    {
        public sealed class ProcessResult
        {
            public int ReplicaId { get; init; }
        }

        /// <summary>
        /// Produces a replica confirmation response envelope.
        /// </summary>
        public static DeRecMessage Produce(ulong channelId, byte[] sharedKey, int replicaId)
        {
            Native.ReplicaConfirmation.ProduceReplicaConfirmationResponseResult nativeResult =
                Native.ReplicaConfirmation.produce_replica_confirmation_response(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    replicaId
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
        /// Decodes, decrypts, and validates a replica confirmation response.
        /// </summary>
        public static ProcessResult Process(DeRecMessage response, byte[] sharedKey)
        {
            byte[] responseWireBytes = response.ToProtoBytes();

            Native.ReplicaConfirmation.ProcessReplicaConfirmationResponseResult nativeResult =
                Native.ReplicaConfirmation.process_replica_confirmation_response(
                    responseWireBytes,
                    (UIntPtr)responseWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new ProcessResult
                {
                    ReplicaId = nativeResult.ReplicaId,
                };
            }
            finally
            {
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
