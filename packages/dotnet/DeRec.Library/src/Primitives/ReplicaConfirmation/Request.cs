// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class ReplicaConfirmation
{
    public static class Request
    {
        public sealed class ProduceResult
        {
            public DeRecMessage Envelope { get; init; } = default!;
            /// <summary>Fingerprint formatted as "XXXX-XXXX-XXXX-XXXX".</summary>
            public string Fingerprint { get; init; } = string.Empty;
        }

        public sealed class ExtractResult
        {
            public int ReplicaId { get; init; }
            /// <summary>Fingerprint formatted as "XXXX-XXXX-XXXX-XXXX".</summary>
            public string Fingerprint { get; init; } = string.Empty;
        }

        /// <summary>
        /// Produces a replica confirmation request envelope.
        /// </summary>
        public static ProduceResult Produce(ulong channelId, byte[] sharedKey, int replicaId)
        {
            Native.ReplicaConfirmation.ProduceReplicaConfirmationRequestResult nativeResult =
                Native.ReplicaConfirmation.produce_replica_confirmation_request(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    replicaId
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new ProduceResult
                {
                    Envelope = DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.RequestWireBytes)),
                    Fingerprint = System.Text.Encoding.UTF8.GetString(Utils.CopyBuffer(nativeResult.Fingerprint)),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestWireBytes);
                Utils.FreeBuffer(nativeResult.Fingerprint);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        /// <summary>
        /// Decodes and verifies a replica confirmation request.
        /// </summary>
        public static ExtractResult Extract(DeRecMessage request, byte[] sharedKey)
        {
            byte[] requestWireBytes = request.ToProtoBytes();

            Native.ReplicaConfirmation.ExtractReplicaConfirmationRequestResult nativeResult =
                Native.ReplicaConfirmation.extract_replica_confirmation_request(
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
                    ReplicaId = nativeResult.ReplicaId,
                    Fingerprint = System.Text.Encoding.UTF8.GetString(Utils.CopyBuffer(nativeResult.Fingerprint)),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.Fingerprint);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
