// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class SecretsDiscovery
{
    public static class Request
    {
        public sealed class ExtractResult
        {
            public int LastBatchIndex { get; init; }
        }

        /// <summary>
        /// Produces a secrets discovery request envelope.
        /// </summary>
        public static DeRecMessage Produce(ulong channelId, byte[] sharedKey, int lastBatchIndex)
        {
            Native.SecretsDiscovery.ProduceSecretsDiscoveryRequestResult nativeResult =
                Native.SecretsDiscovery.produce_secrets_discovery_request(
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
        /// Decodes and decrypts a secrets discovery request.
        /// </summary>
        public static ExtractResult Extract(DeRecMessage request, byte[] sharedKey)
        {
            byte[] requestWireBytes = request.ToProtoBytes();

            Native.SecretsDiscovery.ExtractSecretsDiscoveryRequestResult nativeResult =
                Native.SecretsDiscovery.extract_secrets_discovery_request(
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
