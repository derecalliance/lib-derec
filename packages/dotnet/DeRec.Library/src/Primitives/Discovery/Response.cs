// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

namespace DeRec.Library.Primitives;

public static partial class Discovery
{
    public static class Response
    {
        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            public required byte[] ResponseProtoBytes { get; init; }
        }

        public static DeRecMessage Produce(
            ulong channelId,
            IReadOnlyList<SecretVersionEntry> secretList,
            byte[] sharedKey
        )
        {
            ArgumentNullException.ThrowIfNull(secretList);
            byte[] secretListBytes = DiscoveryWireFormat.Serialize(secretList);

            Native.Discovery.ProduceGetSecretIdsVersionsResponseMessageResult nativeResult =
                Native.Discovery.produce_get_secret_ids_versions_response_message(
                    channelId,
                    secretListBytes,
                    (UIntPtr)secretListBytes.Length,
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

        public static ExtractResult Extract(DeRecMessage response, byte[] sharedKey)
        {
            byte[] responseBytes = response.ToProtoBytes();

            Native.Discovery.ExtractGetSecretIdsVersionsResponseResult nativeResult =
                Native.Discovery.extract_get_secret_ids_versions_response(
                    responseBytes,
                    (UIntPtr)responseBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
                    ResponseProtoBytes = Utils.CopyBuffer(nativeResult.ResponseProtoBytes),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.ResponseProtoBytes);
            }
        }

        /// <summary>
        /// Validates a discovery response and returns the parsed secret list.
        /// Throws <see cref="DeRecException"/> on peer rejection.
        /// </summary>
        public static List<SecretVersionEntry> Process(byte[] responseProtoBytes)
        {
            ArgumentNullException.ThrowIfNull(responseProtoBytes);

            Native.Discovery.ProcessGetSecretIdsVersionsResponseMessageResult nativeResult =
                Native.Discovery.process_get_secret_ids_versions_response_message(
                    responseProtoBytes,
                    (UIntPtr)responseProtoBytes.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return DiscoveryWireFormat.Deserialize(Utils.CopyBuffer(nativeResult.SecretListBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SecretListBytes);
            }
        }
    }
}
