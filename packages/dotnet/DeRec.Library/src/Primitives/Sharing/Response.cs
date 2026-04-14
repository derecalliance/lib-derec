// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class Sharing
{
    public static class Response
    {
        public sealed class ProduceResult
        {
            public required DeRecMessage Envelope { get; init; }
            public required byte[] CommittedShareBytes { get; init; }
            public required byte[] SecretId { get; init; }
            public required int Version { get; init; }
        }

        /// <summary>
        /// Processes an incoming sharing request on behalf of a Helper, producing an acknowledgement envelope.
        /// </summary>
        public static ProduceResult Produce(
            ulong channelId,
            byte[] sharedKey,
            DeRecMessage request
        )
        {
            if (sharedKey is null) throw new ArgumentNullException(nameof(sharedKey));
            if (sharedKey.Length != 32)
                throw new ArgumentException("sharedKey must be exactly 32 bytes.", nameof(sharedKey));
            if (request is null) throw new ArgumentNullException(nameof(request));

            byte[] requestBytes = request.ToProtoBytes();

            Native.Sharing.ProduceStoreShareResponseMessageResult nativeResult =
                Native.Sharing.produce_store_share_response_message(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    requestBytes,
                    (UIntPtr)requestBytes.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new ProduceResult
                {
                    Envelope = DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.WireBytes)),
                    CommittedShareBytes = Utils.CopyBuffer(nativeResult.CommittedShareBytes),
                    SecretId = Utils.CopyBuffer(nativeResult.SecretIdBytes),
                    Version = nativeResult.Version,
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.WireBytes);
                Utils.FreeBuffer(nativeResult.CommittedShareBytes);
                Utils.FreeBuffer(nativeResult.SecretIdBytes);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        /// <summary>
        /// Validates a sharing response received from a Helper. Throws on failure.
        /// </summary>
        public static void Process(
            int version,
            byte[] sharedKey,
            DeRecMessage response
        )
        {
            if (sharedKey is null) throw new ArgumentNullException(nameof(sharedKey));
            if (sharedKey.Length != 32)
                throw new ArgumentException("sharedKey must be exactly 32 bytes.", nameof(sharedKey));
            if (response is null) throw new ArgumentNullException(nameof(response));

            byte[] responseBytes = response.ToProtoBytes();

            Native.Sharing.ProcessStoreShareResponseMessageResult nativeResult =
                Native.Sharing.process_store_share_response_message(
                    version,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    responseBytes,
                    (UIntPtr)responseBytes.Length
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
