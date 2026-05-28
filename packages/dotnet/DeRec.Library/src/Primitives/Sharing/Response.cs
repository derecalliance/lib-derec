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
            public required ulong SecretId { get; init; }
            public required uint Version { get; init; }
        }

        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            /// <summary>
            /// Inner <c>StoreShareResponseMessage</c> proto bytes for chaining
            /// into <see cref="Process"/>.
            /// </summary>
            public required byte[] ResponseProtoBytes { get; init; }
        }

        public static ProduceResult Produce(
            ulong channelId,
            byte[] requestProtoBytes,
            byte[] sharedKey
        )
        {
            ArgumentNullException.ThrowIfNull(requestProtoBytes);
            ArgumentNullException.ThrowIfNull(sharedKey);
            if (sharedKey.Length != 32)
                throw new ArgumentException("sharedKey must be exactly 32 bytes.", nameof(sharedKey));

            Native.Sharing.ProduceStoreShareResponseMessageResult nativeResult =
                Native.Sharing.produce_store_share_response_message(
                    channelId,
                    requestProtoBytes,
                    (UIntPtr)requestProtoBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new ProduceResult
                {
                    Envelope = DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.WireBytes)),
                    CommittedShareBytes = Utils.CopyBuffer(nativeResult.CommittedShareBytes),
                    SecretId = nativeResult.SecretId,
                    Version = nativeResult.Version,
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.WireBytes);
                Utils.FreeBuffer(nativeResult.CommittedShareBytes);
            }
        }

        public static ExtractResult Extract(DeRecMessage response, byte[] sharedKey)
        {
            byte[] responseWireBytes = response.ToProtoBytes();

            Native.Sharing.ExtractStoreShareResponseResult nativeResult =
                Native.Sharing.extract_store_share_response(
                    responseWireBytes,
                    (UIntPtr)responseWireBytes.Length,
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
        /// Validates the helper's store-share acknowledgement. Throws
        /// <see cref="DeRecException"/> on peer rejection
        /// (<see cref="Native.DeRecCode.NonOkStatus"/>) or version mismatch
        /// (<see cref="Native.DeRecCode.VersionMismatch"/>).
        /// </summary>
        public static void Process(uint version, byte[] responseProtoBytes)
        {
            ArgumentNullException.ThrowIfNull(responseProtoBytes);

            Native.Sharing.ProcessStoreShareResponseMessageResult nativeResult =
                Native.Sharing.process_store_share_response_message(
                    version,
                    responseProtoBytes,
                    (UIntPtr)responseProtoBytes.Length
                );

            Utils.ThrowIfError(nativeResult.Error);
        }
    }
}
