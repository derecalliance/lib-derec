// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;

namespace DeRec.Library.Primitives;

public static partial class Unpairing
{
    public static class Response
    {
        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            public required byte[] ResponseProtoBytes { get; init; }
        }

        public static DeRecMessage Produce(ulong channelId, byte[] sharedKey)
        {
            Native.Unpairing.ProduceUnpairResponseMessageResult nativeResult =
                Native.Unpairing.produce_unpair_response_message(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.ResponseWireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.ResponseWireBytes);
            }
        }

        public static ExtractResult Extract(DeRecMessage response, byte[] sharedKey)
        {
            byte[] responseBytes = response.ToProtoBytes();

            Native.Unpairing.ExtractUnpairResponseResult nativeResult =
                Native.Unpairing.extract_unpair_response(
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
        /// Validates the responder's unpair acknowledgement. Throws
        /// <see cref="DeRecException"/> on peer rejection.
        /// </summary>
        public static void Process(byte[] responseProtoBytes)
        {
            ArgumentNullException.ThrowIfNull(responseProtoBytes);

            Native.Unpairing.ProcessUnpairResponseResult nativeResult =
                Native.Unpairing.process_unpair_response_message(
                    responseProtoBytes,
                    (UIntPtr)responseProtoBytes.Length
                );

            Utils.ThrowIfError(nativeResult.Error);
        }
    }
}
