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
            /// <summary>
            /// The channel the request named, echoed back by the answer.
            /// </summary>
            public required ulong UnpairChannelId { get; init; }
            public required byte[] ResponseProtoBytes { get; init; }
        }

        /// <summary>
        /// <c>epoch</c> is the epoch of <c>sharedKey</c> in the channel's key chain,
        /// stamped into the envelope's <c>sequence</c>; 0 for a freshly paired channel.
        /// <c>unpairChannelId</c> is the channel the request named
        /// (<see cref="Request.ExtractResult.UnpairChannelId"/>), which the answer names
        /// back: <c>channelId</c> for an ordinary unpair, the linked channel for a
        /// linked unpair.
        /// </summary>
        public static DeRecMessage Produce(ulong channelId, byte[] sharedKey, uint epoch, ulong unpairChannelId)
        {
            Native.Unpairing.ProduceUnpairResponseMessageResult nativeResult =
                Native.Unpairing.produce_unpair_response_message(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    epoch,
                    unpairChannelId
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
                byte[] innerBytes = Utils.CopyBuffer(nativeResult.ResponseProtoBytes);
                var inner = Org.Derecalliance.Derec.Protobuf.UnpairResponseMessage.Parser
                    .ParseFrom(innerBytes);
                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
                    UnpairChannelId = inner.ChannelId,
                    ResponseProtoBytes = innerBytes,
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
