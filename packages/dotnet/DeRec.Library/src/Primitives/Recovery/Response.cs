// SPDX-License-Identifier: Apache-2.0

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace DeRec.Library.Primitives;

public static partial class Recovery
{
    public static class Response
    {
        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            /// <summary>
            /// Inner <c>GetShareResponseMessage</c> proto bytes. Accumulate
            /// across helpers and pass to <see cref="Recover"/>.
            /// </summary>
            public required byte[] ResponseProtoBytes { get; init; }
        }

        public static DeRecMessage Produce(
            ulong channelId,
            byte[] requestProtoBytes,
            byte[] storedShareProtoBytes,
            byte[] sharedKey
        )
        {
            Native.Recovery.ProduceGetShareResponseMessageResult nativeResult =
                Native.Recovery.produce_get_share_response_message(
                    channelId,
                    requestProtoBytes,
                    (UIntPtr)requestProtoBytes.Length,
                    storedShareProtoBytes,
                    (UIntPtr)storedShareProtoBytes.Length,
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
            byte[] responseWireBytes = response.ToProtoBytes();

            Native.Recovery.ExtractGetShareResponseResult nativeResult =
                Native.Recovery.extract_get_share_response(
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
        /// Reconstructs the original secret from a quorum of extracted helper
        /// responses. Each entry is the <c>ResponseProtoBytes</c> returned by
        /// <see cref="Extract"/>.
        /// </summary>
        public static byte[] Recover(
            IEnumerable<byte[]> extractedResponses,
            ulong secretId,
            uint version
        )
        {
            ArgumentNullException.ThrowIfNull(extractedResponses);
            byte[] serialized = SerializeResponses(extractedResponses);

            Native.Recovery.RecoverFromShareResponsesResult nativeResult =
                Native.Recovery.recover_from_share_responses(
                    serialized,
                    (UIntPtr)serialized.Length,
                    secretId,
                    version
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return Utils.CopyBuffer(nativeResult.SecretData);
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SecretData);
            }
        }

        private static byte[] SerializeResponses(IEnumerable<byte[]> responses)
        {
            List<byte[]> list = new(responses);

            using MemoryStream stream = new();
            using BinaryWriter writer = new(stream);

            writer.Write((uint)list.Count);

            foreach (byte[] bytes in list)
            {
                ArgumentNullException.ThrowIfNull(bytes);
                writer.Write((uint)bytes.Length);
                writer.Write(bytes);
            }

            writer.Flush();
            return stream.ToArray();
        }
    }
}
