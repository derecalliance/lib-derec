// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;

namespace DeRec.Library.Primitives;

public static partial class Recovery
{
    public static class Response
    {
        public sealed class RecoveryInput
        {
            public required DeRecMessage Envelope { get; init; }
            public required byte[] SharedKey { get; init; }
        }

        /// <summary>
        /// Produces a recovery share response envelope (Helper side).
        /// </summary>
        public static DeRecMessage Produce(
            ulong channelId,
            byte[] secretId,
            DeRecMessage request,
            DeRecMessage storedShareRequest,
            byte[] sharedKey
        )
        {
            byte[] requestWireBytes = request.ToProtoBytes();
            byte[] storedShareRequestWireBytes = storedShareRequest.ToProtoBytes();

            Native.Recovery.ProduceGetShareResponseMessageResult nativeResult =
                Native.Recovery.produce_get_share_response_message(
                    channelId,
                    secretId,
                    (UIntPtr)secretId.Length,
                    requestWireBytes,
                    (UIntPtr)requestWireBytes.Length,
                    storedShareRequestWireBytes,
                    (UIntPtr)storedShareRequestWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.WireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.WireBytes);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        /// <summary>
        /// Reconstructs the original secret from a threshold of helper recovery responses (Owner side).
        /// </summary>
        public static byte[] Recover(
            IEnumerable<RecoveryInput> responses,
            byte[] secretId,
            int version
        )
        {
            byte[] serializedResponses = SerializeInputs(responses);

            Native.Recovery.RecoverFromShareResponsesResult nativeResult =
                Native.Recovery.recover_from_share_responses(
                    serializedResponses,
                    (UIntPtr)serializedResponses.Length,
                    secretId,
                    (UIntPtr)secretId.Length,
                    version
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return Utils.CopyBuffer(nativeResult.SecretData);
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SecretData);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        private static byte[] SerializeInputs(IEnumerable<RecoveryInput> responses)
        {
            List<RecoveryInput> list = new(responses);

            using MemoryStream stream = new();
            using BinaryWriter writer = new(stream);

            writer.Write((uint)list.Count);

            foreach (RecoveryInput response in list)
            {
                if (response.Envelope is null) throw new ArgumentNullException(nameof(response.Envelope));
                if (response.SharedKey is null) throw new ArgumentNullException(nameof(response.SharedKey));
                if (response.SharedKey.Length != 32)
                    throw new ArgumentException("SharedKey must be exactly 32 bytes.", nameof(response.SharedKey));

                byte[] envelopeBytes = response.Envelope.ToProtoBytes();
                writer.Write((uint)envelopeBytes.Length);
                writer.Write(envelopeBytes);
                writer.Write(response.SharedKey);
            }

            writer.Flush();
            return stream.ToArray();
        }
    }
}
