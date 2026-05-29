// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class Pairing
{
    public static class Response
    {
        public sealed class ProduceResult
        {
            public required DeRecMessage Envelope { get; init; }
            public required TransportProtocol PeerTransportProtocol { get; init; }
            public required byte[] SharedKey { get; init; }
        }

        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            /// <summary>
            /// Inner <c>PairResponseMessage</c> proto bytes for chaining into
            /// <see cref="Process"/>.
            /// </summary>
            public required byte[] ResponseProtoBytes { get; init; }
        }

        public sealed class ProcessResult
        {
            public required byte[] SharedKey { get; init; }
        }

        /// <summary>
        /// Produces a pairing response envelope and derives the shared key.
        /// </summary>
        public static ProduceResult Produce(
            SenderKind kind,
            byte[] requestProtoBytes,
            byte[] secretKeyMaterial,
            byte[]? communicationInfo = null
        )
        {
            Native.Pairing.ProducePairResponseMessageResult nativeResult =
                Native.Pairing.produce_pair_response_message(
                    (int)kind,
                    requestProtoBytes,
                    (UIntPtr)requestProtoBytes.Length,
                    secretKeyMaterial,
                    (UIntPtr)secretKeyMaterial.Length,
                    communicationInfo,
                    (UIntPtr)(communicationInfo?.Length ?? 0)
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new ProduceResult
                {
                    Envelope = DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.ResponseWireBytes)),
                    PeerTransportProtocol = TransportProtocol.FromProtoBytes(Utils.CopyBuffer(nativeResult.PeerTransportProtocol)),
                    SharedKey = Utils.CopyBuffer(nativeResult.SharedKey),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.ResponseWireBytes);
                Utils.FreeBuffer(nativeResult.PeerTransportProtocol);
                Utils.FreeBuffer(nativeResult.SharedKey);
            }
        }

        public static ExtractResult Extract(DeRecMessage response, byte[] secretKeyMaterial)
        {
            byte[] responseBytes = response.ToProtoBytes();

            Native.Pairing.ExtractPairResponseResult nativeResult =
                Native.Pairing.extract_pair_response(
                    responseBytes,
                    (UIntPtr)responseBytes.Length,
                    secretKeyMaterial,
                    (UIntPtr)secretKeyMaterial.Length
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
        /// Processes a pairing response and derives the shared key. Throws
        /// <see cref="DeRecException"/> on peer rejection.
        /// </summary>
        public static ProcessResult Process(
            ContactMessage contactMessage,
            byte[] responseProtoBytes,
            byte[] secretKeyMaterial
        )
        {
            byte[] contactMessageBytes = contactMessage.ToProtoBytes();

            Native.Pairing.ProcessPairResponseMessageResult nativeResult =
                Native.Pairing.process_pair_response_message(
                    contactMessageBytes,
                    (UIntPtr)contactMessageBytes.Length,
                    responseProtoBytes,
                    (UIntPtr)responseProtoBytes.Length,
                    secretKeyMaterial,
                    (UIntPtr)secretKeyMaterial.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new ProcessResult
                {
                    SharedKey = Utils.CopyBuffer(nativeResult.SharedKey),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SharedKey);
            }
        }
    }
}
