// SPDX-License-Identifier: Apache-2.0

namespace DeRec.Library.Primitives;

public static partial class Pairing
{
    public static class Response
    {
        public sealed class ProduceResult
        {
            public required byte[] Envelope { get; init; }
            public required TransportProtocol ResponderTransportProtocol { get; init; }
            public required byte[] SharedKey { get; init; }
        }

        public sealed class ProcessResult
        {
            public required byte[] SharedKey { get; init; }
        }

        /// <summary>
        /// Produces a pairing response envelope and derives the initiator-side shared key.
        /// </summary>
        public static ProduceResult Produce(
            SenderKind kind,
            byte[] pairRequest,
            byte[] pairingSecretKeyMaterial
        )
        {
            Native.Pairing.ProducePairingResponseMessageResult nativeResult =
                Native.Pairing.produce_pairing_response_message(
                    (int)kind,
                    pairRequest,
                    (UIntPtr)pairRequest.Length,
                    pairingSecretKeyMaterial,
                    (UIntPtr)pairingSecretKeyMaterial.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new ProduceResult
                {
                    Envelope = Utils.CopyBuffer(nativeResult.ResponseWireBytes),
                    ResponderTransportProtocol = TransportProtocol.FromProtoBytes(Utils.CopyBuffer(nativeResult.ResponderTransportProtocol)),
                    SharedKey = Utils.CopyBuffer(nativeResult.SharedKey),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.ResponseWireBytes);
                Utils.FreeBuffer(nativeResult.ResponderTransportProtocol);
                Utils.FreeBuffer(nativeResult.SharedKey);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        /// <summary>
        /// Processes a pairing response envelope and derives the responder-side shared key.
        /// </summary>
        public static ProcessResult Process(
            ContactMessage contactMessage,
            byte[] pairResponse,
            byte[] pairingSecretKeyMaterial
        )
        {
            byte[] contactMessageBytes = contactMessage.ToProtoBytes();

            Native.Pairing.ProcessPairingResponseMessageResult nativeResult =
                Native.Pairing.process_pairing_response_message(
                    contactMessageBytes,
                    (UIntPtr)contactMessageBytes.Length,
                    pairResponse,
                    (UIntPtr)pairResponse.Length,
                    pairingSecretKeyMaterial,
                    (UIntPtr)pairingSecretKeyMaterial.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new ProcessResult
                {
                    SharedKey = Utils.CopyBuffer(nativeResult.SharedKey),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SharedKey);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
