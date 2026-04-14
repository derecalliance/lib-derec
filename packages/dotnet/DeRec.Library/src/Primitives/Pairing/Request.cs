// SPDX-License-Identifier: Apache-2.0

namespace DeRec.Library.Primitives;

public static partial class Pairing
{
    public static class Request
    {
        public sealed class CreateContactResult
        {
            public required ContactMessage ContactMessage { get; init; }
            public required byte[] SecretKeyMaterial { get; init; }
        }

        public sealed class ProduceResult
        {
            public required byte[] Envelope { get; init; }
            public required ContactMessage InitiatorContactMessage { get; init; }
            public required byte[] SecretKeyMaterial { get; init; }
        }

        /// <summary>Creates a <c>ContactMessage</c> used to bootstrap pairing.</summary>
        public static CreateContactResult CreateContact(ulong channelId, TransportProtocol transportProtocol)
        {
            byte[] transportProtocolBytes = transportProtocol.ToProtoBytes();

            Native.Pairing.CreateContactMessageResult nativeResult =
                Native.Pairing.create_contact_message(
                    channelId,
                    transportProtocolBytes,
                    (UIntPtr)transportProtocolBytes.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new CreateContactResult
                {
                    ContactMessage = ContactMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.ContactWireBytes)),
                    SecretKeyMaterial = Utils.CopyBuffer(nativeResult.SecretKeyMaterial),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.ContactWireBytes);
                Utils.FreeBuffer(nativeResult.SecretKeyMaterial);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        /// <summary>Produces a pairing request envelope from a contact message.</summary>
        public static ProduceResult Produce(
            SenderKind kind,
            TransportProtocol transportProtocol,
            ContactMessage contactMessage
        )
        {
            byte[] transportProtocolBytes = transportProtocol.ToProtoBytes();
            byte[] contactMessageBytes = contactMessage.ToProtoBytes();

            Native.Pairing.ProducePairingRequestMessageResult nativeResult =
                Native.Pairing.produce_pairing_request_message(
                    (int)kind,
                    transportProtocolBytes,
                    (UIntPtr)transportProtocolBytes.Length,
                    contactMessageBytes,
                    (UIntPtr)contactMessageBytes.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new ProduceResult
                {
                    Envelope = Utils.CopyBuffer(nativeResult.RequestWireBytes),
                    InitiatorContactMessage = ContactMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.InitiatorContactMessageWireBytes)),
                    SecretKeyMaterial = Utils.CopyBuffer(nativeResult.SecretKeyMaterial),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestWireBytes);
                Utils.FreeBuffer(nativeResult.InitiatorContactMessageWireBytes);
                Utils.FreeBuffer(nativeResult.SecretKeyMaterial);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
