// SPDX-License-Identifier: Apache-2.0

using System;

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
            public required DeRecMessage Envelope { get; init; }
            public required ContactMessage InitiatorContactMessage { get; init; }
            public required byte[] SecretKeyMaterial { get; init; }
        }

        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            /// <summary>
            /// Inner <c>PairRequestMessage</c> proto bytes for chaining into
            /// <see cref="Response.Produce"/>.
            /// </summary>
            public required byte[] RequestProtoBytes { get; init; }
        }

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
                Utils.ThrowIfError(nativeResult.Error);
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
            }
        }

        /// <summary>
        /// Produces a pairing request envelope from a contact message.
        /// <paramref name="communicationInfo"/> is optional and may be null.
        /// </summary>
        public static ProduceResult Produce(
            SenderKind kind,
            TransportProtocol transportProtocol,
            ContactMessage contactMessage,
            byte[]? communicationInfo = null
        )
        {
            byte[] transportProtocolBytes = transportProtocol.ToProtoBytes();
            byte[] contactMessageBytes = contactMessage.ToProtoBytes();

            Native.Pairing.ProducePairRequestMessageResult nativeResult =
                Native.Pairing.produce_pair_request_message(
                    (int)kind,
                    transportProtocolBytes,
                    (UIntPtr)transportProtocolBytes.Length,
                    contactMessageBytes,
                    (UIntPtr)contactMessageBytes.Length,
                    communicationInfo,
                    (UIntPtr)(communicationInfo?.Length ?? 0)
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new ProduceResult
                {
                    Envelope = DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.RequestWireBytes)),
                    InitiatorContactMessage = ContactMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.InitiatorContactMessageWireBytes)),
                    SecretKeyMaterial = Utils.CopyBuffer(nativeResult.SecretKeyMaterial),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestWireBytes);
                Utils.FreeBuffer(nativeResult.InitiatorContactMessageWireBytes);
                Utils.FreeBuffer(nativeResult.SecretKeyMaterial);
            }
        }

        public static ExtractResult Extract(DeRecMessage request, byte[] secretKeyMaterial)
        {
            byte[] requestBytes = request.ToProtoBytes();

            Native.Pairing.ExtractPairRequestResult nativeResult =
                Native.Pairing.extract_pair_request(
                    requestBytes,
                    (UIntPtr)requestBytes.Length,
                    secretKeyMaterial,
                    (UIntPtr)secretKeyMaterial.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
                    RequestProtoBytes = Utils.CopyBuffer(nativeResult.RequestProtoBytes),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestProtoBytes);
            }
        }
    }
}
