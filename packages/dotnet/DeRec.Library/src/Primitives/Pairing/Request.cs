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

        public sealed class ProducePrePairResult
        {
            /// <summary>
            /// Serialized outer plaintext <see cref="DeRecMessage"/> envelope
            /// carrying a <c>PrePairRequestMessage</c>. Ready to send over
            /// transport.
            /// </summary>
            public required DeRecMessage Envelope { get; init; }
        }

        public sealed class ExtractPrePairResult
        {
            public required ulong ChannelId { get; init; }
            /// <summary>
            /// Inner <c>PrePairRequestMessage</c> proto bytes for chaining into
            /// <see cref="Response.ProducePrePair"/>.
            /// </summary>
            public required byte[] RequestProtoBytes { get; init; }
        }

        /// <summary>
        /// Creates an out-of-band <see cref="ContactMessage"/> to bootstrap pairing.
        /// </summary>
        /// <param name="channelId">Identifier for the local pairing session.</param>
        /// <param name="contactMode">
        /// <see cref="ContactMode.InlineKeys"/> embeds the keys directly;
        /// <see cref="ContactMode.HashedKeys"/> embeds only a SHA-384 commitment
        /// and the scanner must complete a <c>PrePair</c> round-trip first. For
        /// <see cref="ContactMode.HashedKeys"/> the <paramref name="transportProtocol"/>
        /// MUST be ephemeral.
        /// </param>
        /// <param name="transportProtocol">Endpoint the scanner uses to reach this initiator.</param>
        public static CreateContactResult CreateContact(
            ulong channelId,
            ContactMode contactMode,
            TransportProtocol transportProtocol
        )
        {
            byte[] transportProtocolBytes = transportProtocol.ToProtoBytes();

            Native.Pairing.CreateContactMessageResult nativeResult =
                Native.Pairing.create_contact_message(
                    channelId,
                    (int)contactMode,
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
        /// <paramref name="communicationInfo"/> and <paramref name="parameterRange"/>
        /// are optional and may be null. Both must be serialized proto
        /// bytes (<c>CommunicationInfo</c> and <c>ParameterRange</c>
        /// respectively).
        /// </summary>
        public static ProduceResult Produce(
            SenderKind kind,
            TransportProtocol transportProtocol,
            ContactMessage contactMessage,
            byte[]? communicationInfo = null,
            byte[]? parameterRange = null
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
                    (UIntPtr)(communicationInfo?.Length ?? 0),
                    parameterRange,
                    (UIntPtr)(parameterRange?.Length ?? 0)
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

        /// <summary>
        /// Scanner-side: builds a plaintext <c>PrePairRequest</c> envelope when
        /// the contact was sent with <see cref="ContactMode.HashedKeys"/>. The
        /// keys obtained via the matching <c>PrePairResponse</c> MUST be checked
        /// against the contact's binding hash with
        /// <see cref="Response.ProcessPrePair"/> before proceeding to a normal
        /// <see cref="Produce"/>.
        /// </summary>
        public static ProducePrePairResult ProducePrePair(
            TransportProtocol transportProtocol,
            ContactMessage contactMessage
        )
        {
            byte[] transportProtocolBytes = transportProtocol.ToProtoBytes();
            byte[] contactMessageBytes = contactMessage.ToProtoBytes();

            Native.Pairing.ProducePrePairRequestMessageResult nativeResult =
                Native.Pairing.produce_pre_pair_request_message(
                    transportProtocolBytes,
                    (UIntPtr)transportProtocolBytes.Length,
                    contactMessageBytes,
                    (UIntPtr)contactMessageBytes.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new ProducePrePairResult
                {
                    Envelope = DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.EnvelopeWireBytes)),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.EnvelopeWireBytes);
            }
        }

        /// <summary>
        /// Initiator-side: decodes an inbound plaintext <c>PrePairRequest</c>
        /// envelope.
        /// </summary>
        public static ExtractPrePairResult ExtractPrePair(DeRecMessage envelope)
        {
            byte[] envelopeBytes = envelope.ToProtoBytes();

            Native.Pairing.ExtractPrePairRequestResult nativeResult =
                Native.Pairing.extract_pre_pair_request(
                    envelopeBytes,
                    (UIntPtr)envelopeBytes.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new ExtractPrePairResult
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
