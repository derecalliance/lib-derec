// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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
        /// Single entry point for all three <see cref="ContactMode"/> variants.
        /// </summary>
        /// <param name="channelId">Identifier for the local pairing session.</param>
        /// <param name="contactMode">
        /// <see cref="ContactMode.InlineKeys"/> embeds the keys directly;
        /// <see cref="ContactMode.HashedKeys"/> embeds only a SHA-384 commitment
        /// and the scanner must complete a <c>PrePair</c> round-trip first;
        /// <see cref="ContactMode.NoKeys"/> carries no keys — the creator
        /// generates them on the fly when the <c>PrePairRequest</c> arrives
        /// (only appropriate when the OOB delivery channel is fully trusted).
        /// </param>
        /// <param name="transportProtocols">Every endpoint this initiator serves, in
        /// preference order. The whole list is advertised.</param>
        /// <param name="nonce"><c>null</c> lets the library generate a fresh
        /// random <c>ulong</c>. Required for <see cref="ContactMode.NoKeys"/>
        /// where callers typically pick a small human-typable value.</param>
        public static CreateContactResult CreateContact(
            ulong channelId,
            ContactMode contactMode,
            IReadOnlyList<TransportProtocol> transportProtocols,
            ulong? nonce = null
        )
        {
            byte[] transportProtocolBytes = TransportProtocol.ToProtoBytesList(transportProtocols);
            uint hasNonce = nonce.HasValue ? 1u : 0u;
            ulong nonceValue = nonce ?? 0ul;

            Native.Pairing.CreateContactMessageResult nativeResult =
                Native.Pairing.create_contact_message(
                    channelId,
                    (int)contactMode,
                    transportProtocolBytes,
                    (UIntPtr)transportProtocolBytes.Length,
                    hasNonce,
                    nonceValue
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new CreateContactResult
                {
                    ContactMessage = DecodeContact(Utils.CopyBuffer(nativeResult.ContactWireBytes)),
                    // Empty for NoKeys (no key material at contact-creation
                    // time); populated for InlineKeys / HashedKeys.
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
        /// Serializes a <see cref="ContactMessage"/> to the protobuf bytes
        /// delivered out of band (typically as a QR code).
        /// </summary>
        /// <exception cref="DeRecException">
        /// The contact violates the invariants of its <see cref="ContactMode"/>,
        /// or advertises no endpoint.
        /// </exception>
        public static byte[] EncodeContact(ContactMessage contactMessage)
        {
            byte[] json = contactMessage.ToWireJson();

            Native.Pairing.EncodeContactMessageResult nativeResult =
                Native.Pairing.encode_contact_message(json, (UIntPtr)json.Length);

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return Utils.CopyBuffer(nativeResult.WireBytes);
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.WireBytes);
            }
        }

        /// <summary>
        /// Parses out-of-band contact bytes back into the
        /// <see cref="ContactMessage"/> a scanner pairs against.
        /// </summary>
        /// <exception cref="DeRecException">
        /// The bytes are not a contact, or the contact violates the invariants
        /// of its <see cref="ContactMode"/>.
        /// </exception>
        public static ContactMessage DecodeContact(byte[] bytes)
        {
            Native.Pairing.DecodeContactMessageResult nativeResult =
                Native.Pairing.decode_contact_message(bytes, (UIntPtr)bytes.Length);

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return ContactMessage.FromWireJson(Utils.CopyBuffer(nativeResult.ContactJson));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.ContactJson);
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
            IReadOnlyList<TransportProtocol> transportProtocols,
            ContactMessage contactMessage,
            byte[]? communicationInfo = null,
            byte[]? parameterRange = null
        )
        {
            byte[] transportProtocolBytes = TransportProtocol.ToProtoBytesList(transportProtocols);
            byte[] contactMessageBytes = EncodeContact(contactMessage);

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
                    InitiatorContactMessage = DecodeContact(Utils.CopyBuffer(nativeResult.InitiatorContactMessageWireBytes)),
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

        /// <summary>
        /// Decrypts a pairing request. <paramref name="parameterRange"/> is the
        /// serialized <c>ParameterRange</c> this side accepts, or null for none;
        /// a request advertising a range that does not overlap it is refused
        /// with <see cref="DeRecCode.IncompatibleParameterRange"/>.
        /// </summary>
        public static ExtractResult Extract(
            DeRecMessage request,
            byte[] secretKeyMaterial,
            byte[]? parameterRange = null
        )
        {
            byte[] requestBytes = request.ToProtoBytes();

            Native.Pairing.ExtractPairRequestResult nativeResult =
                Native.Pairing.extract_pair_request(
                    requestBytes,
                    (UIntPtr)requestBytes.Length,
                    secretKeyMaterial,
                    (UIntPtr)secretKeyMaterial.Length,
                    parameterRange,
                    (UIntPtr)(parameterRange?.Length ?? 0)
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
        /// the contact was sent with <see cref="ContactMode.HashedKeys"/> or
        /// <see cref="ContactMode.NoKeys"/>. The matching <c>PrePairResponse</c>
        /// MUST go through <see cref="Response.ProcessPrePair"/> (HashedKeys) or
        /// <see cref="Response.ProcessPrePairNoKeys"/> (NoKeys) before proceeding
        /// to a normal <see cref="Produce"/>.
        /// </summary>
        public static ProducePrePairResult ProducePrePair(
            IReadOnlyList<TransportProtocol> transportProtocols,
            ContactMessage contactMessage
        )
        {
            byte[] transportProtocolBytes = TransportProtocol.ToProtoBytesList(transportProtocols);
            byte[] contactMessageBytes = EncodeContact(contactMessage);

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
