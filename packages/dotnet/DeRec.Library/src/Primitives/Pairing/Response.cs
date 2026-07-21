// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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
            /// <summary>
            /// Post-handshake rekey channel id the responder is committing to.
            /// Callers MUST atomically rename their local channel record from the
            /// pre-rekey id (the one passed to <see cref="Produce"/>) to this
            /// value as part of accepting the response.
            /// </summary>
            public required ulong ChannelId { get; init; }
        }

        public sealed class ExtractResult
        {
            /// <summary>
            /// Channel id taken from the outer envelope's routing field. This
            /// is the <em>pre-rekey</em> id used to look up the in-flight
            /// pairing session locally. The post-rekey id lives in the inner
            /// response and is surfaced by <see cref="Process"/>.
            /// </summary>
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
            /// <summary>
            /// Post-handshake rekey channel id — already validated against the
            /// caller's own derivation. Callers MUST atomically rename their
            /// local channel record from the pre-rekey id (the one in the
            /// contact) to this value.
            /// </summary>
            public required ulong ChannelId { get; init; }
        }

        public sealed class ProducePrePairResult
        {
            /// <summary>
            /// Serialized outer plaintext <see cref="DeRecMessage"/> envelope
            /// carrying a <c>PrePairResponseMessage</c>. Ready to send over
            /// transport.
            /// </summary>
            public required DeRecMessage Envelope { get; init; }
        }

        public sealed class ExtractPrePairResult
        {
            public required ulong ChannelId { get; init; }
            /// <summary>
            /// Inner <c>PrePairResponseMessage</c> proto bytes for chaining into
            /// <see cref="ProcessPrePair"/>.
            /// </summary>
            public required byte[] ResponseProtoBytes { get; init; }
        }

        public sealed class ProcessPrePairResult
        {
            /// <summary>
            /// Initiator's ML-KEM-768 encapsulation key, validated against the
            /// contact's <c>contactBindingHash</c>.
            /// </summary>
            public required byte[] MlkemEncapsulationKey { get; init; }
            /// <summary>
            /// Initiator's ECIES public key, validated against the contact's
            /// <c>contactBindingHash</c>.
            /// </summary>
            public required byte[] EciesPublicKey { get; init; }
            /// <summary>Nonce echoed from the original <see cref="ContactMessage"/>.</summary>
            public required ulong Nonce { get; init; }
        }

        /// <summary>
        /// Produces a pairing response envelope and derives the shared key.
        /// <paramref name="communicationInfo"/> and <paramref name="parameterRange"/>
        /// are optional and may be null. Both must be serialized proto
        /// bytes (<c>CommunicationInfo</c> and <c>ParameterRange</c>
        /// respectively).
        /// </summary>
        public static ProduceResult Produce(
            ulong channelId,
            byte[] requestProtoBytes,
            byte[] secretKeyMaterial,
            byte[]? communicationInfo = null,
            byte[]? parameterRange = null
        )
        {
            Native.Pairing.ProducePairResponseMessageResult nativeResult =
                Native.Pairing.produce_pair_response_message(
                    channelId,
                    requestProtoBytes,
                    (UIntPtr)requestProtoBytes.Length,
                    secretKeyMaterial,
                    (UIntPtr)secretKeyMaterial.Length,
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
                    Envelope = DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.ResponseWireBytes)),
                    PeerTransportProtocol = TransportProtocol.FromProtoBytes(Utils.CopyBuffer(nativeResult.PeerTransportProtocol)),
                    SharedKey = Utils.CopyBuffer(nativeResult.SharedKey),
                    ChannelId = nativeResult.ChannelId,
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
                    ChannelId = nativeResult.ChannelId,
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SharedKey);
            }
        }

        /// <summary>
        /// Contact-creator side: publishes the actual public keys back to the
        /// scanner in response to a <c>PrePairRequest</c>.
        /// </summary>
        public static ProducePrePairResult ProducePrePair(
            ulong channelId,
            byte[] requestProtoBytes,
            byte[] secretKeyMaterial
        )
        {
            Native.Pairing.ProducePrePairResponseMessageResult nativeResult =
                Native.Pairing.produce_pre_pair_response_message(
                    channelId,
                    requestProtoBytes,
                    (UIntPtr)requestProtoBytes.Length,
                    secretKeyMaterial,
                    (UIntPtr)secretKeyMaterial.Length
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
        /// Scanner-side: decodes an inbound plaintext <c>PrePairResponse</c>
        /// envelope.
        /// </summary>
        public static ExtractPrePairResult ExtractPrePair(DeRecMessage envelope)
        {
            byte[] envelopeBytes = envelope.ToProtoBytes();

            Native.Pairing.ExtractPrePairResponseResult nativeResult =
                Native.Pairing.extract_pre_pair_response(
                    envelopeBytes,
                    (UIntPtr)envelopeBytes.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new ExtractPrePairResult
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
        /// Scanner-side: validates the <c>PrePairResponse</c> against the
        /// contact's SHA-384 binding hash. Returns the validated public keys
        /// and echoed nonce on success; throws <see cref="DeRecException"/> on
        /// non-Ok status, nonce mismatch, hash mismatch, or malformed fields.
        /// </summary>
        public static ProcessPrePairResult ProcessPrePair(
            ContactMessage contactMessage,
            byte[] responseProtoBytes
        )
        {
            byte[] contactMessageBytes = contactMessage.ToProtoBytes();

            Native.Pairing.ProcessPrePairResponseMessageResult nativeResult =
                Native.Pairing.process_pre_pair_response_message(
                    contactMessageBytes,
                    (UIntPtr)contactMessageBytes.Length,
                    responseProtoBytes,
                    (UIntPtr)responseProtoBytes.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new ProcessPrePairResult
                {
                    MlkemEncapsulationKey = Utils.CopyBuffer(nativeResult.MlkemEncapsulationKey),
                    EciesPublicKey = Utils.CopyBuffer(nativeResult.EciesPublicKey),
                    Nonce = nativeResult.Nonce,
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.MlkemEncapsulationKey);
                Utils.FreeBuffer(nativeResult.EciesPublicKey);
            }
        }
    }
}
