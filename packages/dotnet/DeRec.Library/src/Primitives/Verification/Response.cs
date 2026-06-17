// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class Verification
{
    public static class Response
    {
        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            /// <summary>
            /// Inner <c>VerifyShareResponseMessage</c> proto bytes for chaining
            /// into <see cref="Process(byte[], byte[], byte[])"/>.
            /// </summary>
            public required byte[] ResponseProtoBytes { get; init; }
        }

        public static DeRecMessage Produce(
            ulong channelId,
            byte[] requestProtoBytes,
            byte[] sharedKey,
            byte[] shareContent
        )
        {
            Native.Verification.ProduceVerifyShareResponseMessageResult nativeResult =
                Native.Verification.produce_verify_share_response_message(
                    channelId,
                    requestProtoBytes,
                    (UIntPtr)requestProtoBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    shareContent,
                    (UIntPtr)shareContent.Length
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

            Native.Verification.ExtractVerifyShareResponseResult nativeResult =
                Native.Verification.extract_verify_share_response(
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
        /// Verify a <c>VerifyShareResponseMessage</c> against the originating
        /// <c>VerifyShareRequestMessage</c> and the expected share content.
        /// </summary>
        /// <remarks>
        /// <paramref name="requestProtoBytes"/> must be the proto-encoded request
        /// that the owner previously produced for this challenge (kept by the
        /// caller in a per-channel pending-verification map). Responses whose
        /// <c>(nonce, secretId, version)</c> triple doesn't match are rejected —
        /// that's the anti-replay gate.
        /// </remarks>
        /// <returns><c>true</c> if the SHA-384 proof matches the given share content.</returns>
        public static bool Process(
            byte[] requestProtoBytes,
            byte[] responseProtoBytes,
            byte[] shareContent
        )
        {
            Native.Verification.VerifyShareResponseResult nativeResult =
                Native.Verification.process_verify_share_response_message(
                    requestProtoBytes,
                    (UIntPtr)requestProtoBytes.Length,
                    responseProtoBytes,
                    (UIntPtr)responseProtoBytes.Length,
                    shareContent,
                    (UIntPtr)shareContent.Length
                );

            Utils.ThrowIfError(nativeResult.Error);
            return nativeResult.IsValid;
        }
    }
}
