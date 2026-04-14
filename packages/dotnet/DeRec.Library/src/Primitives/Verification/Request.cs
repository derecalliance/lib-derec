// SPDX-License-Identifier: Apache-2.0

using System;

namespace DeRec.Library.Primitives;

public static partial class Verification
{
    public static class Request
    {
        public sealed class ExtractResult
        {
            public ulong ChannelId { get; init; }
            public byte[] SecretId { get; init; } = Array.Empty<byte>();
            public int Version { get; init; }
            public ulong Nonce { get; init; }
        }

        /// <summary>
        /// Generates a verification request envelope (Owner side, step 1).
        /// </summary>
        public static DeRecMessage Produce(
            ulong channelId,
            byte[] secretId,
            int version,
            byte[] sharedKey
        )
        {
            Native.Verification.ProduceVerifyShareRequestMessageResult nativeResult =
                Native.Verification.produce_verify_share_request_message(
                    channelId,
                    secretId,
                    (UIntPtr)secretId.Length,
                    version,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.RequestWireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestWireBytes);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        /// <summary>
        /// Decodes and decrypts a verification request envelope (Helper side, step 1).
        /// </summary>
        public static ExtractResult Extract(DeRecMessage request, byte[] sharedKey)
        {
            byte[] requestWireBytes = request.ToProtoBytes();

            Native.Verification.ExtractVerifyShareRequestResult nativeResult =
                Native.Verification.extract_verify_share_request(
                    requestWireBytes,
                    (UIntPtr)requestWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
                    SecretId = Utils.CopyBuffer(nativeResult.SecretId),
                    Version = nativeResult.Version,
                    Nonce = nativeResult.Nonce,
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SecretId);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
