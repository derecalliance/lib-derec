// SPDX-License-Identifier: Apache-2.0

namespace DeRec.Library.Primitives;

public static partial class Verification
{
    public static class Response
    {
        /// <summary>
        /// Generates a verification response envelope (Helper side, step 2).
        /// </summary>
        public static DeRecMessage Produce(
            ulong channelId,
            byte[] secretId,
            int version,
            ulong nonce,
            byte[] sharedKey,
            DeRecMessage storedRequest
        )
        {
            byte[] shareContent = storedRequest.ToProtoBytes();

            Native.Verification.ProduceVerifyShareResponseMessageResult nativeResult =
                Native.Verification.produce_verify_share_response_message(
                    channelId,
                    secretId,
                    (UIntPtr)secretId.Length,
                    version,
                    nonce,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    shareContent,
                    (UIntPtr)shareContent.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.ResponseWireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.ResponseWireBytes);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        /// <summary>
        /// Verifies a verification response (Owner side, step 3).
        /// Returns <c>true</c> if the proof matches, <c>false</c> otherwise.
        /// </summary>
        public static bool Process(
            DeRecMessage response,
            byte[] sharedKey,
            DeRecMessage storedRequest
        )
        {
            byte[] responseWireBytes = response.ToProtoBytes();
            byte[] shareContent = storedRequest.ToProtoBytes();

            Native.Verification.VerifyShareResponseResult nativeResult =
                Native.Verification.process_verify_share_response_message(
                    responseWireBytes,
                    (UIntPtr)responseWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    shareContent,
                    (UIntPtr)shareContent.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);
                return nativeResult.IsValid;
            }
            finally
            {
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
