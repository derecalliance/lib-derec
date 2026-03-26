using System;

namespace DeRec.Library;

public static class Verification
{
    public static byte[] GenerateVerificationRequest(
        byte[] secretId,
        ulong channelId,
        int version,
        byte[] sharedKey
    )
    {
        Native.Verification.GenerateVerificationRequestResult nativeResult =
            Native.Verification.generate_verification_request(
                secretId,
                (UIntPtr)secretId.Length,
                channelId,
                version,
                sharedKey,
                (UIntPtr)sharedKey.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            return Utils.CopyBuffer(nativeResult.RequestWireBytes);
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.RequestWireBytes);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static byte[] GenerateVerificationResponse(
        byte[] secretId,
        ulong channelId,
        byte[] sharedKey,
        byte[] shareContent,
        byte[] requestWireBytes
    )
    {
        Native.Verification.GenerateVerificationResponseResult nativeResult =
            Native.Verification.generate_verification_response(
                secretId,
                (UIntPtr)secretId.Length,
                channelId,
                sharedKey,
                (UIntPtr)sharedKey.Length,
                shareContent,
                (UIntPtr)shareContent.Length,
                requestWireBytes,
                (UIntPtr)requestWireBytes.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            return Utils.CopyBuffer(nativeResult.ResponseWireBytes);
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.ResponseWireBytes);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static bool VerifyShareResponse(
        byte[] secretId,
        ulong channelId,
        byte[] sharedKey,
        byte[] shareContent,
        byte[] responseWireBytes
    )
    {
        Native.Verification.VerifyShareResponseResult nativeResult =
            Native.Verification.verify_share_response(
                secretId,
                (UIntPtr)secretId.Length,
                channelId,
                sharedKey,
                (UIntPtr)sharedKey.Length,
                shareContent,
                (UIntPtr)shareContent.Length,
                responseWireBytes,
                (UIntPtr)responseWireBytes.Length
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
