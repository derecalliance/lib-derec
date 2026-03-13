using System;
using System.Runtime.InteropServices;
using Google.Protobuf;
using Org.Derecalliance.Derec.Protobuf;

namespace DeRec.Library;

public static class Verification
{
    public static VerifyShareRequestMessage GenerateVerificationRequest(
        byte[] secretId,
        int version
    )
    {
        Native.Verification.GenerateVerificationRequestResult nativeResult =
            Native.Verification.generate_verification_request(
                secretId,
                (UIntPtr)secretId.Length,
                version
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] requestBytes = Utils.CopyBuffer(nativeResult.VerifyShareRequestMessage);

            return VerifyShareRequestMessage.Parser.ParseFrom(requestBytes);
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.VerifyShareRequestMessage);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static VerifyShareResponseMessage GenerateVerificationResponse(
        byte[] secretId,
        ulong channelId,
        byte[] shareContent,
        VerifyShareRequestMessage request
    )
    {
        byte[] requestBytes = request.ToByteArray();

        Native.Verification.GenerateVerificationResponseResult nativeResult =
            Native.Verification.generate_verification_response(
                secretId,
                (UIntPtr)secretId.Length,
                channelId,
                shareContent,
                (UIntPtr)shareContent.Length,
                requestBytes,
                (UIntPtr)requestBytes.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] responseBytes = Utils.CopyBuffer(nativeResult.VerifyShareResponseMessage);

            return VerifyShareResponseMessage.Parser.ParseFrom(responseBytes);
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.VerifyShareResponseMessage);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static bool VerifyShareResponse(
        byte[] secretId,
        ulong channelId,
        byte[] shareContent,
        VerifyShareResponseMessage response
    )
    {
        byte[] responseBytes = response.ToByteArray();

        Native.Verification.VerifyShareResponseResult nativeResult =
            Native.Verification.verify_share_response(
                secretId,
                (UIntPtr)secretId.Length,
                channelId,
                shareContent,
                (UIntPtr)shareContent.Length,
                responseBytes,
                (UIntPtr)responseBytes.Length
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
