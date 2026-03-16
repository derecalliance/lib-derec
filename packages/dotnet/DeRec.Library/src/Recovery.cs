using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Google.Protobuf;
using Org.Derecalliance.Derec.Protobuf;

namespace DeRec.Library;

public static class Recovery
{
    public static GetShareRequestMessage GenerateShareRequest(
        ulong channelId,
        byte[] secretId,
        int version
    )
    {
        Native.Recovery.GenerateShareRequestResult nativeResult =
            Native.Recovery.generate_share_request(
                channelId,
                secretId,
                (UIntPtr)secretId.Length,
                version
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] requestBytes = Utils.CopyBuffer(nativeResult.GetShareRequestMessage);
            return GetShareRequestMessage.Parser.ParseFrom(requestBytes);
        }
        finally
        {
           Utils.FreeBuffer(nativeResult.GetShareRequestMessage);
           Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static GetShareResponseMessage GenerateShareResponse(
        ulong channelId,
        byte[] secretId,
        GetShareRequestMessage request,
        StoreShareRequestMessage shareContent
    )
    {
        byte[] requestBytes = request.ToByteArray();
        byte[] shareContentBytes = shareContent.ToByteArray();

        Native.Recovery.GenerateShareResponseResult nativeResult =
            Native.Recovery.generate_share_response(
                channelId,
                secretId,
                (UIntPtr)secretId.Length,
                requestBytes,
                (UIntPtr)requestBytes.Length,
                shareContentBytes,
                (UIntPtr)shareContentBytes.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] responseBytes = Utils.CopyBuffer(nativeResult.GetShareResponseMessage);
            return GetShareResponseMessage.Parser.ParseFrom(responseBytes);
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.GetShareResponseMessage);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static byte[] RecoverFromShareResponses(
        IEnumerable<GetShareResponseMessage> responses,
        byte[] secretId,
        int version
    )
    {
        byte[] responsesBytes = SerializeShareResponses(responses);

        Native.Recovery.RecoverFromShareResponsesResult nativeResult =
            Native.Recovery.recover_from_share_responses(
                responsesBytes,
                (UIntPtr)responsesBytes.Length,
                secretId,
                (UIntPtr)secretId.Length,
                version
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);
            return Utils.CopyBuffer(nativeResult.SecretData);
        }
        finally
        {
           Utils.FreeBuffer(nativeResult.SecretData);
           Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    private static byte[] SerializeShareResponses(
        IEnumerable<GetShareResponseMessage> responses
    )
    {
        List<GetShareResponseMessage> list = new(responses);
        using MemoryStream stream = new();
        using BinaryWriter writer = new(stream);

        writer.Write((uint)list.Count);

        foreach (GetShareResponseMessage response in list)
        {
            byte[] bytes = response.ToByteArray();
            writer.Write((uint)bytes.Length);
            writer.Write(bytes);
        }

        writer.Flush();
        return stream.ToArray();
    }
}
