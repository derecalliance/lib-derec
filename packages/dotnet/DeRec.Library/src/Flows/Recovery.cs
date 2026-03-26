using System;
using System.Collections.Generic;
using System.IO;

namespace DeRec.Library;

public static class Recovery
{
    public sealed class RecoveryResponseInput
    {
        public required byte[] Bytes { get; init; }
        public required byte[] SharedKey { get; init; }
    }

    public static byte[] GenerateShareRequest(
        ulong channelId,
        byte[] secretId,
        int version,
        byte[] sharedKey
    )
    {
        Native.Recovery.GenerateShareRequestResult nativeResult =
            Native.Recovery.generate_share_request(
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

            return Utils.CopyBuffer(nativeResult.WireBytes);
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.WireBytes);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static byte[] GenerateShareResponse(
        ulong channelId,
        byte[] secretId,
        byte[] requestWireBytes,
        byte[] storedShareRequestWireBytes,
        byte[] sharedKey
    )
    {
        Native.Recovery.GenerateShareResponseResult nativeResult =
            Native.Recovery.generate_share_response(
                channelId,
                secretId,
                (UIntPtr)secretId.Length,
                requestWireBytes,
                (UIntPtr)requestWireBytes.Length,
                storedShareRequestWireBytes,
                (UIntPtr)storedShareRequestWireBytes.Length,
                sharedKey,
                (UIntPtr)sharedKey.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            return Utils.CopyBuffer(nativeResult.WireBytes);
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.WireBytes);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static byte[] RecoverFromShareResponses(
        IEnumerable<RecoveryResponseInput> responses,
        byte[] secretId,
        int version
    )
    {
        byte[] serializedResponses = SerializeRecoveryResponseInputs(responses);

        Native.Recovery.RecoverFromShareResponsesResult nativeResult =
            Native.Recovery.recover_from_share_responses(
                serializedResponses,
                (UIntPtr)serializedResponses.Length,
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

    private static byte[] SerializeRecoveryResponseInputs(
        IEnumerable<RecoveryResponseInput> responses
    )
    {
        List<RecoveryResponseInput> list = new(responses);

        using MemoryStream stream = new();
        using BinaryWriter writer = new(stream);

        writer.Write((uint)list.Count);

        foreach (RecoveryResponseInput response in list)
        {
            if (response.Bytes is null)
            {
                throw new ArgumentNullException(nameof(response.Bytes));
            }

            if (response.SharedKey is null)
            {
                throw new ArgumentNullException(nameof(response.SharedKey));
            }

            if (response.SharedKey.Length != 32)
            {
                throw new ArgumentException(
                    "SharedKey must be exactly 32 bytes.",
                    nameof(response.SharedKey)
                );
            }

            writer.Write((uint)response.Bytes.Length);
            writer.Write(response.Bytes);
            writer.Write(response.SharedKey);
        }

        writer.Flush();
        return stream.ToArray();
    }
}
