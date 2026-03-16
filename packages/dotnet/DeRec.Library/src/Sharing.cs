using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Google.Protobuf;
using Org.Derecalliance.Derec.Protobuf;

namespace DeRec.Library;

public static class Sharing
{
    public sealed class ProtectSecretResult
    {
        public required Dictionary<ulong, StoreShareRequestMessage> Shares { get; init; }
    }

    public static ProtectSecretResult ProtectSecret(
        byte[] secretId,
        byte[] secretData,
        ulong[] channels,
        ulong threshold,
        int version,
        int[]? keepList = null,
        string? description = null
    )
    {
        byte[]? descriptionBytes = description is null
            ? null
            : Encoding.UTF8.GetBytes(description);

        Native.Sharing.ProtectSecretResult nativeResult =
            Native.Sharing.protect_secret(
                secretId,
                (UIntPtr)secretId.Length,
                secretData,
                (UIntPtr)secretData.Length,
                channels,
                (UIntPtr)channels.Length,
                (UIntPtr)threshold,
                version,
                keepList,
                keepList is null ? UIntPtr.Zero : (UIntPtr)keepList.Length,
                descriptionBytes,
                descriptionBytes is null ? UIntPtr.Zero : (UIntPtr)descriptionBytes.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] sharesBytes = Utils.CopyBuffer(nativeResult.Shares);
            Dictionary<ulong, StoreShareRequestMessage> shares =
                DeserializeShares(sharesBytes);

            return new ProtectSecretResult
            {
                Shares = shares,
            };
        }
        finally
        {
           Utils.FreeBuffer(nativeResult.Shares);
           Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    private static Dictionary<ulong, StoreShareRequestMessage> DeserializeShares(byte[] bytes)
    {
        ReadOnlySpan<byte> span = bytes;
        int offset = 0;

        uint entryCount = Utils.ReadU32(span, ref offset);
        Dictionary<ulong, StoreShareRequestMessage> shares =
            new Dictionary<ulong, StoreShareRequestMessage>(checked((int)entryCount));

        for (uint i = 0; i < entryCount; i++)
        {
            ulong channelId = Utils.ReadU64(span, ref offset);
            uint messageLen = Utils.ReadU32(span, ref offset);

            if (messageLen > int.MaxValue)
            {
                throw new InvalidDataException("Serialized share message too large.");
            }

            int len = checked((int)messageLen);

            if (offset + len > span.Length)
            {
                throw new InvalidDataException("Unexpected end of serialized shares buffer.");
            }

            byte[] messageBytes = span.Slice(offset, len).ToArray();
            offset += len;

            StoreShareRequestMessage message =
                StoreShareRequestMessage.Parser.ParseFrom(messageBytes);

            shares.Add(channelId, message);
        }

        if (offset != span.Length)
        {
            throw new InvalidDataException("Unexpected trailing bytes in serialized shares buffer.");
        }

        return shares;
    }
}
