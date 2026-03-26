using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DeRec.Library;

public static class Sharing
{
    public sealed class ProtectSecretResult
    {
        public required byte[] ShareMessageWireBytesArray { get; init; }
    }

    public static ProtectSecretResult ProtectSecret(
        byte[] secretId,
        byte[] secretData,
        Dictionary<ulong, byte[]> channels,
        ulong threshold,
        int version,
        int[]? keepList = null,
        string? description = null
    )
    {
        if (channels is null)
        {
            throw new ArgumentNullException(nameof(channels));
        }

        Native.Sharing.ChannelSharedKeyInput[] nativeChannels = channels
            .OrderBy(entry => entry.Key)
            .Select(entry =>
            {
                if (entry.Value is null)
                {
                    throw new ArgumentException(
                        $"Shared key for channel {entry.Key} cannot be null.",
                        nameof(channels)
                    );
                }

                if (entry.Value.Length != 32)
                {
                    throw new ArgumentException(
                        $"Shared key for channel {entry.Key} must be exactly 32 bytes.",
                        nameof(channels)
                    );
                }

                return new Native.Sharing.ChannelSharedKeyInput
                {
                    ChannelId = entry.Key,
                    SharedKey = (byte[])entry.Value.Clone(),
                };
            })
            .ToArray();

        byte[]? descriptionBytes = description is null
            ? null
            : Encoding.UTF8.GetBytes(description);

        Native.Sharing.ProtectSecretResult nativeResult =
            Native.Sharing.protect_secret(
                secretId,
                (UIntPtr)secretId.Length,
                secretData,
                (UIntPtr)secretData.Length,
                nativeChannels,
                (UIntPtr)nativeChannels.Length,
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

            byte[] shareMessageWireBytesArray =
                Utils.CopyBuffer(nativeResult.SharesWireBytes);

            return new ProtectSecretResult
            {
                ShareMessageWireBytesArray = shareMessageWireBytesArray,
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.SharesWireBytes);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }
}
