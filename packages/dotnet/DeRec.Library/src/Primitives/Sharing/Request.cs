// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

namespace DeRec.Library.Primitives;

public static partial class Sharing
{
    public static class Request
    {
        public sealed class SplitResult
        {
            /// <summary>
            /// Serialized map of channel ID → committed share bytes, in the Rust FFI binary format.
            /// Use <see cref="DeserializeShares"/> to unpack into a dictionary.
            /// </summary>
            public required byte[] SharesWireBytes { get; init; }

            /// <summary>Unpacks the wire bytes into a channel ID → committed share map.</summary>
            public Dictionary<ulong, byte[]> DeserializeShares() =>
                SharingWireFormat.DeserializeShares(SharesWireBytes);
        }

        public sealed class ProduceResult
        {
            public required DeRecMessage Envelope { get; init; }
        }

        /// <summary>
        /// Splits a secret into verifiable committed shares, one per helper channel.
        /// </summary>
        public static SplitResult Split(
            byte[] secretId,
            byte[] secretData,
            ulong[] channelIds,
            ulong threshold,
            int version
        )
        {
            if (channelIds is null) throw new ArgumentNullException(nameof(channelIds));

            Native.Sharing.ProtectSecretResult nativeResult =
                Native.Sharing.protect_secret(
                    secretId,
                    (UIntPtr)secretId.Length,
                    secretData,
                    (UIntPtr)secretData.Length,
                    channelIds,
                    (UIntPtr)channelIds.Length,
                    (UIntPtr)threshold,
                    version
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new SplitResult
                {
                    SharesWireBytes = Utils.CopyBuffer(nativeResult.SharesWireBytes),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SharesWireBytes);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        /// <summary>
        /// Wraps a committed helper share into an encrypted delivery envelope.
        /// </summary>
        public static ProduceResult Produce(
            ulong channelId,
            int version,
            byte[] secretId,
            byte[] committedShare,
            int[] keepList,
            string description,
            byte[] sharedKey
        )
        {
            if (secretId is null) throw new ArgumentNullException(nameof(secretId));
            if (committedShare is null) throw new ArgumentNullException(nameof(committedShare));
            if (keepList is null) throw new ArgumentNullException(nameof(keepList));
            if (sharedKey is null) throw new ArgumentNullException(nameof(sharedKey));
            if (sharedKey.Length != 32)
                throw new ArgumentException("sharedKey must be exactly 32 bytes.", nameof(sharedKey));

            byte[] descriptionBytes = System.Text.Encoding.UTF8.GetBytes(description ?? string.Empty);

            Native.Sharing.ProduceStoreShareRequestMessageResult nativeResult =
                Native.Sharing.produce_store_share_request_message(
                    channelId,
                    version,
                    secretId,
                    (UIntPtr)secretId.Length,
                    committedShare,
                    (UIntPtr)committedShare.Length,
                    keepList,
                    (UIntPtr)keepList.Length,
                    descriptionBytes,
                    (UIntPtr)descriptionBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return new ProduceResult
                {
                    Envelope = DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.WireBytes)),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.WireBytes);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
