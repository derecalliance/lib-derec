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
            /// Serialized FFI map of channel ID → committed share bytes.
            /// Use <see cref="DeserializeShares"/> to unpack into a dictionary.
            /// </summary>
            public required byte[] SharesWireBytes { get; init; }

            public Dictionary<ulong, byte[]> DeserializeShares() =>
                SharingWireFormat.DeserializeShares(SharesWireBytes);
        }

        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            /// <summary>
            /// Inner <c>StoreShareRequestMessage</c> proto bytes for chaining
            /// into <see cref="Response.Produce"/>. Also used as the
            /// stored-share input for <see cref="Recovery.Response.Produce"/>.
            /// </summary>
            public required byte[] RequestProtoBytes { get; init; }
            /// <summary>
            /// Optional response endpoint advertised by the sender on the
            /// inner request. <c>null</c> when the sender did not set one
            /// (the responder routes to the channel's stored peer endpoint).
            /// Mirrors the JS bridge surface.
            /// </summary>
            public TransportProtocol? ReplyTo { get; init; }
        }

        public static SplitResult Split(
            ulong secretId,
            byte[] secretData,
            ulong[] channelIds,
            ulong threshold,
            uint version
        )
        {
            ArgumentNullException.ThrowIfNull(channelIds);

            Native.Sharing.ProtectSecretResult nativeResult =
                Native.Sharing.protect_secret(
                    secretId,
                    secretData,
                    (UIntPtr)secretData.Length,
                    channelIds,
                    (UIntPtr)channelIds.Length,
                    (UIntPtr)threshold,
                    version
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return new SplitResult
                {
                    SharesWireBytes = Utils.CopyBuffer(nativeResult.SharesWireBytes),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SharesWireBytes);
            }
        }

        public static DeRecMessage Produce(
            ulong channelId,
            uint version,
            ulong secretId,
            byte[] committedShare,
            uint[] keepList,
            string description,
            byte[] sharedKey,
            TransportProtocol? replyTo = null
        )
        {
            ArgumentNullException.ThrowIfNull(committedShare);
            ArgumentNullException.ThrowIfNull(keepList);
            ArgumentNullException.ThrowIfNull(sharedKey);
            if (sharedKey.Length != 32)
                throw new ArgumentException("sharedKey must be exactly 32 bytes.", nameof(sharedKey));

            byte[] descriptionBytes = System.Text.Encoding.UTF8.GetBytes(description ?? string.Empty);
            byte[]? replyToBytes = replyTo?.ToProtoBytes();
            UIntPtr replyToLen = replyToBytes is null ? UIntPtr.Zero : (UIntPtr)replyToBytes.Length;

            Native.Sharing.ProduceStoreShareRequestMessageResult nativeResult =
                Native.Sharing.produce_store_share_request_message(
                    channelId,
                    version,
                    secretId,
                    committedShare,
                    (UIntPtr)committedShare.Length,
                    keepList,
                    (UIntPtr)keepList.Length,
                    descriptionBytes,
                    (UIntPtr)descriptionBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    replyToBytes,
                    replyToLen
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.WireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.WireBytes);
            }
        }

        public static ExtractResult Extract(DeRecMessage request, byte[] sharedKey)
        {
            byte[] requestWireBytes = request.ToProtoBytes();

            Native.Sharing.ExtractStoreShareRequestResult nativeResult =
                Native.Sharing.extract_store_share_request(
                    requestWireBytes,
                    (UIntPtr)requestWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                byte[] requestBytes = Utils.CopyBuffer(nativeResult.RequestProtoBytes);
                var inner = Org.Derecalliance.Derec.Protobuf.StoreShareRequestMessage.Parser
                    .ParseFrom(requestBytes);
                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
                    RequestProtoBytes = requestBytes,
                    ReplyTo = TransportProtocol.FromProto(inner.ReplyTo),
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestProtoBytes);
            }
        }
    }
}
