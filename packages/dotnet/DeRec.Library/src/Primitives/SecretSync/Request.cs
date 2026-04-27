// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text;

namespace DeRec.Library.Primitives;

public static partial class SecretSync
{
    public static class Request
    {
        public sealed class ExtractResult
        {
            public byte[] SecretId { get; init; } = Array.Empty<byte>();
            public int Version { get; init; }
            public string Description { get; init; } = string.Empty;
            public List<ulong> ChannelIds { get; init; } = new();
        }

        /// <summary>
        /// Produces a secret sync request envelope.
        /// </summary>
        public static DeRecMessage Produce(
            ulong channelId,
            byte[] sharedKey,
            byte[] secretId,
            int version,
            string description,
            List<ulong> channelIds)
        {
            byte[] descBytes = Encoding.UTF8.GetBytes(description);
            byte[] channelIdsBytes = EncodeChannelIds(channelIds);

            Native.SecretSync.ProduceSecretSyncRequestResult nativeResult =
                Native.SecretSync.produce_secret_sync_request(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    secretId,
                    (UIntPtr)secretId.Length,
                    version,
                    descBytes,
                    (UIntPtr)descBytes.Length,
                    channelIdsBytes,
                    (UIntPtr)channelIdsBytes.Length
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
        /// Decodes and decrypts a secret sync request.
        /// </summary>
        public static ExtractResult Extract(DeRecMessage request, byte[] sharedKey)
        {
            byte[] requestWireBytes = request.ToProtoBytes();

            Native.SecretSync.ExtractSecretSyncRequestResult nativeResult =
                Native.SecretSync.extract_secret_sync_request(
                    requestWireBytes,
                    (UIntPtr)requestWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                byte[] secretId = Utils.CopyBuffer(nativeResult.SecretId);
                string description = Encoding.UTF8.GetString(Utils.CopyBuffer(nativeResult.Description));
                List<ulong> channelIds = DecodeChannelIds(Utils.CopyBuffer(nativeResult.ChannelIds));

                return new ExtractResult
                {
                    SecretId = secretId,
                    Version = nativeResult.Version,
                    Description = description,
                    ChannelIds = channelIds,
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.SecretId);
                Utils.FreeBuffer(nativeResult.Description);
                Utils.FreeBuffer(nativeResult.ChannelIds);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        private static byte[] EncodeChannelIds(List<ulong> channelIds)
        {
            var buf = new List<byte>();
            foreach (ulong id in channelIds)
            {
                buf.AddRange(BitConverter.GetBytes(id));
            }
            return buf.ToArray();
        }

        private static List<ulong> DecodeChannelIds(byte[] data)
        {
            var ids = new List<ulong>();
            if (data.Length == 0) return ids;

            int offset = 0;
            while (offset < data.Length)
            {
                ids.Add(BitConverter.ToUInt64(data, offset));
                offset += 8;
            }

            return ids;
        }
    }
}
