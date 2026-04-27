// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text;

namespace DeRec.Library.Primitives;

public static partial class SecretsDiscovery
{
    public static class Response
    {
        public sealed class SecretEntry
        {
            public byte[] SecretId { get; init; } = Array.Empty<byte>();
            public int Version { get; init; }
            public string Description { get; init; } = string.Empty;
            public List<ulong> ChannelIds { get; init; } = new();
        }

        public sealed class ProcessResult
        {
            public int TotalBatches { get; init; }
            public int CurrentBatch { get; init; }
            public List<SecretEntry> Entries { get; init; } = new();
        }

        /// <summary>
        /// Produces a secrets discovery response envelope.
        /// </summary>
        public static DeRecMessage Produce(
            ulong channelId,
            byte[] sharedKey,
            List<SecretEntry> entries,
            int totalBatches,
            int currentBatch)
        {
            byte[] entriesWireBytes = EncodeEntries(entries);

            Native.SecretsDiscovery.ProduceSecretsDiscoveryResponseResult nativeResult =
                Native.SecretsDiscovery.produce_secrets_discovery_response(
                    channelId,
                    sharedKey,
                    (UIntPtr)sharedKey.Length,
                    entriesWireBytes,
                    (UIntPtr)entriesWireBytes.Length,
                    totalBatches,
                    currentBatch
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
        /// Decodes, decrypts, and processes a secrets discovery response.
        /// </summary>
        public static ProcessResult Process(DeRecMessage response, byte[] sharedKey)
        {
            byte[] responseWireBytes = response.ToProtoBytes();

            Native.SecretsDiscovery.ProcessSecretsDiscoveryResponseResult nativeResult =
                Native.SecretsDiscovery.process_secrets_discovery_response(
                    responseWireBytes,
                    (UIntPtr)responseWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                byte[] entriesBytes = Utils.CopyBuffer(nativeResult.EntriesWireBytes);
                List<SecretEntry> entries = DecodeEntries(entriesBytes);

                return new ProcessResult
                {
                    TotalBatches = nativeResult.TotalBatches,
                    CurrentBatch = nativeResult.CurrentBatch,
                    Entries = entries,
                };
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.EntriesWireBytes);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }

        private static byte[] EncodeEntries(List<SecretEntry> entries)
        {
            var buf = new List<byte>();
            buf.AddRange(BitConverter.GetBytes((uint)entries.Count));
            foreach (var entry in entries)
            {
                buf.AddRange(BitConverter.GetBytes((uint)entry.SecretId.Length));
                buf.AddRange(entry.SecretId);

                buf.AddRange(BitConverter.GetBytes(entry.Version));

                byte[] descBytes = Encoding.UTF8.GetBytes(entry.Description);
                buf.AddRange(BitConverter.GetBytes((uint)descBytes.Length));
                buf.AddRange(descBytes);

                buf.AddRange(BitConverter.GetBytes((uint)entry.ChannelIds.Count));
                foreach (ulong channelId in entry.ChannelIds)
                {
                    buf.AddRange(BitConverter.GetBytes(channelId));
                }
            }
            return buf.ToArray();
        }

        private static List<SecretEntry> DecodeEntries(byte[] data)
        {
            var entries = new List<SecretEntry>();
            if (data.Length == 0) return entries;

            int offset = 0;
            uint count = BitConverter.ToUInt32(data, offset);
            offset += 4;

            for (uint i = 0; i < count; i++)
            {
                uint secretIdLen = BitConverter.ToUInt32(data, offset);
                offset += 4;

                byte[] secretId = new byte[secretIdLen];
                Array.Copy(data, offset, secretId, 0, (int)secretIdLen);
                offset += (int)secretIdLen;

                int version = BitConverter.ToInt32(data, offset);
                offset += 4;

                uint descLen = BitConverter.ToUInt32(data, offset);
                offset += 4;

                string description = Encoding.UTF8.GetString(data, offset, (int)descLen);
                offset += (int)descLen;

                uint channelIdsCount = BitConverter.ToUInt32(data, offset);
                offset += 4;

                var channelIds = new List<ulong>();
                for (uint j = 0; j < channelIdsCount; j++)
                {
                    channelIds.Add(BitConverter.ToUInt64(data, offset));
                    offset += 8;
                }

                entries.Add(new SecretEntry
                {
                    SecretId = secretId,
                    Version = version,
                    Description = description,
                    ChannelIds = channelIds,
                });
            }

            return entries;
        }
    }
}
