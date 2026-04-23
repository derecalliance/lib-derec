// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace DeRec.Library.Primitives;

public static partial class ChannelsDiscovery
{
    public static class Response
    {
        public sealed class ChannelEntry
        {
            public ulong ChannelId { get; init; }
            public byte[] SharedKey { get; init; } = Array.Empty<byte>();
        }

        public sealed class ProcessResult
        {
            public int TotalBatches { get; init; }
            public int CurrentBatch { get; init; }
            public List<ChannelEntry> Entries { get; init; } = new();
        }

        /// <summary>
        /// Produces a channels discovery response envelope.
        /// </summary>
        public static DeRecMessage Produce(
            ulong channelId,
            byte[] sharedKey,
            List<ChannelEntry> entries,
            int totalBatches,
            int currentBatch)
        {
            byte[] entriesWireBytes = EncodeEntries(entries);

            Native.ChannelsDiscovery.ProduceChannelsDiscoveryResponseResult nativeResult =
                Native.ChannelsDiscovery.produce_channels_discovery_response(
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
        /// Decodes, decrypts, and processes a channels discovery response.
        /// </summary>
        public static ProcessResult Process(DeRecMessage response, byte[] sharedKey)
        {
            byte[] responseWireBytes = response.ToProtoBytes();

            Native.ChannelsDiscovery.ProcessChannelsDiscoveryResponseResult nativeResult =
                Native.ChannelsDiscovery.process_channels_discovery_response(
                    responseWireBytes,
                    (UIntPtr)responseWireBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                byte[] entriesBytes = Utils.CopyBuffer(nativeResult.EntriesWireBytes);
                List<ChannelEntry> entries = DecodeEntries(entriesBytes);

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

        private static byte[] EncodeEntries(List<ChannelEntry> entries)
        {
            var buf = new List<byte>();
            buf.AddRange(BitConverter.GetBytes((uint)entries.Count));
            foreach (var entry in entries)
            {
                buf.AddRange(BitConverter.GetBytes(entry.ChannelId));
                buf.AddRange(BitConverter.GetBytes((uint)entry.SharedKey.Length));
                buf.AddRange(entry.SharedKey);
            }
            return buf.ToArray();
        }

        private static List<ChannelEntry> DecodeEntries(byte[] data)
        {
            var entries = new List<ChannelEntry>();
            if (data.Length == 0) return entries;

            int offset = 0;
            uint count = BitConverter.ToUInt32(data, offset);
            offset += 4;

            for (uint i = 0; i < count; i++)
            {
                ulong channelId = BitConverter.ToUInt64(data, offset);
                offset += 8;

                uint keyLen = BitConverter.ToUInt32(data, offset);
                offset += 4;

                byte[] key = new byte[keyLen];
                Array.Copy(data, offset, key, 0, (int)keyLen);
                offset += (int)keyLen;

                entries.Add(new ChannelEntry
                {
                    ChannelId = channelId,
                    SharedKey = key,
                });
            }

            return entries;
        }
    }
}
