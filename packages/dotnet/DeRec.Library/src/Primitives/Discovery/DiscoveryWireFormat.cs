// SPDX-License-Identifier: Apache-2.0

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DeRec.Library.Primitives;

public static partial class Discovery
{
    public sealed class VersionEntry
    {
        public required uint Version { get; init; }
        public required string Description { get; init; }
    }

    public sealed class SecretVersionEntry
    {
        public required ulong SecretId { get; init; }
        public required IReadOnlyList<VersionEntry> Versions { get; init; }
    }

    /// <summary>
    /// Serializes / deserializes the discovery secret list in the FFI binary
    /// format used by <c>produce_get_secret_ids_versions_response_message</c>
    /// (input) and <c>process_get_secret_ids_versions_response_message</c>
    /// (output).
    /// </summary>
    internal static class DiscoveryWireFormat
    {
        internal static byte[] Serialize(IReadOnlyList<SecretVersionEntry> entries)
        {
            using MemoryStream stream = new();
            using BinaryWriter writer = new(stream);

            writer.Write((uint)entries.Count);
            foreach (SecretVersionEntry entry in entries)
            {
                writer.Write(entry.SecretId);
                writer.Write((uint)entry.Versions.Count);
                foreach (VersionEntry v in entry.Versions)
                {
                    writer.Write(v.Version);
                    byte[] descBytes = Encoding.UTF8.GetBytes(v.Description ?? string.Empty);
                    writer.Write((uint)descBytes.Length);
                    writer.Write(descBytes);
                }
            }

            writer.Flush();
            return stream.ToArray();
        }

        internal static List<SecretVersionEntry> Deserialize(byte[] bytes)
        {
            int offset = 0;
            uint count = ReadU32(bytes, ref offset);
            var entries = new List<SecretVersionEntry>((int)count);

            for (uint i = 0; i < count; i++)
            {
                ulong secretId = ReadU64(bytes, ref offset);
                uint versionsCount = ReadU32(bytes, ref offset);
                var versions = new List<VersionEntry>((int)versionsCount);

                for (uint v = 0; v < versionsCount; v++)
                {
                    uint version = ReadU32(bytes, ref offset);
                    uint descLen = ReadU32(bytes, ref offset);
                    if (offset + descLen > bytes.Length)
                    {
                        throw new InvalidOperationException(
                            $"Unexpected end of secret list bytes while reading description for secret_id={secretId}, version={version}.");
                    }
                    string description = Encoding.UTF8.GetString(bytes, offset, (int)descLen);
                    offset += (int)descLen;
                    versions.Add(new VersionEntry { Version = version, Description = description });
                }

                entries.Add(new SecretVersionEntry { SecretId = secretId, Versions = versions });
            }

            if (offset != bytes.Length)
            {
                throw new InvalidOperationException(
                    $"Unexpected trailing bytes in secret list. offset={offset}, total={bytes.Length}");
            }

            return entries;
        }

        private static uint ReadU32(byte[] bytes, ref int offset)
        {
            if (offset + 4 > bytes.Length)
                throw new InvalidOperationException("Unexpected end of secret list while reading u32.");
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
            offset += 4;
            return value;
        }

        private static ulong ReadU64(byte[] bytes, ref int offset)
        {
            if (offset + 8 > bytes.Length)
                throw new InvalidOperationException("Unexpected end of secret list while reading u64.");
            ulong value = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset, 8));
            offset += 8;
            return value;
        }
    }
}
