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
        /// <summary>
        /// Stable per-device identifier of the replica that produced this
        /// version. <c>null</c> means a non-replica <c>Owner</c> produced
        /// it. Two distinct <c>ReplicaId</c>s with the same
        /// <c>Version</c> for the same <c>SecretId</c> indicate
        /// concurrent writes the application must reconcile before
        /// driving recovery.
        /// </summary>
        public ulong? ReplicaId { get; init; }
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
                    // Optional `replica_id` tail: 1-byte flag, then the
                    // u64 LE only if the flag is set. Matches the Rust
                    // FFI reader in `library/src/ffi/discovery.rs`.
                    if (v.ReplicaId is { } replicaId)
                    {
                        writer.Write((byte)1);
                        writer.Write(replicaId);
                    }
                    else
                    {
                        writer.Write((byte)0);
                    }
                }
            }

            writer.Flush();
            return stream.ToArray();
        }

        // Minimum on-wire size of a `SecretVersionEntry` body: u64
        // secret_id + u32 versions_count + zero versions = 12 bytes.
        private const int MinSecretVersionEntryBytes = 12;
        // Minimum on-wire size of a `VersionEntry` body: u32 version
        // + u32 desc_len + zero-length description = 8 bytes.
        // 4 (version) + 4 (desc_len) + 1 (has_replica_id flag) bytes
        // minimum per version entry.
        private const int MinVersionEntryBytes = 9;

        internal static List<SecretVersionEntry> Deserialize(byte[] bytes)
        {
            int offset = 0;
            uint count = ReadU32(bytes, ref offset);

            // The `count` prefix is attacker-controlled (the bytes
            // originate from a remote peer over the discovery
            // response). Reject impossibly large values before they
            // reach `List<>`'s capacity argument; otherwise a 4-byte
            // payload with count = 0x7FFFFFFF would attempt a
            // multi-GB pre-allocation, or count > int.MaxValue would
            // wrap negative and surface an ArgumentOutOfRangeException
            // instead of our intended parse failure.
            int remaining = bytes.Length - offset;
            if (count > (uint)(remaining / MinSecretVersionEntryBytes))
            {
                throw new InvalidOperationException(
                    $"Secret list count={count} exceeds the maximum possible for {remaining} remaining bytes (min {MinSecretVersionEntryBytes}B per entry).");
            }

            var entries = new List<SecretVersionEntry>((int)count);

            for (uint i = 0; i < count; i++)
            {
                ulong secretId = ReadU64(bytes, ref offset);
                uint versionsCount = ReadU32(bytes, ref offset);

                // Same bound applied to the per-secret versions list.
                int remainingForVersions = bytes.Length - offset;
                if (versionsCount > (uint)(remainingForVersions / MinVersionEntryBytes))
                {
                    throw new InvalidOperationException(
                        $"Versions count={versionsCount} for secret_id={secretId} exceeds the maximum possible for {remainingForVersions} remaining bytes (min {MinVersionEntryBytes}B per entry).");
                }

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
                    // Optional `replica_id` tail: 1-byte flag, then the
                    // u64 LE only if the flag is set.
                    if (offset + 1 > bytes.Length)
                    {
                        throw new InvalidOperationException(
                            $"Unexpected end of secret list bytes while reading replica_id flag for secret_id={secretId}, version={version}.");
                    }
                    byte hasReplicaId = bytes[offset];
                    offset += 1;
                    ulong? replicaId = null;
                    if (hasReplicaId != 0)
                    {
                        replicaId = ReadU64(bytes, ref offset);
                    }
                    versions.Add(new VersionEntry
                    {
                        Version = version,
                        Description = description,
                        ReplicaId = replicaId,
                    });
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
