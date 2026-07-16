// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace DeRec.Library.Primitives;

internal static class SharingWireFormat
{
    /// <summary>
    /// Deserializes the binary wire format returned by the Rust FFI <c>protect_secret</c> into
    /// a channel ID → committed share bytes map.
    /// </summary>
    internal static Dictionary<ulong, byte[]> DeserializeShares(byte[] bytes)
    {
        var result = new Dictionary<ulong, byte[]>();
        int offset = 0;

        uint count = ReadU32(bytes, ref offset);

        for (uint i = 0; i < count; i++)
        {
            ulong channelId = ReadU64(bytes, ref offset);
            uint messageLen = ReadU32(bytes, ref offset);

            if (offset + messageLen > bytes.Length)
            {
                throw new InvalidOperationException(
                    $"Unexpected end of shares wire bytes while reading entry {i}."
                );
            }

            byte[] shareBytes = new byte[messageLen];
            Buffer.BlockCopy(bytes, offset, shareBytes, 0, (int)messageLen);
            offset += (int)messageLen;

            if (!result.TryAdd(channelId, shareBytes))
            {
                throw new InvalidOperationException(
                    $"Duplicate channel ID {channelId} in shares wire bytes."
                );
            }
        }

        if (offset != bytes.Length)
        {
            throw new InvalidOperationException(
                $"Unexpected trailing bytes in shares wire bytes. offset={offset}, total={bytes.Length}"
            );
        }

        return result;
    }

    private static uint ReadU32(byte[] bytes, ref int offset)
    {
        if (offset + 4 > bytes.Length)
            throw new InvalidOperationException("Unexpected end of buffer while reading u32.");
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
        offset += 4;
        return value;
    }

    private static ulong ReadU64(byte[] bytes, ref int offset)
    {
        if (offset + 8 > bytes.Length)
            throw new InvalidOperationException("Unexpected end of buffer while reading u64.");
        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset, 8));
        offset += 8;
        return value;
    }
}
