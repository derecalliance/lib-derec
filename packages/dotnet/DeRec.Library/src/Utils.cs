using System;
using System.Runtime.InteropServices;
using System.Buffers.Binary;

namespace DeRec.Library;

internal static class Utils
{
    public static byte[] CopyBuffer(Native.Buffer buffer)
    {
        int len = checked((int)buffer.Len);
        byte[] managed = new byte[len];

        if (len > 0)
        {
            Marshal.Copy(buffer.Ptr, managed, 0, len);
        }

        return managed;
    }

    public static void ThrowIfError(Native.Status status)
    {
        if (status.Code == 0)
        {
            return;
        }

        string message = status.Message != IntPtr.Zero
            ? Marshal.PtrToStringAnsi(status.Message) ?? "unknown error"
            : "unknown error";

        throw new InvalidOperationException(message);
    }

    public static void FreeBuffer(Native.Buffer buffer)
    {
        if (buffer.Ptr != IntPtr.Zero)
        {
            Native.Utils.derec_free_buffer(buffer.Ptr, buffer.Len);
        }
    }

    public static void FreeStatusMessage(Native.Status status)
    {
        if (status.Message != IntPtr.Zero)
        {
            Native.Utils.derec_free_string(status.Message);
        }
    }

    public static uint ReadU32(ReadOnlySpan<byte> span, ref int offset)
    {
        const int size = 4;

        if (offset + size > span.Length)
        {
            throw new InvalidDataException("Unexpected end of buffer while reading u32.");
        }

        uint value = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(offset, size));
        offset += size;
        return value;
    }

    public static ulong ReadU64(ReadOnlySpan<byte> span, ref int offset)
    {
        const int size = 8;

        if (offset + size > span.Length)
        {
            throw new InvalidDataException("Unexpected end of buffer while reading u64.");
        }

        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(span.Slice(offset, size));
        offset += size;
        return value;
    }
}
