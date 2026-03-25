using System;
using System.Runtime.InteropServices;

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
}
