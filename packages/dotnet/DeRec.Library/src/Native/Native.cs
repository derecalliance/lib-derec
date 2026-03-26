using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Utils
{
    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void derec_free_buffer(IntPtr ptr, UIntPtr len);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void derec_free_string(IntPtr ptr);
}

[StructLayout(LayoutKind.Sequential)]
internal struct Buffer
{
    public IntPtr Ptr;
    public UIntPtr Len;
}

[StructLayout(LayoutKind.Sequential)]
internal struct Status
{
    public int Code;
    public IntPtr Message;
}
