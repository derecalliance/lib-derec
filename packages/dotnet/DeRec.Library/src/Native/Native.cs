// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Utils
{
    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void derec_free_buffer(IntPtr ptr, UIntPtr len);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void derec_free_string(IntPtr ptr);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void derec_free_error(DeRecError error);
}

[StructLayout(LayoutKind.Sequential)]
internal struct Buffer
{
    public IntPtr Ptr;
    public UIntPtr Len;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DeRecError
{
    public int Category;
    public int Code;
    public IntPtr Message;
    public int PeerStatus;
    public IntPtr PeerMemo;
    public uint Expected;
    public uint Got;
}

