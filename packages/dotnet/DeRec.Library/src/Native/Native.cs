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

    // The Rust ABI takes a `*mut DeRecError` so the implementation can
    // null out `Message` and `PeerMemo` after freeing them — a second
    // call on the same struct then becomes a safe null-pointer no-op
    // instead of a heap-corrupting double-free. We mirror that on the
    // managed side via `ref`, which pins the struct for the call and
    // surfaces the nulled-out pointers back to the caller on return.
    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void derec_free_error(ref DeRecError error);
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

