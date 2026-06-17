// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

/// <summary>
/// Shared FFI marshaling utilities and global invariants for the
/// <c>Native.*</c> P/Invoke layer.
///
/// <para>
/// <b>Length parameters (inbound buffers).</b> Every extern in this
/// namespace that takes a <c>byte[] buf, UIntPtr bufLen</c> pair
/// requires <c>bufLen == (UIntPtr)buf.Length</c>. The Rust side
/// reconstructs a slice via <c>std::slice::from_raw_parts(ptr, bufLen)</c>
/// and trusts the caller-supplied length as the readable range of the
/// pinned array — there is no managed-runtime guard against
/// pointer/length desynchronization once the call crosses the FFI
/// boundary. Callers MUST derive the length directly from the array's
/// <see cref="Array.Length"/>; NEVER derive it from a wire-protocol
/// header field, a separately-tracked counter, or any external source.
/// Passing a length larger than <c>buf.Length</c> causes an
/// out-of-bounds read in native memory that no managed exception can
/// catch.
/// </para>
///
/// <para>
/// <b>Returned buffers (outbound).</b> Native code returns
/// <see cref="Buffer"/> values that point into the Rust allocator's
/// heap. Ownership transfers to the .NET caller, which MUST invoke
/// <see cref="FreeBuffer"/> exactly once for every successful return —
/// typically via a <c>try { CopyBuffer; ... } finally { FreeBuffer; }</c>
/// block so exception paths still release the allocation. Missing the
/// free leaks native memory invisibly to the GC; calling free twice on
/// the same buffer is undefined behavior.
/// </para>
/// </summary>
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

/// <summary>
/// Non-owning view of a Rust-allocated byte buffer returned across the
/// FFI boundary.
/// </summary>
/// <remarks>
/// The buffer was allocated by the native library; ownership transfers
/// to the .NET caller on receipt. The .NET caller MUST invoke
/// <see cref="DeRec.Library.Utils.FreeBuffer"/> on this struct exactly
/// once after consuming it — typically by reading the bytes via
/// <see cref="DeRec.Library.Utils.CopyBuffer"/> inside a
/// <c>try</c> block and calling <c>FreeBuffer</c> from the matching
/// <c>finally</c> so the allocation is released even on exception
/// paths. Skipping the free call leaks native memory; calling free
/// twice on the same <see cref="Buffer"/> is undefined behavior.
/// <para>
/// The <see cref="Ptr"/> field is <see cref="IntPtr.Zero"/> when the
/// native side returned no buffer (e.g. on error). <c>FreeBuffer</c>
/// is null-pointer safe and may be called unconditionally in
/// <c>finally</c>.
/// </para>
/// </remarks>
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

