// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library;

/// <summary>
/// Typed exception thrown by all DeRec primitive operations on failure.
/// Mirrors <c>DeRecError</c> from the C FFI: <see cref="Category"/> identifies
/// the source phase or layer, <see cref="Code"/> identifies the specific
/// reason, and the structured fields are valid only for specific codes:
/// <list type="bullet">
/// <item><see cref="PeerStatus"/> / <see cref="PeerMemo"/> are populated
/// when <see cref="Code"/> equals <see cref="DeRecCode.NonOkStatus"/>.</item>
/// <item><see cref="Expected"/> / <see cref="Got"/> are populated when
/// <see cref="Code"/> equals <see cref="DeRecCode.VersionMismatch"/>.</item>
/// </list>
/// </summary>
public sealed class DeRecException : Exception
{
    public int Category { get; }
    public int Code { get; }
    public int PeerStatus { get; }
    public string? PeerMemo { get; }
    public uint Expected { get; }
    public uint Got { get; }

    internal DeRecException(int category, int code, string message, int peerStatus, string? peerMemo, uint expected, uint got)
        : base(message)
    {
        Category = category;
        Code = code;
        PeerStatus = peerStatus;
        PeerMemo = peerMemo;
        Expected = expected;
        Got = got;
    }

    public override string ToString()
    {
        var detail = string.Empty;
        if (Code == DeRecCode.NonOkStatus)
        {
            detail = $" peer_status={PeerStatus}, peer_memo={PeerMemo}";
        }
        else if (Code == DeRecCode.VersionMismatch)
        {
            detail = $" expected={Expected}, got={Got}";
        }
        return $"DeRecException(category={Category}, code={Code}): {Message}{detail}";
    }
}

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

    /// <summary>
    /// Throws a <see cref="DeRecException"/> when <paramref name="error"/>
    /// indicates failure. Always releases the error's owned strings before
    /// returning or throwing.
    /// </summary>
    public static void ThrowIfError(Native.DeRecError error)
    {
        if (error.Category == DeRecCategory.Ok)
        {
            // Success: there are no owned strings, but we still call free for safety.
            Native.Utils.derec_free_error(ref error);
            return;
        }

        string message = error.Message != IntPtr.Zero
            ? Marshal.PtrToStringAnsi(error.Message) ?? "unknown error"
            : "unknown error";

        string? peerMemo = error.PeerMemo != IntPtr.Zero
            ? Marshal.PtrToStringAnsi(error.PeerMemo)
            : null;

        var ex = new DeRecException(
            category: error.Category,
            code: error.Code,
            message: message,
            peerStatus: error.PeerStatus,
            peerMemo: peerMemo,
            expected: error.Expected,
            got: error.Got
        );

        Native.Utils.derec_free_error(ref error);
        throw ex;
    }

    public static void FreeBuffer(Native.Buffer buffer)
    {
        if (buffer.Ptr != IntPtr.Zero)
        {
            Native.Utils.derec_free_buffer(buffer.Ptr, buffer.Len);
        }
    }
}
