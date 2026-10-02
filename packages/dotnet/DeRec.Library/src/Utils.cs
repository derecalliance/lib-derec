// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;
using System.Collections.Generic;
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
/// <item><see cref="ConflictingChannelIds"/> is populated when
/// <see cref="Code"/> equals <see cref="DeRecCode.RestoreConflict"/>.</item>
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

    /// <summary>
    /// Channel ids that already exist at the canonical ids carried by the
    /// recovered <c>Secret</c>, when <see cref="Code"/> equals
    /// <see cref="DeRecCode.RestoreConflict"/>. Clear exactly these and retry
    /// the restore. Empty for every other code.
    /// </summary>
    public IReadOnlyList<ulong> ConflictingChannelIds { get; }

    /// <summary>Stable name of <see cref="Category"/>, e.g. <c>"pairing"</c>.</summary>
    public string CategoryName => DeRecCategory.Name(Category);

    /// <summary>Stable name of <see cref="Code"/>, e.g. <c>"no_usable_endpoint"</c>.</summary>
    public string CodeName => DeRecCode.Name(Code);

    internal DeRecException(int category, int code, string message, int peerStatus, string? peerMemo, uint expected, uint got,
        IReadOnlyList<ulong>? conflictingChannelIds = null)
        : base(message)
    {
        Category = category;
        Code = code;
        PeerStatus = peerStatus;
        PeerMemo = peerMemo;
        Expected = expected;
        Got = got;
        ConflictingChannelIds = conflictingChannelIds ?? Array.Empty<ulong>();
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
        return $"DeRecException(category={Category} ({CategoryName}), code={Code} ({CodeName})): {Message}{detail}";
    }
}

internal static class Utils
{
    /// <summary>
    /// Copies the contents of a native-allocated <see cref="Native.Buffer"/>
    /// into a fresh managed <c>byte[]</c>.
    /// </summary>
    /// <remarks>
    /// Does <b>not</b> release the underlying native allocation. After this
    /// call returns, the caller still owns <paramref name="buffer"/> and
    /// MUST invoke <see cref="FreeBuffer"/> on it exactly once — typically
    /// from a <c>finally</c> block paired with the call site so exception
    /// paths still release the allocation. See <see cref="Native.Buffer"/>
    /// for the full ownership contract.
    /// </remarks>
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
    public static void ThrowIfError(Native.DeRecError error) =>
        ThrowIfError(error, conflictingChannelIds: null);

    /// <summary>
    /// <see cref="ThrowIfError(Native.DeRecError)"/>, attaching
    /// <paramref name="conflictingChannelIds"/> to the thrown exception.
    /// </summary>
    public static void ThrowIfError(Native.DeRecError error, IReadOnlyList<ulong>? conflictingChannelIds)
    {
        if (error.Category == DeRecCategory.Ok)
        {
            // Success: there are no owned strings, but we still call free for safety.
            Native.Utils.derec_free_error(ref error);
            return;
        }

        string message = error.Message != IntPtr.Zero
            ? Marshal.PtrToStringUTF8(error.Message) ?? "unknown error"
            : "unknown error";

        string? peerMemo = error.PeerMemo != IntPtr.Zero
            ? Marshal.PtrToStringUTF8(error.PeerMemo)
            : null;

        var ex = new DeRecException(
            category: error.Category,
            code: error.Code,
            message: message,
            peerStatus: error.PeerStatus,
            peerMemo: peerMemo,
            expected: error.Expected,
            got: error.Got,
            conflictingChannelIds: conflictingChannelIds
        );

        Native.Utils.derec_free_error(ref error);
        throw ex;
    }

    /// <summary>
    /// Decodes a native JSON array of decimal-string channel ids into
    /// <c>ulong</c> values. An empty buffer decodes to an empty list. Does not
    /// release <paramref name="buffer"/>.
    /// </summary>
    public static IReadOnlyList<ulong> ParseChannelIdList(Native.Buffer buffer)
    {
        byte[] json = CopyBuffer(buffer);
        if (json.Length == 0)
        {
            return Array.Empty<ulong>();
        }
        var ids = System.Text.Json.JsonSerializer.Deserialize<string[]>(json) ?? Array.Empty<string>();
        return Array.ConvertAll(ids, id => ulong.Parse(id, System.Globalization.CultureInfo.InvariantCulture));
    }

    /// <summary>
    /// Releases the native allocation backing a <see cref="Native.Buffer"/>
    /// returned across the FFI boundary.
    /// </summary>
    /// <remarks>
    /// MUST be called exactly once for every <see cref="Native.Buffer"/>
    /// the native library returns, regardless of whether the surrounding
    /// call succeeded or threw. The canonical pattern is:
    /// <code>
    /// try {
    ///     Utils.ThrowIfError(nativeResult.Error);
    ///     return Utils.CopyBuffer(nativeResult.SomeBuffer);
    /// } finally {
    ///     Utils.FreeBuffer(nativeResult.SomeBuffer);
    /// }
    /// </code>
    /// Skipping the call leaks native memory invisibly to the GC; calling
    /// it twice on the same <see cref="Native.Buffer"/> is undefined
    /// behavior. Null-pointer safe: harmless to call unconditionally in
    /// <c>finally</c> when the native side may not have allocated (e.g.
    /// after an error return).
    /// </remarks>
    public static void FreeBuffer(Native.Buffer buffer)
    {
        if (buffer.Ptr != IntPtr.Zero)
        {
            Native.Utils.derec_free_buffer(buffer.Ptr, buffer.Len);
        }
    }
}
