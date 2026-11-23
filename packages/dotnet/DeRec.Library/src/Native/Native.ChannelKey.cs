// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

// `byte[] key, UIntPtr keyLen` follows the global FFI marshaling contract on
// `Native.Utils` — pass `(UIntPtr)key.Length`. The returned `Buffer` must be
// released via `Utils.FreeBuffer`.
internal static class ChannelKey
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct DeriveChannelKeyResult
    {
        public DeRecError Error;
        public Buffer KeyBytes;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeriveChannelKeyResult derive_channel_key(
        byte[] key,
        UIntPtr keyLen,
        uint epoch,
        uint toEpoch
    );
}
