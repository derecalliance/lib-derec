// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Primitives;

public static partial class Pairing
{
    /// <summary>
    /// Human-readable fingerprint of a pairing's shared key; the same
    /// derivation the protocol's <c>GetFingerprint</c> uses. A
    /// <see cref="ContactMode.NoKeys"/> pairing MUST be confirmed by both
    /// sides comparing this value out of band before the channel is used.
    /// Throws <see cref="DeRecException"/> if <paramref name="sharedKey"/> is
    /// not a valid shared key.
    /// </summary>
    public static string Fingerprint(byte[] sharedKey)
    {
        Native.Pairing.PairingFingerprintResult nativeResult =
            Native.Pairing.pairing_fingerprint(
                sharedKey,
                (UIntPtr)sharedKey.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Error);
            if (nativeResult.Fingerprint == IntPtr.Zero)
                throw new InvalidOperationException("pairing_fingerprint returned null without an error.");
            return Marshal.PtrToStringUTF8(nativeResult.Fingerprint)
                ?? throw new InvalidOperationException("pairing_fingerprint returned an invalid UTF-8 string.");
        }
        finally
        {
            if (nativeResult.Fingerprint != IntPtr.Zero)
                Native.Utils.derec_free_string(nativeResult.Fingerprint);
        }
    }
}
