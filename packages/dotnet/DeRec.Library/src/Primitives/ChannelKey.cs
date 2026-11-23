// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;

namespace DeRec.Library;

/// <summary>
/// Channel-key helpers for primitives used directly on a rotated channel.
/// </summary>
public static class ChannelKey
{
    /// <summary>
    /// Derive the channel key at <paramref name="toEpoch"/> forward from
    /// <paramref name="key"/>, the key at <paramref name="epoch"/>.
    /// </summary>
    /// <remarks>
    /// Derivation only moves forward. A <paramref name="toEpoch"/> below
    /// <paramref name="epoch"/>, or more than 512 above it, is refused as
    /// invalid input.
    /// </remarks>
    /// <param name="key">The 32-byte channel key at <paramref name="epoch"/>.</param>
    /// <param name="epoch">The epoch of <paramref name="key"/>.</param>
    /// <param name="toEpoch">The epoch to derive the key for.</param>
    /// <returns>The 32-byte channel key at <paramref name="toEpoch"/>.</returns>
    /// <exception cref="DeRecException">Thrown if the key length or the epochs are refused.</exception>
    public static byte[] Derive(byte[] key, uint epoch, uint toEpoch)
    {
        ArgumentNullException.ThrowIfNull(key);

        Native.ChannelKey.DeriveChannelKeyResult nativeResult =
            Native.ChannelKey.derive_channel_key(
                key,
                (UIntPtr)key.Length,
                epoch,
                toEpoch
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Error);
            return Utils.CopyBuffer(nativeResult.KeyBytes);
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.KeyBytes);
        }
    }
}
