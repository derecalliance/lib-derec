// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

namespace DeRec.Library.Primitives;

public static partial class Sharing
{
    /// <summary>
    /// A Helper channel and the number of subshares (Shamir points) its
    /// committed share carries. An ordinary Helper carries weight 1.
    /// </summary>
    public readonly record struct WeightedChannel(ulong ChannelId, uint Weight);
}
