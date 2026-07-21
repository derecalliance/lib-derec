// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

namespace DeRec.Library.Primitives;

public static partial class Pairing
{
    public enum SenderKind
    {
        Owner = 0,
        Helper = 1,
        ReplicaSource = 3,
        ReplicaDestination = 4,
    }
}
