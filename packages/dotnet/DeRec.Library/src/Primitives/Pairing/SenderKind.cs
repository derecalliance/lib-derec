// SPDX-License-Identifier: Apache-2.0

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
