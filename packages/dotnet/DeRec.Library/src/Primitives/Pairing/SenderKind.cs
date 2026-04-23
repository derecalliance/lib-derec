// SPDX-License-Identifier: Apache-2.0

namespace DeRec.Library.Primitives;

public static partial class Pairing
{
    public enum SenderKind
    {
        OwnerNonRecovery = 0,
        OwnerRecovery = 1,
        Helper = 2,
        Replica = 3,
    }
}
