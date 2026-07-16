// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using DeRec.Library.Native;

namespace DeRec.Library;

public readonly struct ProtocolVersion
{
    public uint Major { get; }
    public uint Minor { get; }

    internal ProtocolVersion(uint major, uint minor)
    {
        Major = major;
        Minor = minor;
    }

    public static ProtocolVersion Current()
    {
        DeRecProtocolVersion native = Native.ProtocolVersion.derec_protocol_version();
        return new ProtocolVersion(native.Major, native.Minor);
    }

    public override string ToString() => $"DeRec {Major}.{Minor}";
}
