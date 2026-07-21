// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

[StructLayout(LayoutKind.Sequential)]
internal struct DeRecProtocolVersion
{
    public uint Major;
    public uint Minor;
}

internal static class ProtocolVersion
{
    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecProtocolVersion derec_protocol_version();
}
