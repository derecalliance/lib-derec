using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

[StructLayout(LayoutKind.Sequential)]
internal struct DeRecProtocolVersion
{
    public int Major;
    public int Minor;
}

internal static class ProtocolVersion
{
    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecProtocolVersion derec_protocol_version();
}
