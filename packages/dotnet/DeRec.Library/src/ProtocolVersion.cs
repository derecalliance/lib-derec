using DeRec.Library.Native;

namespace DeRec.Library;

public readonly struct ProtocolVersion
{
    public int Major { get; }
    public int Minor { get; }

    internal ProtocolVersion(int major, int minor)
    {
        Major = major;
        Minor = minor;
    }

    public static ProtocolVersion Current()
    {
        DeRecProtocolVersion native = Native.ProtocolVersion.derec_protocol_version();

        return new ProtocolVersion(
            native.Major,
            native.Minor
        );
    }

    public override string ToString()
    {
        return $"DeRec {Major}.{Minor}";
    }
}
