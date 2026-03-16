using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Sharing
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProtectSecretResult
    {
        public Status Status;
        public Buffer Shares;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProtectSecretResult protect_secret(
        byte[] secretId,
        UIntPtr secretIdLen,
        byte[] secretData,
        UIntPtr secretDataLen,
        ulong[] channels,
        UIntPtr channelsLen,
        UIntPtr threshold,
        int version,
        int[]? keepList,
        UIntPtr keepListLen,
        byte[]? description,
        UIntPtr descriptionLen
    );
}
