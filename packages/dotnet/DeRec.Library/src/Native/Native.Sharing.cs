using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Sharing
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ChannelSharedKeyInput
    {
        public ulong ChannelId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] SharedKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProtectSecretResult
    {
        public Status Status;
        public Buffer SharesWireBytes;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProtectSecretResult protect_secret(
        byte[] secretId,
        UIntPtr secretIdLen,
        byte[] secretData,
        UIntPtr secretDataLen,
        ChannelSharedKeyInput[] channels,
        UIntPtr channelsLen,
        UIntPtr threshold,
        int version,
        int[]? keepList,
        UIntPtr keepListLen,
        byte[]? description,
        UIntPtr descriptionLen
    );
}
