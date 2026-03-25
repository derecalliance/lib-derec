using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Verification
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct GenerateVerificationRequestResult
    {
        public Status Status;
        public Buffer RequestWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GenerateVerificationResponseResult
    {
        public Status Status;
        public Buffer ResponseWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct VerifyShareResponseResult
    {
        public Status Status;

        [MarshalAs(UnmanagedType.I1)]
        public bool IsValid;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern GenerateVerificationRequestResult generate_verification_request(
        byte[] secretId,
        UIntPtr secretIdLen,
        ulong channelId,
        int version,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern GenerateVerificationResponseResult generate_verification_response(
        byte[] secretId,
        UIntPtr secretIdLen,
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[] shareContent,
        UIntPtr shareContentLen,
        byte[] requestWireBytes,
        UIntPtr requestWireBytesLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern VerifyShareResponseResult verify_share_response(
        byte[] secretId,
        UIntPtr secretIdLen,
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[] shareContent,
        UIntPtr shareContentLen,
        byte[] responseWireBytes,
        UIntPtr responseWireBytesLen
    );
}
