using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Recovery
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct GenerateShareRequestResult
    {
        public Status Status;
        public Buffer WireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GenerateShareResponseResult
    {
        public Status Status;
        public Buffer WireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RecoverFromShareResponsesResult
    {
        public Status Status;
        public Buffer SecretData;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern GenerateShareRequestResult generate_share_request(
        ulong channelId,
        byte[] secretId,
        UIntPtr secretIdLen,
        int version,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern GenerateShareResponseResult generate_share_response(
        ulong channelId,
        byte[] secretId,
        UIntPtr secretIdLen,
        byte[] requestWireBytes,
        UIntPtr requestWireBytesLen,
        byte[] storedShareRequestWireBytes,
        UIntPtr storedShareRequestWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern RecoverFromShareResponsesResult recover_from_share_responses(
        byte[] responses,
        UIntPtr responsesLen,
        byte[] secretId,
        UIntPtr secretIdLen,
        int version
    );
}
