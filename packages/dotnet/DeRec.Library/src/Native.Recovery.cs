using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Recovery
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct GenerateShareRequestResult
    {
        public Status Status;
        public Buffer GetShareRequestMessage;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GenerateShareResponseResult
    {
        public Status Status;
        public Buffer GetShareResponseMessage;
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
        int version
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern GenerateShareResponseResult generate_share_response(
        ulong channelId,
        byte[] secretId,
        UIntPtr secretIdLen,
        byte[] request,
        UIntPtr requestLen,
        byte[] shareContent,
        UIntPtr shareContentLen
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
