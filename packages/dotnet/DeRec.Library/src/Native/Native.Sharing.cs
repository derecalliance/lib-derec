using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Sharing
{
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
        ulong[] channelIds,
        UIntPtr channelsLen,
        UIntPtr threshold,
        int version
    );

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceStoreShareRequestMessageResult
    {
        public Status Status;
        public Buffer WireBytes;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceStoreShareRequestMessageResult produce_store_share_request_message(
        ulong channelId,
        int version,
        byte[] secretId,
        UIntPtr secretIdLen,
        byte[] committedShare,
        UIntPtr committedShareLen,
        int[] keepList,
        UIntPtr keepListLen,
        byte[] description,
        UIntPtr descriptionLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceStoreShareResponseMessageResult
    {
        public Status Status;
        public Buffer WireBytes;
        public Buffer CommittedShareBytes;
        public Buffer SecretIdBytes;
        public int Version;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceStoreShareResponseMessageResult produce_store_share_response_message(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[] requestBytes,
        UIntPtr requestBytesLen
    );

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessStoreShareResponseMessageResult
    {
        public Status Status;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessStoreShareResponseMessageResult process_store_share_response_message(
        int version,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[] responseBytes,
        UIntPtr responseBytesLen
    );
}
