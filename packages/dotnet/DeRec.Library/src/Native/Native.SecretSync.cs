using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class SecretSync
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceSecretSyncRequestResult
    {
        public Status Status;
        public Buffer RequestWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractSecretSyncRequestResult
    {
        public Status Status;
        public Buffer SecretId;
        public int Version;
        public Buffer Description;
        public Buffer ChannelIds;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceSecretSyncResponseResult
    {
        public Status Status;
        public Buffer ResponseWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessSecretSyncResponseResult
    {
        public Status Status;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceSecretSyncRequestResult produce_secret_sync_request(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[] secretId,
        UIntPtr secretIdLen,
        int version,
        byte[] description,
        UIntPtr descriptionLen,
        byte[] channelIds,
        UIntPtr channelIdsLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractSecretSyncRequestResult extract_secret_sync_request(
        byte[] requestWireBytes,
        UIntPtr requestWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceSecretSyncResponseResult produce_secret_sync_response(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessSecretSyncResponseResult process_secret_sync_response(
        byte[] responseWireBytes,
        UIntPtr responseWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );
}
