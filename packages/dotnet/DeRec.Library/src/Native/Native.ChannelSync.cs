using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class ChannelSync
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceChannelSyncRequestResult
    {
        public Status Status;
        public Buffer RequestWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractChannelSyncRequestResult
    {
        public Status Status;
        public ulong ChannelId;
        public Buffer SharedKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceChannelSyncResponseResult
    {
        public Status Status;
        public Buffer ResponseWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessChannelSyncResponseResult
    {
        public Status Status;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceChannelSyncRequestResult produce_channel_sync_request(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        ulong newChannelId,
        byte[] newSharedKey,
        UIntPtr newSharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractChannelSyncRequestResult extract_channel_sync_request(
        byte[] requestWireBytes,
        UIntPtr requestWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceChannelSyncResponseResult produce_channel_sync_response(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessChannelSyncResponseResult process_channel_sync_response(
        byte[] responseWireBytes,
        UIntPtr responseWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );
}
