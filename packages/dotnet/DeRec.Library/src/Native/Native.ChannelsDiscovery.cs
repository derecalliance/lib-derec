using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class ChannelsDiscovery
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceChannelsDiscoveryRequestResult
    {
        public Status Status;
        public Buffer RequestWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractChannelsDiscoveryRequestResult
    {
        public Status Status;
        public int LastBatchIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceChannelsDiscoveryResponseResult
    {
        public Status Status;
        public Buffer ResponseWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessChannelsDiscoveryResponseResult
    {
        public Status Status;
        public int TotalBatches;
        public int CurrentBatch;
        public Buffer EntriesWireBytes;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceChannelsDiscoveryRequestResult produce_channels_discovery_request(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        int lastBatchIndex
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractChannelsDiscoveryRequestResult extract_channels_discovery_request(
        byte[] requestWireBytes,
        UIntPtr requestWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceChannelsDiscoveryResponseResult produce_channels_discovery_response(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[] entriesWireBytes,
        UIntPtr entriesWireBytesLen,
        int totalBatches,
        int currentBatch
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessChannelsDiscoveryResponseResult process_channels_discovery_response(
        byte[] responseWireBytes,
        UIntPtr responseWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );
}
