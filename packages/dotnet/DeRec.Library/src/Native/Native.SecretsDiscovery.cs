using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class SecretsDiscovery
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceSecretsDiscoveryRequestResult
    {
        public Status Status;
        public Buffer RequestWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractSecretsDiscoveryRequestResult
    {
        public Status Status;
        public int LastBatchIndex;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceSecretsDiscoveryResponseResult
    {
        public Status Status;
        public Buffer ResponseWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessSecretsDiscoveryResponseResult
    {
        public Status Status;
        public int TotalBatches;
        public int CurrentBatch;
        public Buffer EntriesWireBytes;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceSecretsDiscoveryRequestResult produce_secrets_discovery_request(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        int lastBatchIndex
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractSecretsDiscoveryRequestResult extract_secrets_discovery_request(
        byte[] requestWireBytes,
        UIntPtr requestWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceSecretsDiscoveryResponseResult produce_secrets_discovery_response(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[] entriesWireBytes,
        UIntPtr entriesWireBytesLen,
        int totalBatches,
        int currentBatch
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessSecretsDiscoveryResponseResult process_secrets_discovery_response(
        byte[] responseWireBytes,
        UIntPtr responseWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );
}
