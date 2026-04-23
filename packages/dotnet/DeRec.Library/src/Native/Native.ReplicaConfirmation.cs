using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class ReplicaConfirmation
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceReplicaConfirmationRequestResult
    {
        public Status Status;
        public Buffer RequestWireBytes;
        public Buffer Fingerprint;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractReplicaConfirmationRequestResult
    {
        public Status Status;
        public int ReplicaId;
        public Buffer Fingerprint;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceReplicaConfirmationResponseResult
    {
        public Status Status;
        public Buffer ResponseWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessReplicaConfirmationResponseResult
    {
        public Status Status;
        public int ReplicaId;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceReplicaConfirmationRequestResult produce_replica_confirmation_request(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        int replicaId
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractReplicaConfirmationRequestResult extract_replica_confirmation_request(
        byte[] requestWireBytes,
        UIntPtr requestWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceReplicaConfirmationResponseResult produce_replica_confirmation_response(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        int replicaId
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessReplicaConfirmationResponseResult process_replica_confirmation_response(
        byte[] responseWireBytes,
        UIntPtr responseWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );
}
