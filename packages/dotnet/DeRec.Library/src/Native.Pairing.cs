using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Pairing
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct CreateContactMessageResult
    {
        public Status Status;
        public Buffer ContactMessage;
        public Buffer SecretKeyMaterial;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProducePairingRequestMessageResult
    {
        public Status Status;
        public Buffer PairRequestMessage;
        public Buffer SecretKeyMaterial;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProducePairingResponseMessageResult
    {
        public Status Status;
        public Buffer PairResponseMessage;
        public Buffer SharedKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessPairingResponseMessageResult
    {
        public Status Status;
        public Buffer SharedKey;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern CreateContactMessageResult create_contact_message(
        ulong channelId,
        byte[] transportUri,
        UIntPtr transportUriLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProducePairingRequestMessageResult produce_pairing_request_message(
        ulong channelId,
        int peerStatus,
        byte[] contactMessage,
        UIntPtr contactMessageLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProducePairingResponseMessageResult produce_pairing_response_message(
        int peerStatus,
        byte[] pairRequestMessage,
        UIntPtr pairRequestMessageLen,
        byte[] secretKeyMaterial,
        UIntPtr secretKeyMaterialLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessPairingResponseMessageResult process_pairing_response_message(
        byte[] contactMessage,
        UIntPtr contactMessageLen,
        byte[] pairResponseMessage,
        UIntPtr pairResponseMessageLen,
        byte[] secretKeyMaterial,
        UIntPtr secretKeyMaterialLen
    );
}
