using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Pairing
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct CreateContactMessageResult
    {
        public Status Status;
        public Buffer ContactWireBytes;
        public Buffer SecretKeyMaterial;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProducePairingRequestMessageResult
    {
        public Status Status;
        public Buffer RequestWireBytes;
        public Buffer SecretKeyMaterial;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProducePairingResponseMessageResult
    {
        public Status Status;
        public Buffer ResponseWireBytes;
        public Buffer TransportProtocol;
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
        int senderKind,
        byte[] transportUri,
        UIntPtr transportUriLen,
        byte[] contactMessageBytes,
        UIntPtr contactMessageBytesLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProducePairingResponseMessageResult produce_pairing_response_message(
        int senderKind,
        byte[] pairRequestWireBytes,
        UIntPtr pairRequestWireBytesLen,
        byte[] pairingSecretKeyMaterial,
        UIntPtr pairingSecretKeyMaterialLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessPairingResponseMessageResult process_pairing_response_message(
        byte[] contactMessageBytes,
        UIntPtr contactMessageBytesLen,
        byte[] pairResponseWireBytes,
        UIntPtr pairResponseWireBytesLen,
        byte[] pairingSecretKeyMaterial,
        UIntPtr pairingSecretKeyMaterialLen
    );
}
