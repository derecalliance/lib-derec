// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Pairing
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct CreateContactMessageResult
    {
        public DeRecError Error;
        public Buffer ContactWireBytes;
        public Buffer SecretKeyMaterial;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProducePairRequestMessageResult
    {
        public DeRecError Error;
        public Buffer RequestWireBytes;
        public Buffer InitiatorContactMessageWireBytes;
        public Buffer SecretKeyMaterial;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractPairRequestResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer RequestProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct AcceptPairRequestMessageResult
    {
        public DeRecError Error;
        public Buffer ResponseWireBytes;
        public Buffer PeerTransportProtocol;
        public Buffer SharedKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RejectPairRequestMessageResult
    {
        public DeRecError Error;
        public Buffer ResponseWireBytes;
        public Buffer PeerTransportProtocol;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractPairResponseResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer ResponseProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessPairResponseMessageResult
    {
        public DeRecError Error;
        public Buffer SharedKey;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern CreateContactMessageResult create_contact_message(
        ulong channelId,
        byte[] transportProtocolBytes,
        UIntPtr transportProtocolBytesLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProducePairRequestMessageResult produce_pair_request_message(
        int senderKind,
        byte[] transportProtocolBytes,
        UIntPtr transportProtocolBytesLen,
        byte[] contactMessageBytes,
        UIntPtr contactMessageBytesLen,
        byte[]? communicationInfoBytes,
        UIntPtr communicationInfoBytesLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractPairRequestResult extract_pair_request(
        byte[] requestBytes,
        UIntPtr requestBytesLen,
        byte[] secretKeyMaterial,
        UIntPtr secretKeyMaterialLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern AcceptPairRequestMessageResult accept_pair_request_message(
        int senderKind,
        byte[] requestProtoBytes,
        UIntPtr requestProtoBytesLen,
        byte[] secretKeyMaterial,
        UIntPtr secretKeyMaterialLen,
        byte[]? communicationInfoBytes,
        UIntPtr communicationInfoBytesLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern RejectPairRequestMessageResult reject_pair_request_message(
        int senderKind,
        byte[] requestProtoBytes,
        UIntPtr requestProtoBytesLen,
        int statusEnum,
        byte[] memoBytes,
        UIntPtr memoBytesLen,
        byte[]? communicationInfoBytes,
        UIntPtr communicationInfoBytesLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractPairResponseResult extract_pair_response(
        byte[] responseBytes,
        UIntPtr responseBytesLen,
        byte[] secretKeyMaterial,
        UIntPtr secretKeyMaterialLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessPairResponseMessageResult process_pair_response_message(
        byte[] contactMessageBytes,
        UIntPtr contactMessageBytesLen,
        byte[] responseProtoBytes,
        UIntPtr responseProtoBytesLen,
        byte[] secretKeyMaterial,
        UIntPtr secretKeyMaterialLen
    );
}
