// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

// All `byte[] buf, UIntPtr bufLen` parameter pairs in this class follow
// the global FFI marshaling contract on `Native.Utils` — pass
// `(UIntPtr)buf.Length`; never a wire-derived value. Every returned
// `Buffer` field must be released via `Utils.FreeBuffer` (see
// `Native.Buffer` for the ownership contract).
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
    internal struct ProducePairResponseMessageResult
    {
        public DeRecError Error;
        public Buffer ResponseWireBytes;
        public Buffer PeerTransportProtocol;
        public Buffer SharedKey;
        public ulong ChannelId;
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
        public ulong ChannelId;
    }


    [StructLayout(LayoutKind.Sequential)]
    internal struct ProducePrePairRequestMessageResult
    {
        public DeRecError Error;
        public Buffer EnvelopeWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractPrePairRequestResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer RequestProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProducePrePairResponseMessageResult
    {
        public DeRecError Error;
        public Buffer EnvelopeWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractPrePairResponseResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer ResponseProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessPrePairResponseMessageResult
    {
        public DeRecError Error;
        public Buffer MlkemEncapsulationKey;
        public Buffer EciesPublicKey;
        public ulong Nonce;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern CreateContactMessageResult create_contact_message(
        ulong channelId,
        int contactMode,
        byte[] transportProtocolBytes,
        UIntPtr transportProtocolBytesLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecError validate_contact_message(
        byte[] contactMessageBytes,
        UIntPtr contactMessageBytesLen
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
    internal static extern ProducePairResponseMessageResult produce_pair_response_message(
        ulong channelId,
        byte[] requestProtoBytes,
        UIntPtr requestProtoBytesLen,
        byte[] secretKeyMaterial,
        UIntPtr secretKeyMaterialLen,
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


    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProducePrePairRequestMessageResult produce_pre_pair_request_message(
        byte[] transportProtocolBytes,
        UIntPtr transportProtocolBytesLen,
        byte[] contactMessageBytes,
        UIntPtr contactMessageBytesLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractPrePairRequestResult extract_pre_pair_request(
        byte[] envelopeBytes,
        UIntPtr envelopeBytesLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProducePrePairResponseMessageResult produce_pre_pair_response_message(
        ulong channelId,
        byte[] requestProtoBytes,
        UIntPtr requestProtoBytesLen,
        byte[] secretKeyMaterial,
        UIntPtr secretKeyMaterialLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractPrePairResponseResult extract_pre_pair_response(
        byte[] envelopeBytes,
        UIntPtr envelopeBytesLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessPrePairResponseMessageResult process_pre_pair_response_message(
        byte[] contactMessageBytes,
        UIntPtr contactMessageBytesLen,
        byte[] responseProtoBytes,
        UIntPtr responseProtoBytesLen
    );
}
