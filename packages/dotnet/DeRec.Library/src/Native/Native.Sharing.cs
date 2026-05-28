// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Sharing
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProtectSecretResult
    {
        public DeRecError Error;
        public Buffer SharesWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceStoreShareRequestMessageResult
    {
        public DeRecError Error;
        public Buffer WireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractStoreShareRequestResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer RequestProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceStoreShareResponseMessageResult
    {
        public DeRecError Error;
        public Buffer WireBytes;
        public Buffer CommittedShareBytes;
        public ulong SecretId;
        public uint Version;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractStoreShareResponseResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer ResponseProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessStoreShareResponseMessageResult
    {
        public DeRecError Error;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProtectSecretResult protect_secret(
        ulong secretId,
        byte[] secretData,
        UIntPtr secretDataLen,
        ulong[] channelIds,
        UIntPtr channelsLen,
        UIntPtr threshold,
        uint version
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceStoreShareRequestMessageResult produce_store_share_request_message(
        ulong channelId,
        uint version,
        ulong secretId,
        byte[] committedShare,
        UIntPtr committedShareLen,
        uint[] keepList,
        UIntPtr keepListLen,
        byte[] description,
        UIntPtr descriptionLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractStoreShareRequestResult extract_store_share_request(
        byte[] requestBytes,
        UIntPtr requestBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceStoreShareResponseMessageResult produce_store_share_response_message(
        ulong channelId,
        byte[] requestProtoBytes,
        UIntPtr requestProtoBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractStoreShareResponseResult extract_store_share_response(
        byte[] responseBytes,
        UIntPtr responseBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessStoreShareResponseMessageResult process_store_share_response_message(
        uint version,
        byte[] responseProtoBytes,
        UIntPtr responseProtoBytesLen
    );
}
