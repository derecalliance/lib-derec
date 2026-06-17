// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

// All `byte[] buf, UIntPtr bufLen` parameter pairs in this class follow
// the global FFI marshaling contract on `Native.Utils` — pass
// `(UIntPtr)buf.Length`; never a wire-derived value. Every returned
// `Buffer` field must be released via `Utils.FreeBuffer` (see
// `Native.Buffer` for the ownership contract).
internal static class Recovery
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceGetShareRequestMessageResult
    {
        public DeRecError Error;
        public Buffer RequestWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractGetShareRequestResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer RequestProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceGetShareResponseMessageResult
    {
        public DeRecError Error;
        public Buffer ResponseWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractGetShareResponseResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer ResponseProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RecoverFromShareResponsesResult
    {
        public DeRecError Error;
        public Buffer SecretData;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceGetShareRequestMessageResult produce_get_share_request_message(
        ulong channelId,
        ulong secretId,
        uint version,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[]? replyTo,
        UIntPtr replyToLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractGetShareRequestResult extract_get_share_request(
        byte[] requestBytes,
        UIntPtr requestBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceGetShareResponseMessageResult produce_get_share_response_message(
        ulong channelId,
        byte[] requestProtoBytes,
        UIntPtr requestProtoBytesLen,
        byte[] storedShareProtoBytes,
        UIntPtr storedShareProtoBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractGetShareResponseResult extract_get_share_response(
        byte[] responseBytes,
        UIntPtr responseBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern RecoverFromShareResponsesResult recover_from_share_responses(
        byte[] responses,
        UIntPtr responsesLen,
        ulong secretId,
        uint version
    );
}
