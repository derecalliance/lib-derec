// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

// All `byte[] buf, UIntPtr bufLen` parameter pairs in this class follow
// the global FFI marshaling contract on `Native.Utils` — pass
// `(UIntPtr)buf.Length`; never a wire-derived value. Every returned
// `Buffer` field must be released via `Utils.FreeBuffer` (see
// `Native.Buffer` for the ownership contract).
internal static class Verification
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceVerifyShareRequestMessageResult
    {
        public DeRecError Error;
        public Buffer RequestWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractVerifyShareRequestResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer RequestProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceVerifyShareResponseMessageResult
    {
        public DeRecError Error;
        public Buffer ResponseWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractVerifyShareResponseResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer ResponseProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct VerifyShareResponseResult
    {
        public DeRecError Error;

        [MarshalAs(UnmanagedType.I1)]
        public bool IsValid;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceVerifyShareRequestMessageResult produce_verify_share_request_message(
        ulong channelId,
        ulong secretId,
        uint version,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[]? replyTo,
        UIntPtr replyToLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractVerifyShareRequestResult extract_verify_share_request(
        byte[] requestBytes,
        UIntPtr requestBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceVerifyShareResponseMessageResult produce_verify_share_response_message(
        ulong channelId,
        byte[] requestProtoBytes,
        UIntPtr requestProtoBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[] shareContent,
        UIntPtr shareContentLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractVerifyShareResponseResult extract_verify_share_response(
        byte[] responseBytes,
        UIntPtr responseBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern VerifyShareResponseResult process_verify_share_response_message(
        byte[] requestProtoBytes,
        UIntPtr requestProtoBytesLen,
        byte[] responseProtoBytes,
        UIntPtr responseProtoBytesLen,
        byte[] shareContent,
        UIntPtr shareContentLen
    );
}
