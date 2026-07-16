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
internal static class Unpairing
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceUnpairRequestMessageResult
    {
        public DeRecError Error;
        public Buffer RequestWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractUnpairRequestResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        /// <summary>Owned C string. Release with derec_free_string.</summary>
        public IntPtr Memo;
        public Buffer RequestProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceUnpairResponseMessageResult
    {
        public DeRecError Error;
        public Buffer ResponseWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractUnpairResponseResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer ResponseProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessUnpairResponseResult
    {
        public DeRecError Error;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceUnpairRequestMessageResult produce_unpair_request_message(
        ulong channelId,
        byte[] memoBytes,
        UIntPtr memoBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[]? replyTo,
        UIntPtr replyToLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractUnpairRequestResult extract_unpair_request(
        byte[] requestBytes,
        UIntPtr requestBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceUnpairResponseMessageResult produce_unpair_response_message(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractUnpairResponseResult extract_unpair_response(
        byte[] responseBytes,
        UIntPtr responseBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessUnpairResponseResult process_unpair_response_message(
        byte[] responseProtoBytes,
        UIntPtr responseProtoBytesLen
    );
}
