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
internal static class Discovery
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceGetSecretIdsVersionsRequestMessageResult
    {
        public DeRecError Error;
        public Buffer EnvelopeWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractGetSecretIdsVersionsRequestResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer RequestProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceGetSecretIdsVersionsResponseMessageResult
    {
        public DeRecError Error;
        public Buffer EnvelopeWireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractGetSecretIdsVersionsResponseResult
    {
        public DeRecError Error;
        public ulong ChannelId;
        public Buffer ResponseProtoBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessGetSecretIdsVersionsResponseMessageResult
    {
        public DeRecError Error;
        public Buffer SecretListBytes;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceGetSecretIdsVersionsRequestMessageResult produce_get_secret_ids_versions_request_message(
        ulong channelId,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[]? replyTo,
        UIntPtr replyToLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractGetSecretIdsVersionsRequestResult extract_get_secret_ids_versions_request(
        byte[] requestBytes,
        UIntPtr requestBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceGetSecretIdsVersionsResponseMessageResult produce_get_secret_ids_versions_response_message(
        ulong channelId,
        byte[] secretListBytes,
        UIntPtr secretListBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractGetSecretIdsVersionsResponseResult extract_get_secret_ids_versions_response(
        byte[] responseBytes,
        UIntPtr responseBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProcessGetSecretIdsVersionsResponseMessageResult process_get_secret_ids_versions_response_message(
        byte[] responseProtoBytes,
        UIntPtr responseProtoBytesLen
    );
}
