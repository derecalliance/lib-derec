// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

// All `byte[] buf, UIntPtr bufLen` parameter pairs in this class follow
// the global FFI marshaling contract on `Native.Utils` — pass
// `(UIntPtr)buf.Length`; never a wire-derived value. Every returned
// `Buffer` field must be released via `Utils.FreeBuffer` (see
// `Native.Buffer` for the ownership contract).
internal static class Envelope
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ApplyTraceIdResult
    {
        public DeRecError Error;
        public Buffer WireBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ReadTraceIdResult
    {
        public DeRecError Error;
        public ulong TraceId;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ApplyTraceIdResult apply_trace_id_to_envelope(
        byte[] envelope,
        UIntPtr envelopeLen,
        ulong traceId
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ReadTraceIdResult read_trace_id_from_envelope(
        byte[] envelope,
        UIntPtr envelopeLen
    );
}
