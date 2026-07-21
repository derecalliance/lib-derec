// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;

namespace DeRec.Library;

/// <summary>
/// Envelope-level helpers that operate on raw <c>DeRecMessage</c> wire bytes
/// without touching the encrypted inner payload.
///
/// The outer <c>DeRecMessage</c> envelope is plaintext, so a handful of
/// metadata fields can be read or rewritten in-place. Today these helpers
/// expose only <c>traceId</c> — the opaque correlation token described on
/// <c>DeRecMessage.traceId</c> — but this class is the natural home for any
/// future envelope-level utilities.
/// </summary>
public static class Envelope
{
    /// <summary>
    /// Overwrite <c>traceId</c> on an already-produced envelope and return the
    /// re-encoded bytes.
    /// </summary>
    /// <remarks>
    /// Useful for callers using primitives directly: the
    /// <c>produce_*_request_message</c> family emits envelopes with
    /// <c>traceId = 0</c>, so callers who want correlation produce + then call
    /// this. The orchestrator does this automatically end-to-end.
    /// </remarks>
    /// <param name="envelope">Wire bytes of an existing <c>DeRecMessage</c> envelope.</param>
    /// <param name="traceId">Correlation token to write into the envelope.</param>
    /// <returns>Re-encoded envelope bytes with <c>traceId</c> overwritten.</returns>
    /// <exception cref="DeRecException">Thrown if the envelope cannot be decoded.</exception>
    public static byte[] ApplyTraceId(byte[] envelope, ulong traceId)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        Native.Envelope.ApplyTraceIdResult nativeResult =
            Native.Envelope.apply_trace_id_to_envelope(
                envelope,
                (UIntPtr)envelope.Length,
                traceId
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Error);
            return Utils.CopyBuffer(nativeResult.WireBytes);
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.WireBytes);
        }
    }

    /// <summary>
    /// Read <c>traceId</c> off an envelope without touching the encrypted
    /// inner payload. Pair with <see cref="ApplyTraceId(byte[], ulong)"/> for
    /// primitive-level request/response correlation.
    /// </summary>
    /// <param name="envelope">Wire bytes of a <c>DeRecMessage</c> envelope.</param>
    /// <returns>
    /// The trace id read from the envelope. Zero if the sender did not set
    /// one — the protobuf default is indistinguishable from an explicit zero.
    /// </returns>
    /// <exception cref="DeRecException">Thrown if the envelope cannot be decoded.</exception>
    public static ulong ReadTraceId(byte[] envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        Native.Envelope.ReadTraceIdResult nativeResult =
            Native.Envelope.read_trace_id_from_envelope(
                envelope,
                (UIntPtr)envelope.Length
            );

        Utils.ThrowIfError(nativeResult.Error);
        return nativeResult.TraceId;
    }

    /// <summary>
    /// Convenience overload of <see cref="ApplyTraceId(byte[], ulong)"/> that
    /// accepts and returns a typed <see cref="DeRecMessage"/>.
    /// </summary>
    public static DeRecMessage ApplyTraceId(DeRecMessage envelope, ulong traceId)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        byte[] stamped = ApplyTraceId(envelope.ToProtoBytes(), traceId);
        return DeRecMessage.FromProtoBytes(stamped);
    }

    /// <summary>
    /// Convenience overload of <see cref="ReadTraceId(byte[])"/> that accepts
    /// a typed <see cref="DeRecMessage"/>.
    /// </summary>
    public static ulong ReadTraceId(DeRecMessage envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        return ReadTraceId(envelope.ToProtoBytes());
    }
}
