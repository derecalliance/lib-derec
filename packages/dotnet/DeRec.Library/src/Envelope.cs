// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;

namespace DeRec.Library;

/// <summary>
/// Envelope-level helpers that operate on raw <c>DeRecMessage</c> wire bytes
/// without touching the encrypted inner payload.
///
/// The outer <c>DeRecMessage</c> envelope is plaintext, so a handful of
/// metadata fields can be read or rewritten in-place: <c>traceId</c>, the
/// opaque correlation token described on <c>DeRecMessage.traceId</c>, and the
/// message identity replay detection keys on.
/// </summary>
public static class Envelope
{
    /// <summary>
    /// Identify an envelope for replay and reflection detection.
    /// </summary>
    /// <remarks>
    /// Detecting a message delivered twice, or delivered back to its sender,
    /// is the application's job: keep the <see cref="MessageId.Id"/> of every
    /// envelope sent and of every envelope <c>ProcessAsync</c> accepted until
    /// <c>max(received or sent at, Timestamp) + InboundMessage</c>, keep the
    /// record across restarts, and drop an inbound envelope whose id is kept.
    /// The README has the full contract. The id is the same for every
    /// copy of one message, whatever its unauthenticated cleartext fields
    /// (sequence, trace id, protocol version) say, and different for every
    /// other message, so never key on a hash of the raw bytes instead.
    /// </remarks>
    /// <param name="envelope">Wire bytes of a <c>DeRecMessage</c> envelope.</param>
    /// <returns>The envelope's identity and send time.</returns>
    /// <exception cref="DeRecException">
    /// Thrown if the envelope cannot be decoded or carries no timestamp.
    /// </exception>
    public static MessageId ReadMessageId(byte[] envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        Native.Envelope.MessageIdResult nativeResult =
            Native.Envelope.message_id_from_envelope(
                envelope,
                (UIntPtr)envelope.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Error);
            return new MessageId(Utils.CopyBuffer(nativeResult.Id), nativeResult.Timestamp);
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.Id);
        }
    }

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

/// <summary>
/// The identity of one delivered message, read by
/// <see cref="Envelope.ReadMessageId(byte[])"/>.
/// </summary>
/// <param name="Id">SHA-256 of the envelope's encrypted <c>message</c> field (32 bytes).</param>
/// <param name="Timestamp">The envelope's send time, in seconds since the Unix epoch.</param>
public sealed record MessageId(byte[] Id, ulong Timestamp);
