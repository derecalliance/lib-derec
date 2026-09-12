// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
// Covers the two ITransport adapters shipped so applications do not hand-write
// the send contract. Mirrors the Rust `protocol::transport_adapters` tests, the
// Go `protocol` adapter tests, and the React Native `transport-adapters` suite.

using System;
using System.Collections.Generic;
using DeRec.Library;
using DeRec.Library.Orchestrator;

namespace DeRec.Bindings.Smoke;

internal static class TransportAdapters
{
    private const string A = "https://a.example";
    private const string B = "https://b.example";
    private const string C = "https://c.example";

    /// <summary>
    /// Records every endpoint it was asked to dial, and refuses the ones named.
    /// </summary>
    private sealed class RecordingDialer : ISendOne
    {
        private readonly HashSet<string> _refuse;

        public RecordingDialer(params string[] refuse) => _refuse = new HashSet<string>(refuse);

        public List<string> Attempted { get; } = new();

        public void SendOne(TransportProtocol endpoint, byte[] message)
        {
            Attempted.Add(endpoint.Uri);
            if (_refuse.Contains(endpoint.Uri))
            {
                throw new InvalidOperationException($"refused {endpoint.Uri}");
            }
        }
    }

    private static IReadOnlyList<TransportProtocol> Endpoints(params string[] uris)
    {
        var list = new List<TransportProtocol>(uris.Length);
        foreach (string uri in uris)
        {
            list.Add(new TransportProtocol(uri));
        }
        return list;
    }

    private static void AssertAttempted(RecordingDialer dialer, params string[] expected)
    {
        if (dialer.Attempted.Count != expected.Length)
        {
            throw new InvalidOperationException(
                $"attempted {dialer.Attempted.Count} endpoint(s), expected {expected.Length}: "
                + string.Join(", ", dialer.Attempted));
        }
        for (int i = 0; i < expected.Length; i++)
        {
            if (dialer.Attempted[i] != expected[i])
            {
                throw new InvalidOperationException(
                    $"attempt {i} was {dialer.Attempted[i]}, expected {expected[i]}");
            }
        }
    }

    public static void RunAll()
    {
        Console.WriteLine("=== Transport adapters ===");

        // Delivering to every endpoint would send one authenticated message to
        // the same peer several times, so the first success ends the attempt.
        var dialer = new RecordingDialer();
        new SequentialFailover(dialer).Send(Endpoints(A, B), new byte[] { 1 });
        AssertAttempted(dialer, A);

        dialer = new RecordingDialer(A);
        new SequentialFailover(dialer).Send(Endpoints(A, B), new byte[] { 1 });
        AssertAttempted(dialer, A, B);

        // The order is the peer's and is not reinterpreted.
        dialer = new RecordingDialer(A);
        new SequentialFailover(dialer).Send(Endpoints(A, B, C), new byte[] { 1 });
        AssertAttempted(dialer, A, B);

        dialer = new RecordingDialer(A, B);
        try
        {
            new SequentialFailover(dialer).Send(Endpoints(A, B), new byte[] { 1 });
            throw new InvalidOperationException(
                "SequentialFailover must throw when no endpoint accepted the message");
        }
        catch (InvalidOperationException e) when (e.Message.StartsWith("refused", StringComparison.Ordinal))
        {
            // Expected: the last dialer failure propagates.
        }
        AssertAttempted(dialer, A, B);

        dialer = new RecordingDialer();
        new SingleEndpointTransport(dialer).Send(Endpoints(A, B), new byte[] { 1 });
        AssertAttempted(dialer, A);

        // The distinguishing property: where SequentialFailover would recover,
        // this reports the failure. That is the cost of choosing it.
        dialer = new RecordingDialer(A);
        try
        {
            new SingleEndpointTransport(dialer).Send(Endpoints(A, B), new byte[] { 1 });
            throw new InvalidOperationException(
                "SingleEndpointTransport must not fall back to the second endpoint");
        }
        catch (InvalidOperationException e) when (e.Message.StartsWith("refused", StringComparison.Ordinal))
        {
            // Expected.
        }
        AssertAttempted(dialer, A);

        Console.WriteLine("Transport adapters passed.");
    }
}
