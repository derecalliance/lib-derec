// SPDX-License-Identifier: Apache-2.0
// In-memory store + recording transport helpers used by the smoke
// tests. Lives here (not in the published `DeRec.Library` package) so
// the library surface stays free of test-only types.

using System;
using System.Collections.Generic;
using System.Linq;

using DeRec.Library.Orchestrator;

namespace DeRec.Bindings.Smoke;

internal sealed class InMemoryChannelStore : IChannelStore
{
    private readonly Dictionary<(ulong, ulong), Channel> _channels = new();
    private readonly Dictionary<(ulong, ulong), HashSet<ulong>> _links = new();

    public Channel? Load(ulong secretId, ulong channelId) =>
        _channels.TryGetValue((secretId, channelId), out var c) ? c : null;

    public void Save(ulong secretId, Channel channel) =>
        _channels[(secretId, channel.Id)] = channel;

    public bool Remove(ulong secretId, ulong channelId) =>
        _channels.Remove((secretId, channelId));

    public IEnumerable<ulong> ListChannelIds(ulong secretId) =>
        _channels.Keys.Where(k => k.Item1 == secretId).Select(k => k.Item2);

    public void LinkChannel(ulong secretId, ulong a, ulong b)
    {
        if (a == b) return;
        var ka = (secretId, a);
        var kb = (secretId, b);
        if (!_links.TryGetValue(ka, out var sa)) { sa = new HashSet<ulong>(); _links[ka] = sa; }
        if (!_links.TryGetValue(kb, out var sb)) { sb = new HashSet<ulong>(); _links[kb] = sb; }
        sa.Add(b);
        sb.Add(a);
    }

    public IEnumerable<ulong> LinkedChannels(ulong secretId, ulong channelId)
    {
        var visited = new HashSet<ulong>();
        var queue = new Queue<ulong>();
        queue.Enqueue(channelId);
        while (queue.Count > 0)
        {
            var curr = queue.Dequeue();
            if (!visited.Add(curr)) continue;
            if (_links.TryGetValue((secretId, curr), out var nbrs))
            {
                foreach (var n in nbrs)
                    if (!visited.Contains(n)) queue.Enqueue(n);
            }
        }
        return visited;
    }
}

internal sealed class InMemorySecretStore : ISecretStore
{
    private readonly Dictionary<(ulong, ulong, SecretKind), SecretValue> _data = new();

    public SecretValue? Load(ulong secretId, ulong channelId, SecretKind kind) =>
        _data.TryGetValue((secretId, channelId, kind), out var v) ? v : null;

    public void Save(ulong secretId, ulong channelId, SecretValue value) =>
        _data[(secretId, channelId, value.Kind)] = value;

    public void Remove(ulong secretId, ulong channelId, SecretKind kind) =>
        _data.Remove((secretId, channelId, kind));
}

/// <summary>
/// Keyed by <c>(secretId, channelId, version)</c>. Tracks an optional
/// per-<c>secretId</c> <c>OwnerVersion</c> surfaced via
/// <see cref="LatestVersion"/>.
/// </summary>
internal sealed class InMemoryShareStore : IShareStore
{
    private readonly Dictionary<(ulong, ulong, uint), Share> _data = new();
    private readonly Dictionary<ulong, uint> _ownerVersions = new();

    public IEnumerable<Share> Load(ulong secretId, ulong channelId, uint[] versions)
    {
        var filter = versions.Length == 0 ? null : new HashSet<uint>(versions);
        return _data
            .Where(kv => kv.Key.Item1 == secretId && kv.Key.Item2 == channelId &&
                          (filter is null || filter.Contains(kv.Key.Item3)))
            .Select(kv => kv.Value)
            .ToArray();
    }

    public IEnumerable<Share> LoadMany(ulong secretId, ulong[] channelIds, uint[] versions)
    {
        var cset = new HashSet<ulong>(channelIds);
        var filter = versions.Length == 0 ? null : new HashSet<uint>(versions);
        return _data
            .Where(kv => kv.Key.Item1 == secretId && cset.Contains(kv.Key.Item2) &&
                          (filter is null || filter.Contains(kv.Key.Item3)))
            .Select(kv => kv.Value)
            .ToArray();
    }

    public IEnumerable<Share> LoadAll(ulong secretId, ulong[] channelIds)
    {
        var cset = new HashSet<ulong>(channelIds);
        return _data
            .Where(kv => kv.Key.Item1 == secretId && cset.Contains(kv.Key.Item2))
            .Select(kv => kv.Value)
            .ToArray();
    }

    public uint? LatestVersion(ulong secretId) =>
        _ownerVersions.TryGetValue(secretId, out var v) ? v : null;

    public void Save(ulong secretId, ulong channelId, Share share)
    {
        _data[(secretId, channelId, share.Version)] = share;
    }

    public void RemoveChannel(ulong secretId, ulong channelId)
    {
        var keys = _data.Keys
            .Where(k => k.Item1 == secretId && k.Item2 == channelId)
            .ToList();
        foreach (var k in keys) _data.Remove(k);
    }

    public void SetOwnerVersion(ulong secretId, uint version) =>
        _ownerVersions[secretId] = version;
}

/// <summary>
/// Keyed by <c>secretId</c>. Holds at most one
/// <see cref="UserSecrets"/> per id — the most recent
/// <c>start(ProtectSecret)</c> snapshot.
/// </summary>
internal sealed class InMemoryUserSecretStore : IUserSecretStore
{
    private readonly Dictionary<ulong, UserSecrets> _data = new();

    public UserSecrets? LoadLatest(ulong secretId) =>
        _data.TryGetValue(secretId, out var v) ? v : null;

    public void SaveLatest(ulong secretId, UserSecrets value) =>
        _data[secretId] = value;

    public void Remove(ulong secretId) => _data.Remove(secretId);
}

/// <summary>
/// Keyed by <c>(secretId, StateKey)</c>. Holds the full
/// <see cref="StateItem"/> payload — same load-modify-save contract as
/// the Rust-side in-memory implementation.
/// </summary>
internal sealed class InMemoryStateStore : IStateStore
{
    private readonly Dictionary<(ulong, StateKey), StateItem> _data = new();

    public void Save(ulong secretId, StateItem item) =>
        _data[(secretId, item.Key())] = item;

    public StateItem? Load(ulong secretId, StateKey key) =>
        _data.TryGetValue((secretId, key), out var v) ? v : null;

    public bool Remove(ulong secretId, StateKey key) =>
        _data.Remove((secretId, key));

    public IEnumerable<StateItem> LoadAll(ulong secretId, StateKind kind) =>
        _data
            .Where(kv => kv.Key.Item1 == secretId && kv.Key.Item2.Kind == kind)
            .Select(kv => kv.Value)
            .ToArray();
}

/// <summary>
/// Captures every outbound message in <see cref="Outbox"/> so tests can
/// hand-pump envelopes to the peer's
/// <see cref="DeRec.Library.Orchestrator.DeRecProtocol.ProcessAsync"/>.
/// </summary>
internal sealed class RecordingTransport : ITransport
{
    public readonly List<(string Uri, int Protocol, byte[] Bytes)> Outbox = new();

    public void Send(string uri, int protocol, byte[] message) =>
        Outbox.Add((uri, protocol, message));

    public List<(string Uri, int Protocol, byte[] Bytes)> DrainAll()
    {
        var copy = new List<(string, int, byte[])>(Outbox);
        Outbox.Clear();
        return copy;
    }

    public byte[] DrainOne()
    {
        if (Outbox.Count != 1)
            throw new InvalidOperationException(
                $"expected exactly one outbound message, got {Outbox.Count}");
        var msg = Outbox[0].Bytes;
        Outbox.Clear();
        return msg;
    }
}
