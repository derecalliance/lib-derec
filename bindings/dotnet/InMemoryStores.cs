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
    private readonly Dictionary<ulong, Channel> _channels = new();
    private readonly Dictionary<ulong, HashSet<ulong>> _links = new();

    public Channel? Load(ulong channelId) =>
        _channels.TryGetValue(channelId, out var c) ? c : null;

    public void Save(Channel channel) => _channels[channel.Id] = channel;

    public bool Remove(ulong channelId) => _channels.Remove(channelId);

    public IEnumerable<ulong> ListChannelIds() => _channels.Keys;

    public void LinkChannel(ulong a, ulong b)
    {
        if (a == b) return;
        if (!_links.TryGetValue(a, out var sa)) { sa = new HashSet<ulong>(); _links[a] = sa; }
        if (!_links.TryGetValue(b, out var sb)) { sb = new HashSet<ulong>(); _links[b] = sb; }
        sa.Add(b);
        sb.Add(a);
    }

    public IEnumerable<ulong> LinkedChannels(ulong channelId)
    {
        var visited = new HashSet<ulong>();
        var queue = new Queue<ulong>();
        queue.Enqueue(channelId);
        while (queue.Count > 0)
        {
            var curr = queue.Dequeue();
            if (!visited.Add(curr)) continue;
            if (_links.TryGetValue(curr, out var nbrs))
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
    private readonly Dictionary<(ulong, SecretKind), SecretValue> _data = new();

    public SecretValue? Load(ulong channelId, SecretKind kind) =>
        _data.TryGetValue((channelId, kind), out var v) ? v : null;

    public void Save(ulong channelId, SecretValue value) =>
        _data[(channelId, value.Kind)] = value;

    public void Remove(ulong channelId, SecretKind kind) =>
        _data.Remove((channelId, kind));
}

/// <summary>
/// Keyed by <c>(channelId, secretId, version)</c>. Tracks an optional
/// <c>OwnerVersion</c> surfaced via <see cref="LatestVersion"/> so
/// ProtectSecret can find "the latest" without a per-call scan.
/// </summary>
internal sealed class InMemoryShareStore : IShareStore
{
    private readonly Dictionary<ulong, Dictionary<ulong, Dictionary<uint, Share>>> _data = new();
    private uint? _ownerVersion;

    public IEnumerable<Share> Load(ulong channelId, ulong secretId, uint[] versions)
    {
        if (!_data.TryGetValue(channelId, out var bySecret)) return Array.Empty<Share>();
        if (!bySecret.TryGetValue(secretId, out var byVersion)) return Array.Empty<Share>();
        if (versions.Length == 0) return byVersion.Values.ToArray();
        var filter = new HashSet<uint>(versions);
        return byVersion.Where(kv => filter.Contains(kv.Key)).Select(kv => kv.Value).ToArray();
    }

    public IEnumerable<Share> LoadMany(ulong[] channelIds, ulong secretId, uint[] versions)
    {
        var filter = versions.Length == 0 ? null : new HashSet<uint>(versions);
        var result = new List<Share>();
        foreach (var ch in channelIds)
        {
            if (!_data.TryGetValue(ch, out var bySecret)) continue;
            if (!bySecret.TryGetValue(secretId, out var byVersion)) continue;
            foreach (var (v, s) in byVersion)
            {
                if (filter is not null && !filter.Contains(v)) continue;
                result.Add(s);
            }
        }
        return result;
    }

    public IEnumerable<Share> LoadAll(ulong[] channelIds)
    {
        var result = new List<Share>();
        foreach (var ch in channelIds)
        {
            if (!_data.TryGetValue(ch, out var bySecret)) continue;
            foreach (var byVersion in bySecret.Values)
                foreach (var share in byVersion.Values)
                    result.Add(share);
        }
        return result;
    }

    public uint? LatestVersion() => _ownerVersion;

    public void Save(ulong channelId, Share share)
    {
        if (!_data.TryGetValue(channelId, out var bySecret))
        {
            bySecret = new();
            _data[channelId] = bySecret;
        }
        if (!bySecret.TryGetValue(share.SecretId, out var byVersion))
        {
            byVersion = new();
            bySecret[share.SecretId] = byVersion;
        }
        byVersion[share.Version] = share;
    }

    public void RemoveChannel(ulong channelId) => _data.Remove(channelId);

    public void SetOwnerVersion(uint version) => _ownerVersion = version;
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
