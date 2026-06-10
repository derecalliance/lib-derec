// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

using DeRec.Library.Primitives;

namespace DeRec.Library.Orchestrator;

/// <summary>
/// Post-pairing peer record persisted in <see cref="IChannelStore"/>.
/// Wire shape matches the JSON-on-the-FFI <c>ChannelRecord</c> consumed
/// by the Rust orchestrator.
/// </summary>
public sealed record Channel(
    ulong ChannelId,
    string TransportUri,
    int TransportProtocol,
    Dictionary<string, string> CommunicationInfo,
    string Status,
    ulong CreatedAt,
    int Role,
    ulong? ReplicaId);

/// <summary>
/// Kind selector for <see cref="ISecretStore"/>. Numeric values must
/// match the Rust-side <c>SecretKind</c>.
/// </summary>
public enum SecretKind : uint
{
    SharedKey = 0,
    PairingSecret = 1,
    PairingContact = 2,
}

/// <summary>
/// Opaque secret payload stored alongside a channel id and
/// <see cref="SecretKind"/>. The <c>Bytes</c> wire format depends on
/// kind — apps treat it as opaque.
/// </summary>
public sealed record SecretValue(SecretKind Kind, byte[] Bytes);

/// <summary>
/// Channel-record persistence for the protocol. Implementations MUST
/// be safe to read/write across multiple calls, but never see
/// overlapping calls (the protocol holds the store by <c>&amp;mut self</c>
/// on the Rust side, serialising access).
/// </summary>
public interface IChannelStore
{
    Channel? Load(ulong channelId);
    void Save(Channel channel);
    bool Remove(ulong channelId);
    IEnumerable<ulong> ListChannelIds();
    void LinkChannel(ulong a, ulong b);
    IEnumerable<ulong> LinkedChannels(ulong channelId);
}

/// <summary>
/// Secret-record persistence. Same per-call-isolation contract as
/// <see cref="IChannelStore"/>.
/// </summary>
public interface ISecretStore
{
    SecretValue? Load(ulong channelId, SecretKind kind);
    void Save(ulong channelId, SecretValue value);
    void Remove(ulong channelId, SecretKind kind);
}

/// <summary>
/// Stored share — opaque protobuf bytes keyed by
/// <c>(channel_id, secret_id, version)</c>. The byte format depends on
/// which side stored it (helper: <c>StoreShareRequestMessage</c>; owner:
/// <c>CommittedDeRecShare</c>); the store treats them as opaque.
/// </summary>
public sealed record Share(ulong SecretId, uint Version, byte[] Bytes);

/// <summary>
/// Share-record persistence. Same per-call-isolation contract as
/// <see cref="IChannelStore"/>. The orchestrator funnels every share
/// access through this interface — discovery/recovery/verification all
/// hit one of the <c>Load*</c> overloads.
/// </summary>
public interface IShareStore
{
    /// <summary>
    /// Shares for a single channel, scoped to one secret. Pass an
    /// empty <paramref name="versions"/> slice for all versions.
    /// </summary>
    IEnumerable<Share> Load(ulong channelId, ulong secretId, uint[] versions);
    /// <summary>
    /// Shares across several channels, scoped to one secret. Recovery
    /// resolves the linked-channel set via
    /// <see cref="IChannelStore.LinkedChannels"/> first, then calls this.
    /// </summary>
    IEnumerable<Share> LoadMany(ulong[] channelIds, ulong secretId, uint[] versions);
    /// <summary>
    /// Every share across the given channels — discovery only (no
    /// <c>secret_id</c> filter).
    /// </summary>
    IEnumerable<Share> LoadAll(ulong[] channelIds);
    /// <summary>
    /// Highest version stored anywhere, or <c>null</c> if empty.
    /// </summary>
    uint? LatestVersion();
    void Save(ulong channelId, Share share);
    void RemoveChannel(ulong channelId);
}

/// <summary>
/// Outbound message delivery. Stubbed for chunk 7a — wired up in 7b.
/// </summary>
public interface ITransport
{
    void Send(string uri, int protocol, byte[] message);
}

/// <summary>
/// In-memory <see cref="IChannelStore"/> for smoke tests. Not
/// thread-safe; the protocol serialises access.
/// </summary>
public sealed class InMemoryChannelStore : IChannelStore
{
    private readonly Dictionary<ulong, Channel> _channels = new();
    private readonly Dictionary<ulong, HashSet<ulong>> _links = new();

    public Channel? Load(ulong channelId) =>
        _channels.TryGetValue(channelId, out var c) ? c : null;

    public void Save(Channel channel) => _channels[channel.ChannelId] = channel;

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

/// <summary>In-memory <see cref="ISecretStore"/> for smoke tests.</summary>
public sealed class InMemorySecretStore : ISecretStore
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
/// In-memory <see cref="IShareStore"/> for smoke tests. Keyed by
/// <c>(channelId, secretId, version)</c> — same shape as the JS smoke's
/// <c>InMemoryShareStore</c>. Tracks an optional <c>OwnerVersion</c>
/// surfaced via <see cref="LatestVersion"/> so ProtectSecret can find
/// "the latest" without a per-call scan.
/// </summary>
public sealed class InMemoryShareStore : IShareStore
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

    /// <summary>
    /// Owner-side helper: set the "latest version" the protocol reports
    /// via <see cref="LatestVersion"/>. Apps using this store as a
    /// helper-side persistence keep the default <c>null</c>.
    /// </summary>
    public void SetOwnerVersion(uint version) => _ownerVersion = version;
}

/// <summary>
/// In-memory recording transport for smoke tests. Captures every
/// outbound message in <see cref="Outbox"/> so tests can hand-pump
/// envelopes to the peer's <see cref="DeRecProtocol.ProcessAsync"/>.
/// </summary>
public sealed class RecordingTransport : ITransport
{
    public readonly List<(string Uri, int Protocol, byte[] Bytes)> Outbox = new();

    public void Send(string uri, int protocol, byte[] message) =>
        Outbox.Add((uri, protocol, message));

    /// <summary>Drains and returns every queued message.</summary>
    public List<(string Uri, int Protocol, byte[] Bytes)> DrainAll()
    {
        var copy = new List<(string, int, byte[])>(Outbox);
        Outbox.Clear();
        return copy;
    }

    /// <summary>Drains exactly one message or throws.</summary>
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
