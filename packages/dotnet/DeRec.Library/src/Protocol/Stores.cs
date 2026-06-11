// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

using DeRec.Library.Primitives;

namespace DeRec.Library.Orchestrator;

/// <summary>
/// Lifecycle status of a paired channel.
/// </summary>
/// <remarks>
/// Replica channels start as <see cref="Pending"/> after pairing and
/// transition to <see cref="Paired"/> once fingerprint verification
/// succeeds. Helper / Owner channels are <see cref="Paired"/>
/// immediately after pairing. Names match the Rust-side
/// <c>ChannelStatus</c> variants verbatim — the bridge round-trips
/// them as strings on the FFI boundary.
/// </remarks>
public enum ChannelStatus
{
    Pending,
    Paired,
}

/// <summary>
/// Post-pairing peer record persisted in <see cref="IChannelStore"/>.
/// </summary>
/// <remarks>
/// Mirrors the Rust-side <c>crate::protocol::types::Channel</c> shape
/// 1:1. The FFI bridge translates between this typed form and the
/// snake_case JSON wire format internally; consumers only ever see
/// the strongly-typed values.
/// </remarks>
/// <param name="Id">Channel identifier; opaque on this side.</param>
/// <param name="Transport">The peer's transport endpoint.</param>
/// <param name="CommunicationInfo">App-level identity metadata for the peer.</param>
/// <param name="Status">Lifecycle state (<see cref="ChannelStatus"/>).</param>
/// <param name="CreatedAt">Unix timestamp (seconds) when the channel was created.</param>
/// <param name="Role">This node's role on the channel, fixed at pairing time.</param>
/// <param name="ReplicaId">Peer's replica identity (only set for replica roles).</param>
public sealed record Channel(
    ulong Id,
    TransportProtocol Transport,
    Dictionary<string, string> CommunicationInfo,
    ChannelStatus Status,
    ulong CreatedAt,
    Pairing.SenderKind Role,
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
/// Outbound message delivery — the protocol hands the application
/// the encoded envelope bytes plus the destination endpoint and the
/// application is responsible for shipping them over the wire.
/// </summary>
public interface ITransport
{
    void Send(string uri, int protocol, byte[] message);
}

