// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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
    Channel? Load(ulong secretId, ulong channelId);
    void Save(ulong secretId, Channel channel);
    bool Remove(ulong secretId, ulong channelId);
    IEnumerable<ulong> ListChannelIds(ulong secretId);
    void LinkChannel(ulong secretId, ulong a, ulong b);
    IEnumerable<ulong> LinkedChannels(ulong secretId, ulong channelId);
}

/// <summary>
/// Secret-record persistence. Same per-call-isolation contract as
/// <see cref="IChannelStore"/>.
/// </summary>
public interface ISecretStore
{
    SecretValue? Load(ulong secretId, ulong channelId, SecretKind kind);
    void Save(ulong secretId, ulong channelId, SecretValue value);
    void Remove(ulong secretId, ulong channelId, SecretKind kind);
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
    /// Shares for a single channel within <paramref name="secretId"/>.
    /// Pass an empty <paramref name="versions"/> array for all versions.
    /// </summary>
    IEnumerable<Share> Load(ulong secretId, ulong channelId, uint[] versions);
    /// <summary>
    /// Shares across several channels within <paramref name="secretId"/>.
    /// </summary>
    IEnumerable<Share> LoadMany(ulong secretId, ulong[] channelIds, uint[] versions);
    /// <summary>
    /// Every share stored under <paramref name="secretId"/> across the
    /// given channels (used by Discovery for this secret).
    /// </summary>
    IEnumerable<Share> LoadAll(ulong secretId, ulong[] channelIds);
    /// <summary>
    /// Highest version stored for <paramref name="secretId"/>, or
    /// <c>null</c> if no shares exist yet for this secret.
    /// </summary>
    uint? LatestVersion(ulong secretId);
    void Save(ulong secretId, ulong channelId, Share share);
    void RemoveChannel(ulong secretId, ulong channelId);
}

/// <summary>
/// One user-secret entry inside the secret. Wire-equivalent to the Rust
/// <c>UserSecret</c> — <see cref="Id"/> is an app-defined identifier,
/// <see cref="Name"/> is a human-readable label, <see cref="Data"/> is
/// the raw bytes.
/// </summary>
public sealed record UserSecretEntry(byte[] Id, string Name, byte[] Data);

/// <summary>
/// Snapshot of the user-facing secret contents written every time the
/// application calls <c>start(FlowKind.ProtectSecret)</c>. The
/// pair-completion auto-publish hook reads it back so freshly-paired
/// peers receive the current secret without an explicit re-publish.
/// </summary>
public sealed record UserSecrets(uint Version, UserSecretEntry[] Secrets, string? Description);

/// <summary>
/// Persistence for the user-facing secret contents, keyed by
/// <c>secret_id</c>. One <c>secret_id</c> maps to at most one stored
/// <see cref="UserSecrets"/> entry — the most recent snapshot.
/// </summary>
public interface IUserSecretStore
{
    /// <summary>
    /// Return the latest snapshot for <paramref name="secretId"/>, or
    /// <c>null</c> if the application has never published for this id
    /// on this instance.
    /// </summary>
    UserSecrets? LoadLatest(ulong secretId);
    /// <summary>
    /// Overwrite the snapshot for <paramref name="secretId"/>.
    /// </summary>
    void SaveLatest(ulong secretId, UserSecrets value);
    /// <summary>
    /// Drop the snapshot for <paramref name="secretId"/>. Idempotent.
    /// </summary>
    void Remove(ulong secretId);
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

/// <summary>
/// Tag identifying which category of in-flight orchestrator state a
/// <see cref="StateItem"/> belongs to. Numeric values must match the
/// Rust-side <c>StateKind</c>.
/// </summary>
public enum StateKind : uint
{
    /// <summary>Outstanding verify-share challenges, one per channel.</summary>
    PendingVerification = 0,
    /// <summary>Recovery accumulator, one per (secretId, version).</summary>
    PendingRecovery = 1,
    /// <summary>Outstanding unpair acknowledgements, one per channel.</summary>
    PendingUnpair = 2,
    /// <summary>Active sharing round, at most one per secretId.</summary>
    SharingRound = 3,
}

/// <summary>
/// Secondary-key selector for one row inside a <see cref="StateKind"/>
/// under a <c>secretId</c>. Which field is populated is determined by
/// <see cref="Kind"/>.
/// </summary>
/// <param name="Kind">Row category.</param>
/// <param name="ChannelId">Set for <see cref="StateKind.PendingVerification"/> and <see cref="StateKind.PendingUnpair"/>.</param>
/// <param name="Version">Set for <see cref="StateKind.PendingRecovery"/>.</param>
public sealed record StateKey(StateKind Kind, ulong? ChannelId, uint? Version)
{
    public static StateKey PendingVerification(ulong channelId) =>
        new(StateKind.PendingVerification, channelId, null);
    public static StateKey PendingRecovery(uint version) =>
        new(StateKind.PendingRecovery, null, version);
    public static StateKey PendingUnpair(ulong channelId) =>
        new(StateKind.PendingUnpair, channelId, null);
    public static StateKey SharingRound() =>
        new(StateKind.SharingRound, null, null);
}

/// <summary>
/// Payload of one row in the state store. Which fields are populated
/// is determined by <see cref="Kind"/> — the FFI bridge validates and
/// normalises the JSON wire-form.
/// </summary>
/// <param name="Kind">Row category.</param>
/// <param name="ChannelId">Set for <see cref="StateKind.PendingVerification"/> and <see cref="StateKind.PendingUnpair"/>.</param>
/// <param name="Version">Set for <see cref="StateKind.PendingRecovery"/> and <see cref="StateKind.SharingRound"/>.</param>
/// <param name="StartedAt">Unix seconds when the operation was initiated (for <see cref="StateKind.PendingUnpair"/> and <see cref="StateKind.SharingRound"/>).</param>
/// <param name="Bytes">
/// Prost-encoded <c>VerifyShareRequestMessage</c> for
/// <see cref="StateKind.PendingVerification"/>; otherwise null.
/// </param>
/// <param name="Shares">
/// Prost-encoded <c>GetShareResponseMessage</c> blobs, one per
/// received share, for <see cref="StateKind.PendingRecovery"/>;
/// otherwise null.
/// </param>
/// <param name="Pending">Channel-id set of helpers yet to respond (only for <see cref="StateKind.SharingRound"/>).</param>
/// <param name="Confirmed">Channel-id set of helpers that confirmed storage (only for <see cref="StateKind.SharingRound"/>).</param>
/// <param name="Failed">Channel-id set of helpers that rejected or timed out (only for <see cref="StateKind.SharingRound"/>).</param>
public sealed record StateItem(
    StateKind Kind,
    ulong? ChannelId,
    uint? Version,
    ulong? StartedAt,
    byte[]? Bytes,
    byte[][]? Shares,
    ulong[]? Pending = null,
    ulong[]? Confirmed = null,
    ulong[]? Failed = null)
{
    public StateKey Key() => Kind switch
    {
        StateKind.PendingVerification => StateKey.PendingVerification(
            ChannelId ?? throw new InvalidOperationException("PendingVerification requires ChannelId")),
        StateKind.PendingRecovery => StateKey.PendingRecovery(
            Version ?? throw new InvalidOperationException("PendingRecovery requires Version")),
        StateKind.PendingUnpair => StateKey.PendingUnpair(
            ChannelId ?? throw new InvalidOperationException("PendingUnpair requires ChannelId")),
        StateKind.SharingRound => StateKey.SharingRound(),
        _ => throw new InvalidOperationException($"unknown StateKind: {Kind}"),
    };

    public static StateItem PendingVerification(ulong channelId, byte[] requestBytes) =>
        new(StateKind.PendingVerification, channelId, null, null, requestBytes, null);
    public static StateItem PendingRecovery(uint version, byte[][] shares) =>
        new(StateKind.PendingRecovery, null, version, null, null, shares);
    public static StateItem PendingUnpair(ulong channelId, ulong startedAt) =>
        new(StateKind.PendingUnpair, channelId, null, startedAt, null, null);
    public static StateItem SharingRound(
        uint version,
        ulong[] pending,
        ulong[] confirmed,
        ulong[] failed,
        ulong startedAt) =>
        new(StateKind.SharingRound, null, version, startedAt, null, null, pending, confirmed, failed);
}

/// <summary>
/// In-flight orchestrator state persistence. Same per-call-isolation
/// contract as <see cref="IChannelStore"/>. Backends are treated as
/// full-replacement upsert stores — accumulator-style state
/// (<see cref="StateKind.PendingRecovery"/> and
/// <see cref="StateKind.SharingRound"/>) grows via load-modify-save
/// cycles from the library.
/// </summary>
public interface IStateStore
{
    /// <summary>
    /// Insert or full-replace the row at <c>(secretId, item.Key())</c>.
    /// Idempotent.
    /// </summary>
    void Save(ulong secretId, StateItem item);

    /// <summary>
    /// Read the row at <c>(secretId, key)</c>. Return <c>null</c> when
    /// no row exists.
    /// </summary>
    StateItem? Load(ulong secretId, StateKey key);

    /// <summary>
    /// Remove the row at <c>(secretId, key)</c>. Returns <c>true</c> iff
    /// a row was actually removed. Idempotent — removing a missing
    /// entry returns <c>false</c>, not an error.
    /// </summary>
    bool Remove(ulong secretId, StateKey key);

    /// <summary>
    /// Return every item of the given <paramref name="kind"/> under this
    /// <paramref name="secretId"/>.
    /// </summary>
    IEnumerable<StateItem> LoadAll(ulong secretId, StateKind kind);
}

