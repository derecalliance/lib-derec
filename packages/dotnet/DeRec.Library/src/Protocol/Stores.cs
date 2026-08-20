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

    /// <summary>
    /// A replica-group member that has been told to leave and is awaiting
    /// the roster version that completes its removal. Never set on a helper
    /// channel.
    /// </summary>
    Unpairing,
}

/// <summary>
/// A member's role within a replica group.
/// </summary>
/// <remarks>
/// Exactly one member of a group is the <c>Source</c>. This is a property of
/// <em>membership</em>, not of a channel: all members share one channel, so
/// the channel cannot carry it. The value is absolute — every member records
/// the same role for a given peer, regardless of who is reading.
/// </remarks>
public enum ReplicaRole
{
    Source,
    Destination,
}

/// <summary>
/// A channel to a single helper, or to the owner from a helper's side.
/// </summary>
/// <remarks>
/// Mirrors the Rust-side <c>crate::protocol::types::HelperChannel</c> shape
/// 1:1. Keyed by <c>(secretId, channelId)</c>.
/// </remarks>
/// <param name="ChannelId">Channel identifier; opaque on this side.</param>
/// <param name="Transport">The peer's transport endpoint.</param>
/// <param name="CommunicationInfo">App-level identity metadata for the peer.</param>
/// <param name="Status">Lifecycle state (<see cref="ChannelStatus"/>).</param>
/// <param name="CreatedAt">Unix timestamp (seconds) when the channel was created.</param>
/// <param name="PeerRole">
/// The <em>peer's</em> role on the channel, fixed at pairing time. A
/// channel row describes the participant on the other end, so a
/// helper-pairing held by an Owner carries <c>Helper</c> here, and the
/// Helper's own row for the same channel carries <c>Owner</c>.
/// </param>
public sealed record HelperChannel(
    ulong ChannelId,
    TransportProtocol Transport,
    Dictionary<string, string> CommunicationInfo,
    ChannelStatus Status,
    ulong CreatedAt,
    Pairing.SenderKind PeerRole);

/// <summary>
/// One member of a replica group, including this device itself.
/// </summary>
/// <remarks>
/// Mirrors the Rust-side <c>crate::protocol::types::ReplicaMember</c> shape
/// 1:1. Keyed by <c>(secretId, replicaId)</c>: every member shares one
/// <c>ChannelId</c>, so the channel cannot be the key. Storing this device's
/// own row is what makes the roster reconstructible from stores alone.
/// </remarks>
/// <param name="ChannelId">The group channel. Identical for every member.</param>
/// <param name="ReplicaId">This member's identity — the primary key within the group.</param>
/// <param name="Transport">This member's transport endpoint.</param>
/// <param name="CommunicationInfo">App-level identity metadata for the member.</param>
/// <param name="Role">This member's role (<see cref="ReplicaRole"/>).</param>
/// <param name="Status">Lifecycle state (<see cref="ChannelStatus"/>).</param>
/// <param name="CreatedAt">Unix timestamp (seconds) when the row was created.</param>
public sealed record ReplicaMember(
    ulong ChannelId,
    ulong ReplicaId,
    TransportProtocol Transport,
    Dictionary<string, string> CommunicationInfo,
    ReplicaRole Role,
    ChannelStatus Status,
    ulong CreatedAt);

/// <summary>
/// A record held by <see cref="IChannelStore"/>: either a helper channel or
/// one replica-group member. Exactly one of the two properties is non-null.
/// </summary>
public sealed record ChannelRecord(HelperChannel? Helper, ReplicaMember? Replica)
{
    public static ChannelRecord Of(HelperChannel helper) => new(helper, null);
    public static ChannelRecord Of(ReplicaMember member) => new(null, member);

    /// <summary>The channel this record names, whichever variant it is.</summary>
    public ulong ChannelId => Helper?.ChannelId ?? Replica?.ChannelId
        ?? throw new InvalidOperationException("ChannelRecord holds neither variant");

    /// <summary>
    /// The replica id this record is keyed by, or <c>0</c> for a helper
    /// channel — the value the Rust side reserves as "absent".
    /// </summary>
    public ulong ReplicaId => Replica?.ReplicaId ?? 0;

    /// <summary>Lifecycle state, whichever variant it is.</summary>
    public ChannelStatus Status => Helper?.Status ?? Replica?.Status
        ?? throw new InvalidOperationException("ChannelRecord holds neither variant");
}

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
/// <remarks>
/// A record is addressed by <c>(channelId, replicaId)</c>. A <c>replicaId</c>
/// of <c>0</c> — the value the protocol reserves as "absent" — addresses the
/// helper channel at <c>channelId</c>.
/// <para>
/// Any other value addresses that member of the replica group, and the member
/// is keyed by <b><c>replicaId</c> alone</b>. The accompanying
/// <c>channelId</c> is context, not part of the key: a member moves between
/// channels during an admission handover while remaining the same member, and
/// a lookup that required both to match would miss it exactly when the move
/// needs to be observed. Keep two maps — helpers by <c>channelId</c>, members
/// by <c>replicaId</c> — not one keyed by the pair.
/// </para>
/// </remarks>
public interface IChannelStore
{
    ChannelRecord? Load(ulong secretId, ulong channelId, ulong replicaId);
    void Save(ulong secretId, ChannelRecord record);
    bool Remove(ulong secretId, ulong channelId, ulong replicaId);
    IEnumerable<HelperChannel> ListHelpers(ulong secretId);

    /// <summary>
    /// Every replica-group member stored under <paramref name="secretId"/>,
    /// including this device's own row.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The order is significant in exactly one situation. A group has one
    /// member holding the <c>Source</c> role; when it is removed, the protocol
    /// promotes the first element of this sequence that is neither the
    /// departing member nor itself leaving. Ordering this sequence is
    /// therefore how an application chooses its succession policy. The choice
    /// is read once, on the single device running the removal, and is then
    /// published in the roster, so implementations on different devices need
    /// not agree on order. Nothing else consults it.
    /// </para>
    /// <para>
    /// Returning an arbitrary order is correct and simply delegates the choice
    /// to the storage — note that a SQL <c>SELECT</c> without <c>ORDER BY</c>
    /// and <c>Dictionary</c> enumeration are both arbitrary. Order explicitly
    /// to make succession predictable.
    /// </para>
    /// </remarks>
    IEnumerable<ReplicaMember> ListReplicas(ulong secretId);
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
/// <remarks>
/// <para>
/// This is a <b>mailbox</b>, not a request/response channel: every peer has
/// an address, and a reply is posted to that address rather than returned
/// from <c>ProcessAsync</c>. Where both sides are reachable services, a
/// one-way push is all that is needed.
/// </para>
/// <para>
/// A peer that cannot be addressed — a phone, a browser, anything behind NAT
/// — breaks that silently: the reply is handed to <c>Send</c>, goes nowhere,
/// and nothing reports an error. Such a service must answer on the connection
/// the request arrived on, by building the protocol per request with an
/// <c>ITransport</c> that collects into a buffer instead of sending, then
/// returning the collected message whose trace id matches the inbound
/// envelope's (<see cref="DeRec.Library.Envelope.ReadTraceId(byte[])"/>).
/// One call can emit several messages, so the rest of the buffer is genuine
/// fan-out and still has to be delivered. See "Serving DeRec over
/// request/response transports" in the Rust SDK README for the full pattern.
/// </para>
/// </remarks>
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
    /// <summary>
    /// Active replica catch-up, at most one row per <c>secretId</c>. Holds
    /// the versions members have reported so far.
    /// </summary>
    PendingSyncCheck = 4,
}

/// <summary>
/// Secondary-key selector for one row inside a <see cref="StateKind"/>
/// under a <c>secretId</c>. Which field is populated is determined by
/// <see cref="Kind"/>.
/// </summary>
/// <param name="Kind">Row category.</param>
/// <param name="Kind">Row category.</param>
/// <param name="ChannelId">Set for <see cref="StateKind.PendingVerification"/> and <see cref="StateKind.PendingUnpair"/>.</param>
/// <param name="SecretId">
/// The secret being recovered, set for <see cref="StateKind.PendingRecovery"/>.
/// Not necessarily the <c>secretId</c> partitioning the store: a recovering
/// device runs an ephemeral instance whose own id owns the partition while
/// the target belongs to the wire.
/// </param>
/// <param name="Version">Set for <see cref="StateKind.PendingRecovery"/>.</param>
public sealed record StateKey(StateKind Kind, ulong? ChannelId, ulong? SecretId, uint? Version)
{
    public static StateKey PendingVerification(ulong channelId) =>
        new(StateKind.PendingVerification, channelId, null, null);
    public static StateKey PendingRecovery(ulong secretId, uint version) =>
        new(StateKind.PendingRecovery, null, secretId, version);
    public static StateKey PendingUnpair(ulong channelId) =>
        new(StateKind.PendingUnpair, channelId, null, null);
    public static StateKey SharingRound() =>
        new(StateKind.SharingRound, null, null, null);
}

/// <summary>
/// Payload of one row in the state store. Which fields are populated
/// is determined by <see cref="Kind"/> — the FFI bridge validates and
/// normalises the JSON wire-form.
/// </summary>
/// <param name="Kind">Row category.</param>
/// <param name="ChannelId">Set for <see cref="StateKind.PendingVerification"/> and <see cref="StateKind.PendingUnpair"/>.</param>
/// <param name="SecretId">The secret being recovered, set for <see cref="StateKind.PendingRecovery"/>. See <see cref="StateKey"/>.</param>
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
/// <param name="PendingReplicas">
/// Replica-id set of group members yet to respond (only for
/// <see cref="StateKind.SharingRound"/>). The replica leg is keyed by
/// <c>replicaId</c>, not <c>channelId</c>: every member of a group answers on
/// the one shared channel, so a channel-keyed set would collapse them.
/// </param>
/// <param name="SyncedReplicas">Replica-id set of members that acknowledged.</param>
/// <param name="BehindReplicas">Replica-id set of members that refused, timed out, or were unreachable.</param>
public sealed record StateItem(
    StateKind Kind,
    ulong? ChannelId,
    ulong? SecretId,
    uint? Version,
    ulong? StartedAt,
    byte[]? Bytes,
    byte[][]? Shares,
    ulong[]? Pending = null,
    ulong[]? Confirmed = null,
    ulong[]? Failed = null,
    ulong[]? PendingReplicas = null,
    ulong[]? SyncedReplicas = null,
    ulong[]? BehindReplicas = null)
{
    public StateKey Key() => Kind switch
    {
        StateKind.PendingVerification => StateKey.PendingVerification(
            ChannelId ?? throw new InvalidOperationException("PendingVerification requires ChannelId")),
        StateKind.PendingRecovery => StateKey.PendingRecovery(
            SecretId ?? throw new InvalidOperationException("PendingRecovery requires SecretId"),
            Version ?? throw new InvalidOperationException("PendingRecovery requires Version")),
        StateKind.PendingUnpair => StateKey.PendingUnpair(
            ChannelId ?? throw new InvalidOperationException("PendingUnpair requires ChannelId")),
        StateKind.SharingRound => StateKey.SharingRound(),
        _ => throw new InvalidOperationException($"unknown StateKind: {Kind}"),
    };

    public static StateItem PendingVerification(ulong channelId, byte[] requestBytes) =>
        new(StateKind.PendingVerification, channelId, null, null, null, requestBytes, null);
    public static StateItem PendingRecovery(ulong secretId, uint version, byte[][] shares) =>
        new(StateKind.PendingRecovery, null, secretId, version, null, null, shares);
    public static StateItem PendingUnpair(ulong channelId, ulong startedAt) =>
        new(StateKind.PendingUnpair, channelId, null, null, startedAt, null, null);
    public static StateItem SharingRound(
        uint version,
        ulong[] pending,
        ulong[] confirmed,
        ulong[] failed,
        ulong startedAt,
        ulong[]? pendingReplicas = null,
        ulong[]? syncedReplicas = null,
        ulong[]? behindReplicas = null) =>
        new(StateKind.SharingRound, null, null, version, startedAt, null, null, pending, confirmed, failed,
            pendingReplicas ?? Array.Empty<ulong>(),
            syncedReplicas ?? Array.Empty<ulong>(),
            behindReplicas ?? Array.Empty<ulong>());
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

