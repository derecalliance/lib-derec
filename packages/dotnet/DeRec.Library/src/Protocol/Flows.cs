// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

using DeRec.Library.Primitives;

namespace DeRec.Library.Orchestrator;

/// <summary>
/// Numeric flow-kind discriminator passed to
/// <see cref="DeRecProtocol.StartAsync"/>. Values MUST match the
/// Rust-side constants in <c>library/src/interop/ffi/protocol/flow.rs</c>.
/// </summary>
public enum FlowKind : uint
{
    Pairing = 0,
    Discovery = 1,
    ProtectSecret = 2,
    VerifyShares = 3,
    RecoverSecret = 4,
    Unpair = 5,
    UpdateChannelInfo = 6,
    /// <summary>
    /// Ask the replica group whether this device is behind, and catch up if
    /// it is. Replica-only; takes no parameters.
    /// </summary>
    ReplicaDiscovery = 7,
    /// <summary>
    /// Remove a member from the replica group. Replica-only. Naming this
    /// device is a voluntary departure; naming another is an eviction.
    /// </summary>
    UnpairReplica = 8,
}

/// <summary>
/// Selects which channels a flow targets. Construct via the
/// <see cref="All"/>, <see cref="One"/>, or <see cref="Many"/> factory
/// members; the wire shape (<c>null</c>, decimal-string, or
/// string-array) is handled automatically by the JSON converter when
/// the value is attached to a flow params record. Mirrors the Target
/// convention used by every other DeRec SDK.
/// </summary>
[JsonConverter(typeof(TargetJsonConverter))]
public abstract record Target
{
    public static Target All { get; } = new AllTarget();
    public static Target One(ulong channelId) => new SingleTarget(channelId);
    public static Target Many(params ulong[] channelIds) => new ManyTarget(channelIds);

    internal sealed record AllTarget : Target;
    internal sealed record SingleTarget(ulong ChannelId) : Target;
    internal sealed record ManyTarget(ulong[] ChannelIds) : Target;
}

/// <summary>
/// Serializes a <see cref="Target"/> as the on-the-wire shape that
/// the Rust orchestrator expects: <c>null</c> for
/// <see cref="Target.All"/>, a decimal-string for
/// <see cref="Target.One"/>, and an array of decimal-strings for
/// <see cref="Target.Many"/>.
/// </summary>
public sealed class TargetJsonConverter : JsonConverter<Target?>
{
    public override Target? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        throw new NotSupportedException("Target is write-only on the SDK boundary.");
    }

    public override void Write(Utf8JsonWriter writer, Target? value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case null:
            case Target.AllTarget:
                writer.WriteNullValue();
                break;
            case Target.SingleTarget s:
                writer.WriteStringValue(s.ChannelId.ToString());
                break;
            case Target.ManyTarget m:
                writer.WriteStartArray();
                foreach (ulong id in m.ChannelIds)
                    writer.WriteStringValue(id.ToString());
                writer.WriteEndArray();
                break;
            default:
                throw new JsonException($"unknown Target variant: {value.GetType()}");
        }
    }
}

/// <summary>
/// Params for <see cref="FlowKind.Pairing"/>. Mirrors the Rust
/// <c>PairingParamsJson</c> wire shape.
/// </summary>
public sealed record PairingParams
{
    [JsonPropertyName("kind")]
    public required Pairing.SenderKind Kind { get; init; }

    /// <summary>prost-encoded <c>ContactMessage</c> bytes.</summary>
    [JsonPropertyName("contact")]
    public required byte[] Contact { get; init; }

    [JsonPropertyName("peer_communication_info")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? PeerCommunicationInfo { get; init; }
}

/// <summary>Params for <see cref="FlowKind.Discovery"/>.</summary>
public sealed record DiscoveryParams
{
    [JsonPropertyName("target")] public Target? Target { get; init; }
}

/// <summary>
/// Per-secret payload inside <see cref="ProtectSecretParams.Secrets"/>.
/// <see cref="Id"/> is an app-defined identifier; <see cref="Data"/> is
/// the raw bytes to distribute.
/// </summary>
public sealed record UserSecret
{
    [JsonPropertyName("id")] public required byte[] Id { get; init; }
    [JsonPropertyName("name")] public required string Name { get; init; }
    [JsonPropertyName("data")] public required byte[] Data { get; init; }
}

/// <summary>
/// Params for <see cref="FlowKind.ProtectSecret"/>.
///
/// The secret identifier comes from
/// <see cref="DeRecProtocol.SecretId"/> (set at construction) and the
/// target set is the protocol's full roster of paired Owner→Helper +
/// Source→ReplicaDestination channels — neither field is carried on the
/// flow params anymore.
/// </summary>
public sealed record ProtectSecretParams
{
    [JsonPropertyName("secrets")] public required UserSecret[] Secrets { get; init; }
    [JsonPropertyName("description")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Description { get; init; }
}

/// <summary>Params for <see cref="FlowKind.VerifyShares"/>.</summary>
public sealed record VerifySharesParams
{
    [JsonPropertyName("secret_id"), JsonNumberHandling(JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString)] public required ulong SecretId { get; init; }
    [JsonPropertyName("version")] public required uint Version { get; init; }
    [JsonPropertyName("target")] public Target? Target { get; init; }
}

/// <summary>Params for <see cref="FlowKind.RecoverSecret"/>.</summary>
public sealed record RecoverSecretParams
{
    [JsonPropertyName("secret_id"), JsonNumberHandling(JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString)] public required ulong SecretId { get; init; }
    [JsonPropertyName("version")] public required uint Version { get; init; }
}

/// <summary>Params for <see cref="FlowKind.Unpair"/>.</summary>
public sealed record UnpairParams
{
    [JsonPropertyName("channel_id"), JsonNumberHandling(JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString)] public required ulong ChannelId { get; init; }
    [JsonPropertyName("memo")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Memo { get; init; }
}

/// <summary>Params for <see cref="FlowKind.UpdateChannelInfo"/>.</summary>
public sealed record UpdateChannelInfoParams
{
    [JsonPropertyName("target")] public Target? Target { get; init; }
    [JsonPropertyName("communication_info")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? CommunicationInfo { get; init; }
    /// <summary>
    /// Every endpoint this node now serves, in its own preference order.
    /// Empty leaves the target(s)' stored set untouched.
    /// </summary>
    [JsonPropertyName("own_transports")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public IReadOnlyList<TransportProtocolDto>? OwnTransports { get; init; }

    public sealed record TransportProtocolDto
    {
        [JsonPropertyName("uri")] public required string Uri { get; init; }
        [JsonPropertyName("protocol")] public required int Protocol { get; init; }
    }
}

/// <summary>
/// Params for <see cref="FlowKind.ReplicaDiscovery"/>.
/// </summary>
/// <remarks>
/// The flow takes none: the group and this device's own version are both read
/// from the stores. Present so every flow kind has a params type and
/// <see cref="DeRecProtocol.StartAsync"/> reads uniformly at the call site.
/// </remarks>
public sealed record ReplicaDiscoveryParams;

/// <summary>
/// Params for <see cref="FlowKind.UnpairReplica"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ReplicaId"/> is the member's <c>replica_id</c>, as
/// <c>ReplicaPairedEvent.PeerReplicaId</c> hands it back. Naming no current
/// member is rejected, not silently ignored.
/// </para>
/// <para>
/// <b>Starting this flow removes nothing on its own</b> and emits no
/// <c>ReplicaRemovedEvent</c>. It tells every member and flags the target
/// locally; the removal completes only once the application publishes a
/// roster omitting that member — an ordinary
/// <see cref="FlowKind.ProtectSecret"/> — at which point
/// <c>ReplicaRemovedEvent</c> fires. A group with no secret to publish
/// therefore cannot complete a removal.
/// </para>
/// <para>
/// Any member may remove any member, the source included: a lost or stolen
/// source must be removable by the devices that remain, and the library checks
/// no role. Ask the user before starting this flow, above all when it names the
/// source. Removing the source promotes the first remaining member in the order
/// <c>IChannelStore.ListReplicas</c> returns. The removed member is not asked
/// and gets no event when told to leave: when a roster excluding it arrives it
/// drops its whole <c>secret_id</c> partition and emits
/// <see cref="SelfRemovedFromGroupEvent"/>. The secret survives on the
/// remaining members and the helpers.
/// </para>
/// </remarks>
public sealed record UnpairReplicaParams
{
    [JsonPropertyName("replica_id"), JsonNumberHandling(JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString)] public required ulong ReplicaId { get; init; }

    [JsonPropertyName("memo")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Memo { get; init; }
}

/// <summary>
/// Common parent for every <see cref="DeRecEvent"/> the orchestrator
/// can emit. Concrete variants are differentiated by their
/// <see cref="EventType"/> discriminator — produced by the
/// <see cref="DeRecEventConverter"/> based on the <c>"type"</c> field
/// in the wire JSON.
/// </summary>
[JsonConverter(typeof(DeRecEventConverter))]
public abstract record DeRecEvent
{
    /// <summary>Discriminator value matching the Rust <c>"type"</c> field.</summary>
    public abstract string EventType { get; }
}

/// <summary>
/// Fired by the orchestrator on both sides of a completed pair
/// handshake. <see cref="Kind"/> is the *peer's* role on the channel.
/// </summary>
public sealed record PairingCompletedEvent : DeRecEvent
{
    public override string EventType => "PairingCompleted";

    /// <summary>
    /// Long-term <c>channel_id</c> both peers atomically rotated to at the end
    /// of the handshake. All post-pairing traffic and library state keys on
    /// this value.
    /// </summary>
    public required ulong ChannelId { get; init; }

    /// <summary>
    /// Transient <c>channel_id</c> that traveled on the <c>ContactMessage</c>
    /// and the pairing envelopes. No longer resolves in library state after
    /// this event fires — provided so applications that persisted it can
    /// rekey their own records.
    /// </summary>
    public required ulong PairingChannelId { get; init; }
    public required Pairing.SenderKind Kind { get; init; }
    public Dictionary<string, string> PeerCommunicationInfo { get; init; } = new();
}

/// <summary>
/// Fired alongside <see cref="PairingCompletedEvent"/> on replica-mode
/// pairings. Carries the peer's <c>replica_id</c>.
/// </summary>
public sealed record ReplicaPairedEvent : DeRecEvent
{
    public override string EventType => "ReplicaPaired";

    public required ulong ChannelId { get; init; }
    public required ulong PeerReplicaId { get; init; }
}

/// <summary>
/// Surfaced for every inbound request that needs the app's explicit
/// consent before the orchestrator acts (responder side of Pairing,
/// PrePair, StoreShare, etc.). Pass <see cref="Action"/> verbatim to
/// <see cref="DeRecProtocol.AcceptAsync"/> or
/// <see cref="DeRecProtocol.RejectAsync"/>.
/// </summary>
public sealed record ActionRequiredEvent : DeRecEvent
{
    public override string EventType => "ActionRequired";

    public required ulong ChannelId { get; init; }

    /// <summary>Opaque PendingAction bytes — round-trip verbatim.</summary>
    public required byte[] Action { get; init; }

    /// <summary>Which request is awaiting consent; one of the
    /// <see cref="PendingActionKind"/> constants.</summary>
    public required string ActionKind { get; init; }

    /// <summary>Correlation token of the inbound request.
    /// Matches the peer's <c>*Started</c> event for the same round.</summary>
    public required ulong TraceId { get; init; }

    /// <summary>The peer's communication info (Pairing only; empty otherwise).</summary>
    public Dictionary<string, string> PeerCommunicationInfo { get; init; } = new();

    /// <summary>The peer's role from its pair request (Pairing only).</summary>
    public Pairing.SenderKind? SenderKind { get; init; }

    /// <summary>Share version (StoreShare, VerifyShare, GetShare).</summary>
    public uint? Version { get; init; }

    /// <summary>Description of the secret version (StoreShare only).</summary>
    public string? ShareDescription { get; init; }

    /// <summary>Secret identifier (StoreShare, VerifyShare,
    /// GetShare). On GetShare, with <see cref="Version"/>, it names the share
    /// being asked for.</summary>
    public ulong? ShareSecretId { get; init; }

    /// <summary>Length in bytes of the share the helper would store
    /// (StoreShare only) — what a size or quota decision is made on.</summary>
    public ulong? ShareSize { get; init; }

    /// <summary>The peer's memo (Unpair only).</summary>
    public string? UnpairMemo { get; init; }

    /// <summary>The communication info accepting would replace the stored map
    /// with (UpdateChannelInfo only). <c>null</c> leaves it unchanged; an
    /// empty map clears it.</summary>
    public Dictionary<string, string>? UpdatedCommunicationInfo { get; init; }

    /// <summary>The endpoints accepting would move the peer to
    /// (UpdateChannelInfo only). <c>null</c> leaves them unchanged.</summary>
    public IReadOnlyList<TransportProtocol>? UpdatedTransports { get; init; }
}

/// <summary>
/// The label vocabulary for <see cref="ActionRequiredEvent.ActionKind"/> and
/// <see cref="AutoAcceptedEvent.ActionKind"/>. Matches the Rust
/// <c>PendingActionKind</c> discriminants one-for-one.
/// </summary>
public static class PendingActionKind
{
    public const string Pairing = "Pairing";
    public const string PrePair = "PrePair";
    public const string StoreShare = "StoreShare";
    public const string VerifyShare = "VerifyShare";
    public const string Discovery = "Discovery";
    public const string GetShare = "GetShare";
    public const string Unpair = "Unpair";
    public const string UpdateChannelInfo = "UpdateChannelInfo";
}

public sealed record ShareStoredEvent : DeRecEvent
{
    public override string EventType => "ShareStored";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }
}

public sealed record ShareConfirmedEvent : DeRecEvent
{
    public override string EventType => "ShareConfirmed";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }
}

public sealed record ShareRejectedEvent : DeRecEvent
{
    public override string EventType => "ShareRejected";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }
    public required Org.Derecalliance.Derec.Protobuf.StatusEnum Status { get; init; }
    public required string Memo { get; init; }
}

/// <summary>
/// A publishing round finished — every targeted helper confirmed, rejected,
/// or timed out.
/// </summary>
/// <remarks>
/// <para>
/// <b>A mixed round waits for the replica leg.</b> The counts here describe
/// helpers only and are known the instant the helpers answer, but the event is
/// withheld until every replica member has also acknowledged, refused, or
/// timed out. One unreachable member therefore delays it by up to the
/// configured timeout, which is easy to mistake for a hang. Nothing is lost —
/// the round always terminates, and a silent member is reported in
/// <c>ReplicaSyncCompleteEvent.Behind</c> rather than failing it.
/// </para>
/// <para>
/// Drive per-helper progress from <c>ShareConfirmedEvent</c> instead: those
/// land as each helper answers, with no cross-population wait. A helpers-only
/// round is unaffected.
/// </para>
/// </remarks>
public sealed record SharingCompleteEvent : DeRecEvent
{
    public override string EventType => "SharingComplete";
    public required uint Version { get; init; }
    public required uint ConfirmedCount { get; init; }
    public required uint FailedCount { get; init; }
    public required bool ThresholdMet { get; init; }
}

public sealed record ShareVerifiedEvent : DeRecEvent
{
    public override string EventType => "ShareVerified";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }
}

/// <summary>
/// A helper refused a verification challenge: its response carried a non-OK
/// <c>Status</c> instead of a proof. The challenge is spent; a new
/// <c>VerifyShares</c> round challenges the helper again.
/// </summary>
public sealed record ShareVerifyRejectedEvent : DeRecEvent
{
    public override string EventType => "ShareVerifyRejected";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }
    public required Org.Derecalliance.Derec.Protobuf.StatusEnum Status { get; init; }
    public required string Memo { get; init; }
}

public sealed record DiscoveredSecretVersion(uint Version, string Description);

public sealed record DiscoveredSecret(ulong SecretId, IReadOnlyList<DiscoveredSecretVersion> Versions);

public sealed record SecretsDiscoveredEvent : DeRecEvent
{
    public override string EventType => "SecretsDiscovered";
    public required ulong ChannelId { get; init; }
    public required IReadOnlyList<DiscoveredSecret> Secrets { get; init; }
}

public sealed record RecoveryShareReceivedEvent : DeRecEvent
{
    public override string EventType => "RecoveryShareReceived";
    public required ulong ChannelId { get; init; }
    public required uint SharesReceived { get; init; }
}

public sealed record RecoveryShareErrorEvent : DeRecEvent
{
    public override string EventType => "RecoveryShareError";
    public required ulong ChannelId { get; init; }
    public required uint SharesReceived { get; init; }
    public required string Error { get; init; }
}

/// <summary>
/// A helper refused a recovery share request: its response carried a non-OK
/// <c>Status</c> (e.g. <c>UnknownShareVersion</c>) instead of a share. The
/// refusal is not collected — it does not count towards
/// <c>SharesReceived</c> and the recovery stays open for the other helpers'
/// shares — but it does answer that helper's
/// <see cref="RecoverSecretStartedEvent"/>.
/// </summary>
public sealed record RecoveryShareRefusedEvent : DeRecEvent
{
    public override string EventType => "RecoveryShareRefused";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }
    public required Org.Derecalliance.Derec.Protobuf.StatusEnum Status { get; init; }
    public required string Memo { get; init; }
}

/// <summary>
/// A helper answered a recovery share request with a share that cannot be
/// part of the secret. <see cref="Reason"/> is one of the
/// <see cref="CorruptionReason"/> constants.
/// </summary>
/// <remarks>
/// The share is set aside: it does not count towards <c>SharesReceived</c>
/// and never blocks the recovery — the other helpers' shares still complete
/// it. <see cref="CorruptionReason.Malformed"/> and
/// <see cref="CorruptionReason.InvalidProof"/> are reported as the share
/// arrives; <see cref="CorruptionReason.Inconsistent"/> alongside
/// <see cref="SecretRecoveredEvent"/>, once per helper. An honest helper never
/// sends a corrupted share, so the application may treat this as a sign of a
/// damaged or compromised helper — for example by offering to unpair it. It
/// also answers that helper's <see cref="RecoverSecretStartedEvent"/>.
/// </remarks>
public sealed record RecoveryShareCorruptedEvent : DeRecEvent
{
    public override string EventType => "RecoveryShareCorrupted";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }
    public required string Reason { get; init; }
}

/// <summary>
/// The label vocabulary for <see cref="RecoveryShareCorruptedEvent.Reason"/>.
/// Matches the Rust <c>CorruptionReason</c> discriminants one-for-one.
/// </summary>
public static class CorruptionReason
{
    /// <summary>The response carries no decodable share for the requested secret and version.</summary>
    public const string Malformed = "Malformed";
    /// <summary>The share fails its own Merkle proof, e.g. a value altered after it was split.</summary>
    public const string InvalidProof = "InvalidProof";
    /// <summary>
    /// The share is valid on its own, but its commitment root or ciphertext
    /// disagrees with the shares the secret was rebuilt from.
    /// </summary>
    public const string Inconsistent = "Inconsistent";
}

/// <summary>
/// Recovery completed — the reconstructed <see cref="Secret"/> is
/// returned exactly once. Mirrors
/// <see cref="ReplicaSecretReceivedEvent.Secret"/>: the nested
/// <see cref="Secret"/> carries the typed
/// <c>secrets: IReadOnlyList&lt;UserSecret&gt;</c> the owner originally
/// protected, plus the roster snapshot (<c>helpers</c>,
/// <c>replicas</c>, <c>ownerReplicaId</c>) captured at distribution
/// time. The library handles the two-stage <c>DeRecSecret</c> →
/// <c>Secret</c> protobuf decode internally.
/// </summary>
public sealed record SecretRecoveredEvent : DeRecEvent
{
    public override string EventType => "SecretRecovered";
    public required Secret Secret { get; init; }
}

public sealed record UnpairedEvent : DeRecEvent
{
    public override string EventType => "Unpaired";
    public required ulong ChannelId { get; init; }
}

public sealed record UnpairRejectedEvent : DeRecEvent
{
    public override string EventType => "UnpairRejected";
    public required ulong ChannelId { get; init; }
    public required Org.Derecalliance.Derec.Protobuf.StatusEnum Status { get; init; }
    public required string Memo { get; init; }
}

public sealed record PrePairRejectedEvent : DeRecEvent
{
    public override string EventType => "PrePairRejected";
    public required ulong ChannelId { get; init; }
    public required Org.Derecalliance.Derec.Protobuf.StatusEnum Status { get; init; }
    public required string Memo { get; init; }
}

public sealed record HelperInfo(
    [property: JsonPropertyName("channel_id"), JsonNumberHandling(JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString)] ulong ChannelId,
    [property: JsonPropertyName("transports"), JsonConverter(typeof(TransportEndpointListJsonConverter))] IReadOnlyList<TransportProtocol> Transports,
    [property: JsonPropertyName("shared_key")] byte[] SharedKey,
    [property: JsonPropertyName("communication_info"), OmitWhenEmpty] Dictionary<string, string> CommunicationInfo);

/// <summary>
/// One member of the replica group. Exactly one member of a group has
/// <c>Role</c> <see cref="ReplicaRole.Source"/>, and that member is the one
/// the secret originated from.
/// </summary>
public sealed record ReplicaInfo(
    [property: JsonPropertyName("replica_id"), JsonNumberHandling(JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString)] ulong ReplicaId,
    [property: JsonPropertyName("transports"), JsonConverter(typeof(TransportEndpointListJsonConverter))] IReadOnlyList<TransportProtocol> Transports,
    [property: JsonPropertyName("role")] ReplicaRole Role,
    [property: JsonPropertyName("communication_info"), OmitWhenEmpty] Dictionary<string, string> CommunicationInfo);

public sealed record Secret(
    [property: JsonPropertyName("helpers")] IReadOnlyList<HelperInfo> Helpers,
    [property: JsonPropertyName("secrets")] IReadOnlyList<UserSecret> Secrets)
{
    /// <summary>
    /// The replica group: every member (including the writer), the one
    /// channel they share, and the 32-byte group key. <c>null</c> when this
    /// <c>secret_id</c> has no replica setup. Required by
    /// <see cref="DeRecProtocol.RestoreAsync"/> to rebuild replica state
    /// without re-pairing.
    /// </summary>
    [JsonPropertyName("replicas")]
    public Replicas? Replicas { get; init; }
}

public sealed record Replicas(
    [property: JsonPropertyName("channel_id"), JsonNumberHandling(JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString)] ulong ChannelId,
    [property: JsonPropertyName("members")] IReadOnlyList<ReplicaInfo> Members,
    [property: JsonPropertyName("shared_key")] byte[] SharedKey);

public sealed record ChannelShare(
    [property: JsonPropertyName("channel_id"), JsonNumberHandling(JsonNumberHandling.AllowReadingFromString | JsonNumberHandling.WriteAsString)] ulong ChannelId,
    [property: JsonPropertyName("committed_share")] byte[] CommittedShare);

public sealed record ReplicaSecretReceivedEvent : DeRecEvent
{
    public override string EventType => "ReplicaSecretReceived";
    public required ulong ChannelId { get; init; }
    /// <summary>
    /// The member this copy came from: the publisher on a push, the member
    /// that answered on a catch-up.
    /// </summary>
    public required ulong FromReplicaId { get; init; }
    /// <summary>
    /// The member that published <see cref="Version"/>, now stored with it.
    /// Equal to <see cref="FromReplicaId"/> on a push; on a catch-up it names
    /// the original publisher, or <c>null</c> when the serving
    /// member's snapshot records no author.
    /// </summary>
    public ulong? AuthorReplicaId { get; init; }
    public required ulong SecretId { get; init; }
    public required uint Version { get; init; }
    public required Secret Secret { get; init; }
    public required IReadOnlyList<ChannelShare> Shares { get; init; }
}

/// <summary>
/// A member left the group and its roster row was dropped. Fires on the
/// members that remain.
/// </summary>
public sealed record ReplicaRemovedEvent : DeRecEvent
{
    public override string EventType => "ReplicaRemoved";
    public required ulong ReplicaId { get; init; }
}

/// <summary>
/// The group's source role moved to another member because the previous
/// source is leaving. Fires on the device that chose the successor — which it
/// does by the order its channel store returns members in — and on the
/// successor itself when the roster promoting it arrives.
/// </summary>
public sealed record ReplicaSourceChangedEvent : DeRecEvent
{
    public override string EventType => "ReplicaSourceChanged";
    public required ulong ReplicaId { get; init; }
}

/// <summary>
/// This device left the group and dropped its whole <c>SecretId</c>
/// partition. Fires only once it was told to leave and has since seen a
/// roster excluding it. The teardown is automatic: this device is not asked
/// first and gets no earlier event.
/// </summary>
public sealed record SelfRemovedFromGroupEvent : DeRecEvent
{
    public override string EventType => "SelfRemovedFromGroup";
    public required uint Version { get; init; }
}

/// <summary>
/// A replica catch-up finished. <c>FetchedFrom</c> is null when this device
/// was already current, in which case no hydration event follows.
/// </summary>
public sealed record ReplicaDiscoveryCompleteEvent : DeRecEvent
{
    public override string EventType => "ReplicaDiscoveryComplete";
    public required uint LocalVersion { get; init; }
    public required uint GroupVersion { get; init; }
    public ulong? FetchedFrom { get; init; }
}

/// <summary>
/// The first sync for a <c>SecretId</c> this device had no snapshot for —
/// the secret now exists here. Distinguished from
/// <see cref="ReplicaSecretReceivedEvent"/>, which reports a later version of
/// a secret the device already held. Both are written to the stores by the
/// library before the event is surfaced.
/// </summary>
public sealed record ReplicaSecretInstalledEvent : DeRecEvent
{
    public override string EventType => "ReplicaSecretInstalled";
    public required ulong ChannelId { get; init; }
    /// <summary>
    /// The member this copy came from, as on
    /// <see cref="ReplicaSecretReceivedEvent.FromReplicaId"/>.
    /// </summary>
    public required ulong FromReplicaId { get; init; }
    /// <summary>
    /// The member that published <see cref="Version"/>, as on
    /// <see cref="ReplicaSecretReceivedEvent.AuthorReplicaId"/>.
    /// </summary>
    public ulong? AuthorReplicaId { get; init; }
    public required ulong SecretId { get; init; }
    public required uint Version { get; init; }
    public required Secret Secret { get; init; }
    public required IReadOnlyList<ChannelShare> Shares { get; init; }
}

/// <summary>
/// A member offered a different copy of the version this device holds.
/// <para>
/// Two members published the same version independently — each derives the
/// next version from what it held, so concurrent changes collide. Nothing was
/// written; this device keeps its own copy and refused the incoming one with
/// <c>VERSION_CONFLICT</c>, so the publisher sees
/// <see cref="ReplicaSyncRejectedEvent"/>.
/// </para>
/// <para>
/// The application resolves the conflict. The held copy is in the local
/// stores; the incoming one is <see cref="Secret"/>. Publishing the resolved
/// state with <c>FlowKind.ProtectSecret</c> writes the next version, which
/// supersedes both on every member and helper.
/// </para>
/// <para>
/// Until then, do not publish from this device: any further
/// <c>ProtectSecret</c> is a higher version that every other member applies
/// over its own copy, losing the change it never merged.
/// </para>
/// </summary>
public sealed record ReplicaVersionConflictEvent : DeRecEvent
{
    public override string EventType => "ReplicaVersionConflict";
    /// <summary>The channel the copy arrived on.</summary>
    public required ulong ChannelId { get; init; }
    /// <summary>The member this copy came from.</summary>
    public required ulong FromReplicaId { get; init; }
    /// <summary><c>secret_id</c> of the incoming copy.</summary>
    public required ulong SecretId { get; init; }
    /// <summary>The contested version.</summary>
    public required uint Version { get; init; }
    /// <summary>
    /// Who published the copy this device holds, or <c>null</c> when its
    /// snapshot records no author.
    /// </summary>
    public ulong? HeldAuthorReplicaId { get; init; }
    /// <summary>
    /// Who published the incoming copy, or <c>null</c> when
    /// the serving member's snapshot records no author.
    /// </summary>
    public ulong? IncomingAuthorReplicaId { get; init; }
    /// <summary>The incoming copy's full state: secrets, helpers and replicas.</summary>
    public required Secret Secret { get; init; }
}

/// <summary>
/// A group member refused a secret sync. Keyed by <c>ReplicaId</c>, not
/// <c>ChannelId</c>: every member answers on the one group channel.
/// A <c>VERSION_CONFLICT</c> status means another member holds a different
/// copy of this version: do not publish from this device again until the
/// conflict is resolved. Run <c>FlowKind.ReplicaDiscovery</c> to receive the
/// group's copy as <see cref="ReplicaVersionConflictEvent"/>, merge, and
/// publish the result once with <c>FlowKind.ProtectSecret</c>.
/// </summary>
public sealed record ReplicaSyncRejectedEvent : DeRecEvent
{
    public override string EventType => "ReplicaSyncRejected";
    public required ulong ReplicaId { get; init; }
    public required ulong SecretId { get; init; }
    public required uint Version { get; init; }
    public required Org.Derecalliance.Derec.Protobuf.StatusEnum Status { get; init; }
    public required string Memo { get; init; }
}

/// <summary>
/// A secret sync could not be delivered to a member at all — distinct from
/// <see cref="ReplicaSyncRejectedEvent"/>, which is the member answering "no".
/// </summary>
public sealed record ReplicaSyncFailedEvent : DeRecEvent
{
    public override string EventType => "ReplicaSyncFailed";
    public required ulong ReplicaId { get; init; }
    public required uint Version { get; init; }
    public required string Reason { get; init; }
}

/// <summary>
/// The replica leg of a publishing round finished. Reported separately from
/// <see cref="SharingCompleteEvent"/>: replicas are best-effort, so a member
/// in <c>Behind</c> does not fail the round. <c>Behind</c> is the
/// application's retry list — the library keeps no durable per-member sync
/// state.
/// </summary>
public sealed record ReplicaSyncCompleteEvent : DeRecEvent
{
    public override string EventType => "ReplicaSyncComplete";
    public required uint Version { get; init; }
    public required IReadOnlyList<ulong> Synced { get; init; }
    public required IReadOnlyList<ulong> Behind { get; init; }
}

public sealed record ReplicaSecretAckedEvent : DeRecEvent
{
    public override string EventType => "ReplicaSecretAcked";
    public required ulong ChannelId { get; init; }
    public required ulong FromReplicaId { get; init; }
    public required ulong SecretId { get; init; }
    public required uint Version { get; init; }
    public required Org.Derecalliance.Derec.Protobuf.StatusEnum Status { get; init; }
    public required string Memo { get; init; }
}

public sealed record ChannelInfoUpdatedEvent : DeRecEvent
{
    public override string EventType => "ChannelInfoUpdated";
    public required ulong ChannelId { get; init; }
}

public sealed record ChannelInfoUpdateRejectedEvent : DeRecEvent
{
    public override string EventType => "ChannelInfoUpdateRejected";
    public required ulong ChannelId { get; init; }
    public required Org.Derecalliance.Derec.Protobuf.StatusEnum Status { get; init; }
    public required string Memo { get; init; }
}

public sealed record NoOpEvent : DeRecEvent
{
    public override string EventType => "NoOp";
}

/// <summary>
/// An inbound message was dropped untouched: no store was written and nothing
/// was sent back. <see cref="Reason"/> is one of the <see cref="IgnoreReason"/>
/// constants.
/// </summary>
/// <remarks>
/// <see cref="IgnoreReason.PendingVerification"/> means the peer sent it before
/// this device confirmed the channel's fingerprint — typically a replica source
/// pushing its first copy while this destination still shows the code.
/// Confirming does not replay it: after <c>VerifyFingerprintAsync</c> succeeds,
/// a replica destination starts <see cref="FlowKind.ReplicaDiscovery"/> to pull
/// the copy itself. <see cref="TraceId"/> matches the peer's <c>*Started</c>
/// event for the same round (<c>0</c> when the sender set none).
/// </remarks>
public sealed record MessageIgnoredEvent : DeRecEvent
{
    public override string EventType => "MessageIgnored";
    public required ulong ChannelId { get; init; }
    public required string Reason { get; init; }
    public required ulong TraceId { get; init; }
}

/// <summary>
/// The label vocabulary for <see cref="MessageIgnoredEvent.Reason"/>. Matches
/// the Rust <c>IgnoreReason</c> discriminants one-for-one.
/// </summary>
public static class IgnoreReason
{
    public const string PendingVerification = "PendingVerification";
    public const string Expired = "Expired";
}

/// <summary>
/// Returned by <c>RestoreAsync</c>: a roster entry got no channel, so this
/// device cannot reach that peer. Every other entry and the user-secret
/// snapshot were restored; <see cref="Reason"/> is one of the
/// <see cref="NotRestoredReason"/> constants.
/// </summary>
/// <remarks>
/// For a helper, <see cref="ChannelId"/> is its channel and
/// <see cref="ReplicaId"/> is null. For a replica group member,
/// <see cref="ChannelId"/> is the group's channel and <see cref="ReplicaId"/>
/// names the member. The peer itself is untouched — a helper still holds its
/// share — and pairing with it again makes it reachable.
/// </remarks>
public sealed record PeerNotRestoredEvent : DeRecEvent
{
    public override string EventType => "PeerNotRestored";
    public required ulong ChannelId { get; init; }
    public ulong? ReplicaId { get; init; }
    public required string Reason { get; init; }
}

/// <summary>
/// The label vocabulary for <see cref="PeerNotRestoredEvent.Reason"/>.
/// Matches the Rust <c>NotRestoredReason</c> discriminants one-for-one.
/// </summary>
public static class NotRestoredReason
{
    /// <summary>The recovered roster names no endpoint for the peer.</summary>
    public const string NoTransports = "NoTransports";
}

/// <summary>
/// Fired by <see cref="DeRecProtocol.StartAsync"/> when a pairing
/// handshake was dispatched successfully. <see cref="Kind"/> is the
/// local party's role in the flow (same value that will land on the
/// subsequent <see cref="PairingCompletedEvent.Kind"/>).
/// </summary>
public sealed record PairingStartedEvent : DeRecEvent
{
    public override string EventType => "PairingStarted";
    public required ulong ChannelId { get; init; }
    public required Pairing.SenderKind Kind { get; init; }

    /// <summary>The token identifying the round this request belongs to.
    /// One is drawn per <c>Start</c> call, so a fan-out shares it across all
    /// of its targets, and the peer echoes it on the response.</summary>
    public required ulong TraceId { get; init; }
}

public sealed record DiscoveryStartedEvent : DeRecEvent
{
    public override string EventType => "DiscoveryStarted";
    public required ulong ChannelId { get; init; }

    /// <summary>The token identifying the round this request belongs to.
    /// One is drawn per <c>Start</c> call, so a fan-out shares it across all
    /// of its targets, and the peer echoes it on the response.</summary>
    public required ulong TraceId { get; init; }
}

public sealed record DiscoveryFailedEvent : DeRecEvent
{
    public override string EventType => "DiscoveryFailed";
    public required ulong ChannelId { get; init; }
    public required string Error { get; init; }
}

public sealed record ProtectSecretStartedEvent : DeRecEvent
{
    public override string EventType => "ProtectSecretStarted";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }

    /// <summary>The token identifying the round this request belongs to.
    /// One is drawn per <c>Start</c> call, so a fan-out shares it across all
    /// of its targets, and the peer echoes it on the response.</summary>
    public required ulong TraceId { get; init; }
}

public sealed record ProtectSecretFailedEvent : DeRecEvent
{
    public override string EventType => "ProtectSecretFailed";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }
    public required string Error { get; init; }
}

public sealed record VerifySharesStartedEvent : DeRecEvent
{
    public override string EventType => "VerifySharesStarted";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }

    /// <summary>The token identifying the round this request belongs to.
    /// One is drawn per <c>Start</c> call, so a fan-out shares it across all
    /// of its targets, and the peer echoes it on the response.</summary>
    public required ulong TraceId { get; init; }
}

public sealed record VerifySharesFailedEvent : DeRecEvent
{
    public override string EventType => "VerifySharesFailed";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }
    public required string Error { get; init; }
}

public sealed record RecoverSecretStartedEvent : DeRecEvent
{
    public override string EventType => "RecoverSecretStarted";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }

    /// <summary>The token identifying the round this request belongs to.
    /// One is drawn per <c>Start</c> call, so a fan-out shares it across all
    /// of its targets, and the peer echoes it on the response.</summary>
    public required ulong TraceId { get; init; }
}

public sealed record RecoverSecretFailedEvent : DeRecEvent
{
    public override string EventType => "RecoverSecretFailed";
    public required ulong ChannelId { get; init; }
    public required uint Version { get; init; }
    public required string Error { get; init; }
}

public sealed record UnpairFailedEvent : DeRecEvent
{
    public override string EventType => "UnpairFailed";
    public required ulong ChannelId { get; init; }
    public required string Error { get; init; }
}

public sealed record UnpairStartedEvent : DeRecEvent
{
    public override string EventType => "UnpairStarted";
    public required ulong ChannelId { get; init; }

    /// <summary>The token identifying the round this request belongs to.
    /// One is drawn per <c>Start</c> call, so a fan-out shares it across all
    /// of its targets, and the peer echoes it on the response.</summary>
    public required ulong TraceId { get; init; }
}

public sealed record UpdateChannelInfoStartedEvent : DeRecEvent
{
    public override string EventType => "UpdateChannelInfoStarted";
    public required ulong ChannelId { get; init; }

    /// <summary>The token identifying the round this request belongs to.
    /// One is drawn per <c>Start</c> call, so a fan-out shares it across all
    /// of its targets, and the peer echoes it on the response.</summary>
    public required ulong TraceId { get; init; }
}

public sealed record UpdateChannelInfoFailedEvent : DeRecEvent
{
    public override string EventType => "UpdateChannelInfoFailed";
    public required ulong ChannelId { get; init; }
    public required string Error { get; init; }
}

/// <summary>
/// Emitted by <see cref="DeRecProtocol.ProcessAsync"/> in place of
/// <see cref="ActionRequiredEvent"/> when the configured
/// <see cref="AutoAcceptPolicy"/> opts in to the inbound action's flow.
/// The same event vec also carries the flow's completion events
/// (<see cref="ShareStoredEvent"/>, <see cref="PairingCompletedEvent"/>,
/// etc.); use this event purely for observability/audit logging.
/// </summary>
public sealed record AutoAcceptedEvent : DeRecEvent
{
    public override string EventType => "AutoAccepted";
    public required ulong ChannelId { get; init; }
    /// <summary>
    /// Same label vocabulary as
    /// <see cref="ActionRequiredEvent"/>'s underlying action kind
    /// (<c>"Pairing"</c>, <c>"StoreShare"</c>, …).
    /// </summary>
    public required string ActionKind { get; init; }
}

/// <summary>
/// Placeholder for any DeRecEvent variant not yet fully marshaled
/// across the FFI. <see cref="Variant"/> carries the Rust discriminant
/// name so the app can still log "unknown event" cleanly.
/// </summary>
public sealed record UnmappedEvent : DeRecEvent
{
    public override string EventType => "Unmapped";

    public required string Variant { get; init; }
}

/// <summary>
/// <see cref="System.Text.Json"/> converter that dispatches on the
/// <c>"type"</c> JSON field to the right <see cref="DeRecEvent"/>
/// subclass.
/// </summary>
public sealed class DeRecEventConverter : JsonConverter<DeRecEvent>
{
    public override DeRecEvent Read(ref System.Text.Json.Utf8JsonReader reader, Type typeToConvert, System.Text.Json.JsonSerializerOptions options)
    {
        using var doc = System.Text.Json.JsonDocument.ParseValue(ref reader);
        var root = doc.RootElement;
        string type = root.GetProperty("type").GetString()
            ?? throw new System.Text.Json.JsonException("DeRecEvent missing \"type\" field");
        return type switch
        {
            "PairingCompleted" => ParsePairingCompleted(root),
            "ReplicaPaired" => ParseReplicaPaired(root),
            "ActionRequired" => ParseActionRequired(root),
            "ShareStored" => new ShareStoredEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
            },
            "ShareConfirmed" => new ShareConfirmedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
            },
            "ShareRejected" => new ShareRejectedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
                Status = (Org.Derecalliance.Derec.Protobuf.StatusEnum)root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "SharingComplete" => new SharingCompleteEvent
            {
                Version = root.GetProperty("version").GetUInt32(),
                ConfirmedCount = root.GetProperty("confirmed_count").GetUInt32(),
                FailedCount = root.GetProperty("failed_count").GetUInt32(),
                ThresholdMet = root.GetProperty("threshold_met").GetBoolean(),
            },
            "ShareVerified" => new ShareVerifiedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
            },
            "ShareVerifyRejected" => new ShareVerifyRejectedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
                Status = (Org.Derecalliance.Derec.Protobuf.StatusEnum)root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "SecretsDiscovered" => ParseSecretsDiscovered(root),
            "RecoveryShareReceived" => new RecoveryShareReceivedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                SharesReceived = root.GetProperty("shares_received").GetUInt32(),
            },
            "RecoveryShareError" => new RecoveryShareErrorEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                SharesReceived = root.GetProperty("shares_received").GetUInt32(),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "RecoveryShareRefused" => new RecoveryShareRefusedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
                Status = (Org.Derecalliance.Derec.Protobuf.StatusEnum)root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "RecoveryShareCorrupted" => new RecoveryShareCorruptedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
                Reason = root.GetProperty("reason").GetString() ?? string.Empty,
            },
            "SecretRecovered" => new SecretRecoveredEvent
            {
                Secret = ParseSecretObject(root.GetProperty("secret")),
            },
            "Unpaired" => new UnpairedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
            },
            "UnpairRejected" => new UnpairRejectedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Status = (Org.Derecalliance.Derec.Protobuf.StatusEnum)root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "PrePairRejected" => new PrePairRejectedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Status = (Org.Derecalliance.Derec.Protobuf.StatusEnum)root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "ReplicaSecretReceived" => ParseReplicaSecretReceived(root),
            "ReplicaSecretInstalled" => ParseReplicaSecretInstalled(root),
            "ReplicaVersionConflict" => new ReplicaVersionConflictEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                FromReplicaId = ReadId(root.GetProperty("from_replica_id")),
                SecretId = ReadId(root.GetProperty("secret_id")),
                Version = root.GetProperty("version").GetUInt32(),
                HeldAuthorReplicaId = ReadOptionalId(root.GetProperty("held_author_replica_id")),
                IncomingAuthorReplicaId = ReadOptionalId(root.GetProperty("incoming_author_replica_id")),
                Secret = ParseSecretObject(root.GetProperty("secret")),
            },
            "ReplicaSyncRejected" => new ReplicaSyncRejectedEvent
            {
                ReplicaId = ReadId(root.GetProperty("replica_id")),
                SecretId = ReadId(root.GetProperty("secret_id")),
                Version = root.GetProperty("version").GetUInt32(),
                Status = (Org.Derecalliance.Derec.Protobuf.StatusEnum)root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString()!,
            },
            "ReplicaSyncFailed" => new ReplicaSyncFailedEvent
            {
                ReplicaId = ReadId(root.GetProperty("replica_id")),
                Version = root.GetProperty("version").GetUInt32(),
                Reason = root.GetProperty("reason").GetString()!,
            },
            "ReplicaRemoved" => new ReplicaRemovedEvent
            {
                ReplicaId = ReadId(root.GetProperty("replica_id")),
            },
            "ReplicaSourceChanged" => new ReplicaSourceChangedEvent
            {
                ReplicaId = ReadId(root.GetProperty("replica_id")),
            },
            "SelfRemovedFromGroup" => new SelfRemovedFromGroupEvent
            {
                Version = root.GetProperty("version").GetUInt32(),
            },
            "ReplicaDiscoveryComplete" => new ReplicaDiscoveryCompleteEvent
            {
                LocalVersion = root.GetProperty("local_version").GetUInt32(),
                GroupVersion = root.GetProperty("group_version").GetUInt32(),
                FetchedFrom = root.TryGetProperty("fetched_from", out var ff)
                    ? ReadId(ff)
                    : null,
            },
            "ReplicaSyncComplete" => new ReplicaSyncCompleteEvent
            {
                Version = root.GetProperty("version").GetUInt32(),
                Synced = ReadIdList(root.GetProperty("synced")),
                Behind = ReadIdList(root.GetProperty("behind")),
            },
            "ReplicaSecretAcked" => new ReplicaSecretAckedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                FromReplicaId = ReadId(root.GetProperty("from_replica_id")),
                SecretId = ReadId(root.GetProperty("secret_id")),
                Version = root.GetProperty("version").GetUInt32(),
                Status = (Org.Derecalliance.Derec.Protobuf.StatusEnum)root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "ChannelInfoUpdated" => new ChannelInfoUpdatedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
            },
            "ChannelInfoUpdateRejected" => new ChannelInfoUpdateRejectedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Status = (Org.Derecalliance.Derec.Protobuf.StatusEnum)root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "AutoAccepted" => new AutoAcceptedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                ActionKind = root.GetProperty("action_kind").GetString() ?? string.Empty,
            },
            "NoOp" => new NoOpEvent(),
            "MessageIgnored" => new MessageIgnoredEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Reason = root.GetProperty("reason").GetString() ?? string.Empty,
                TraceId = ReadId(root.GetProperty("trace_id")),
            },
            "PeerNotRestored" => new PeerNotRestoredEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                ReplicaId = root.TryGetProperty("replica_id", out var rid)
                    ? ReadId(rid)
                    : null,
                Reason = root.GetProperty("reason").GetString() ?? string.Empty,
            },
            "PairingStarted" => new PairingStartedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Kind = (Pairing.SenderKind)root.GetProperty("kind").GetInt32(),
                TraceId = ReadId(root.GetProperty("trace_id")),
            },
            "DiscoveryStarted" => new DiscoveryStartedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                TraceId = ReadId(root.GetProperty("trace_id")),
            },
            "DiscoveryFailed" => new DiscoveryFailedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "ProtectSecretStarted" => new ProtectSecretStartedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
                TraceId = ReadId(root.GetProperty("trace_id")),
            },
            "ProtectSecretFailed" => new ProtectSecretFailedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "VerifySharesStarted" => new VerifySharesStartedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
                TraceId = ReadId(root.GetProperty("trace_id")),
            },
            "VerifySharesFailed" => new VerifySharesFailedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "RecoverSecretStarted" => new RecoverSecretStartedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
                TraceId = ReadId(root.GetProperty("trace_id")),
            },
            "RecoverSecretFailed" => new RecoverSecretFailedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Version = root.GetProperty("version").GetUInt32(),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "UnpairFailed" => new UnpairFailedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "UnpairStarted" => new UnpairStartedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                TraceId = ReadId(root.GetProperty("trace_id")),
            },
            "UpdateChannelInfoStarted" => new UpdateChannelInfoStartedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                TraceId = ReadId(root.GetProperty("trace_id")),
            },
            "UpdateChannelInfoFailed" => new UpdateChannelInfoFailedEvent
            {
                ChannelId = ReadId(root.GetProperty("channel_id")),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "Unmapped" => new UnmappedEvent
            {
                Variant = root.GetProperty("variant").GetString() ?? "unknown",
            },
            _ => new UnmappedEvent { Variant = type },
        };
    }

    private static byte[] ReadByteArray(System.Text.Json.JsonElement el)
    {
        var bytes = new List<byte>(el.GetArrayLength());
        foreach (var b in el.EnumerateArray()) bytes.Add(b.GetByte());
        return bytes.ToArray();
    }

    private static ulong ReadId(System.Text.Json.JsonElement el) =>
        ulong.TryParse(el.GetString(), System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out ulong id)
            ? id
            : throw new System.Text.Json.JsonException($"expected a decimal u64 id, got {el.GetRawText()}");

    private static ulong? ReadOptionalId(System.Text.Json.JsonElement el) =>
        el.ValueKind == System.Text.Json.JsonValueKind.Null ? null : ReadId(el);

    private static List<ulong> ReadIdList(System.Text.Json.JsonElement el)
    {
        var out_ = new List<ulong>(el.GetArrayLength());
        foreach (var item in el.EnumerateArray()) out_.Add(ReadId(item));
        return out_;
    }

    private static IReadOnlyList<TransportProtocol> ReadEndpoints(System.Text.Json.JsonElement member)
    {
        var endpoints = new List<TransportProtocol>();
        foreach (var t in member.GetProperty("transports").EnumerateArray())
            endpoints.Add(TransportProtocol.FromWireEndpoint(t));
        return endpoints;
    }

    private static Dictionary<string, string> ReadStringMap(System.Text.Json.JsonElement el)
    {
        var dict = new Dictionary<string, string>();
        if (el.ValueKind == System.Text.Json.JsonValueKind.Object)
        {
            foreach (var prop in el.EnumerateObject())
                dict[prop.Name] = prop.Value.GetString() ?? string.Empty;
        }
        return dict;
    }

    private static SecretsDiscoveredEvent ParseSecretsDiscovered(System.Text.Json.JsonElement root)
    {
        var secrets = new List<DiscoveredSecret>();
        if (root.TryGetProperty("secrets", out var secretsArr) &&
            secretsArr.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            foreach (var s in secretsArr.EnumerateArray())
            {
                var versions = new List<DiscoveredSecretVersion>();
                if (s.TryGetProperty("versions", out var vArr))
                {
                    foreach (var v in vArr.EnumerateArray())
                    {
                        versions.Add(new DiscoveredSecretVersion(
                            v.GetProperty("version").GetUInt32(),
                            v.GetProperty("description").GetString() ?? string.Empty));
                    }
                }
                secrets.Add(new DiscoveredSecret(
                    ReadId(s.GetProperty("secret_id")),
                    versions));
            }
        }
        return new SecretsDiscoveredEvent
        {
            ChannelId = ReadId(root.GetProperty("channel_id")),
            Secrets = secrets,
        };
    }

    /// <summary>
    /// Parse the nested <c>secret</c> JSON object common to
    /// <see cref="ReplicaSecretReceivedEvent"/>,
    /// <see cref="ReplicaSecretInstalledEvent"/>,
    /// <see cref="ReplicaVersionConflictEvent"/> and
    /// <see cref="SecretRecoveredEvent"/>. All expose the
    /// identical wire shape — the typed
    /// <see cref="DeRec.Library.Orchestrator.Secret"/> the owner
    /// originally protected.
    /// </summary>
    private static Secret ParseSecretObject(System.Text.Json.JsonElement secretEl)
    {
        var helpers = new List<HelperInfo>();
        foreach (var h in secretEl.GetProperty("helpers").EnumerateArray())
        {
            helpers.Add(new HelperInfo(
                ReadId(h.GetProperty("channel_id")),
                ReadEndpoints(h),
                ReadByteArray(h.GetProperty("shared_key")),
                h.TryGetProperty("communication_info", out var hci) ? ReadStringMap(hci) : new()));
        }
        var secrets = new List<UserSecret>();
        foreach (var s in secretEl.GetProperty("secrets").EnumerateArray())
        {
            secrets.Add(new UserSecret
            {
                Id = ReadByteArray(s.GetProperty("id")),
                Name = s.GetProperty("name").GetString()!,
                Data = ReadByteArray(s.GetProperty("data")),
            });
        }
        Replicas? replicas = null;
        if (secretEl.TryGetProperty("replicas", out var replicasEl)
            && replicasEl.ValueKind == System.Text.Json.JsonValueKind.Object)
        {
            var members = new List<ReplicaInfo>();
            foreach (var r in replicasEl.GetProperty("members").EnumerateArray())
            {
                members.Add(new ReplicaInfo(
                    ReadId(r.GetProperty("replica_id")),
                    ReadEndpoints(r),
                    ReplicaRoleJsonConverter.Parse(r.GetProperty("role").GetString()),
                    r.TryGetProperty("communication_info", out var rci) ? ReadStringMap(rci) : new()));
            }
            var sharedKey = ReadByteArray(replicasEl.GetProperty("shared_key"));
            replicas = new Replicas(
                ReadId(replicasEl.GetProperty("channel_id")),
                members,
                sharedKey);
        }
        return new Secret(helpers, secrets)
        {
            Replicas = replicas,
        };
    }

    private static ReplicaSecretReceivedEvent ParseReplicaSecretReceived(System.Text.Json.JsonElement root)
    {
        var container = ParseSecretObject(root.GetProperty("secret"));

        var shares = new List<ChannelShare>();
        foreach (var s in root.GetProperty("shares").EnumerateArray())
        {
            shares.Add(new ChannelShare(
                ReadId(s.GetProperty("channel_id")),
                ReadByteArray(s.GetProperty("committed_share"))));
        }

        return new ReplicaSecretReceivedEvent
        {
            ChannelId = ReadId(root.GetProperty("channel_id")),
            FromReplicaId = ReadId(root.GetProperty("from_replica_id")),
            AuthorReplicaId = ReadOptionalId(root.GetProperty("author_replica_id")),
            SecretId = ReadId(root.GetProperty("secret_id")),
            Version = root.GetProperty("version").GetUInt32(),
            Secret = container,
            Shares = shares,
        };
    }

    private static ReplicaSecretInstalledEvent ParseReplicaSecretInstalled(System.Text.Json.JsonElement root)
    {
        var container = ParseSecretObject(root.GetProperty("secret"));

        var shares = new List<ChannelShare>();
        foreach (var s in root.GetProperty("shares").EnumerateArray())
        {
            shares.Add(new ChannelShare(
                ReadId(s.GetProperty("channel_id")),
                ReadByteArray(s.GetProperty("committed_share"))));
        }

        return new ReplicaSecretInstalledEvent
        {
            ChannelId = ReadId(root.GetProperty("channel_id")),
            FromReplicaId = ReadId(root.GetProperty("from_replica_id")),
            AuthorReplicaId = ReadOptionalId(root.GetProperty("author_replica_id")),
            SecretId = ReadId(root.GetProperty("secret_id")),
            Version = root.GetProperty("version").GetUInt32(),
            Secret = container,
            Shares = shares,
        };
    }

    private static ActionRequiredEvent ParseActionRequired(System.Text.Json.JsonElement root)
    {
        var actionEl = root.GetProperty("action");
        var bytes = new List<byte>(actionEl.GetArrayLength());
        foreach (var b in actionEl.EnumerateArray()) bytes.Add(b.GetByte());

        List<TransportProtocol>? updatedTransports = null;
        if (root.TryGetProperty("updated_transports", out var ut))
        {
            updatedTransports = new List<TransportProtocol>(ut.GetArrayLength());
            foreach (var t in ut.EnumerateArray())
                updatedTransports.Add(TransportProtocol.FromWireEndpoint(t));
        }

        return new ActionRequiredEvent
        {
            ChannelId = ReadId(root.GetProperty("channel_id")),
            Action = bytes.ToArray(),
            ActionKind = root.GetProperty("action_kind").GetString()!,
            TraceId = ReadId(root.GetProperty("trace_id")),
            PeerCommunicationInfo = root.TryGetProperty("peer_communication_info", out var pci)
                ? ReadStringMap(pci)
                : new(),
            SenderKind = root.TryGetProperty("sender_kind", out var sk)
                ? (Pairing.SenderKind)sk.GetInt32()
                : null,
            Version = root.TryGetProperty("version", out var v) ? v.GetUInt32() : null,
            ShareDescription = root.TryGetProperty("share_description", out var sd) ? sd.GetString() : null,
            ShareSecretId = root.TryGetProperty("share_secret_id", out var ssi) ? ReadId(ssi) : null,
            ShareSize = root.TryGetProperty("share_size", out var ss) ? ss.GetUInt64() : null,
            UnpairMemo = root.TryGetProperty("unpair_memo", out var um) ? um.GetString() : null,
            UpdatedCommunicationInfo = root.TryGetProperty("updated_communication_info", out var uci)
                ? ReadStringMap(uci)
                : null,
            UpdatedTransports = updatedTransports,
        };
    }

    public override void Write(System.Text.Json.Utf8JsonWriter writer, DeRecEvent value, System.Text.Json.JsonSerializerOptions options)
    {
        throw new NotSupportedException("DeRecEvent is read-only from the FFI side.");
    }

    private static PairingCompletedEvent ParsePairingCompleted(System.Text.Json.JsonElement root)
    {
        var ev = new PairingCompletedEvent
        {
            ChannelId = ReadId(root.GetProperty("channel_id")),
            PairingChannelId = ReadId(root.GetProperty("pairing_channel_id")),
            Kind = (Pairing.SenderKind)root.GetProperty("kind").GetInt32(),
        };
        if (root.TryGetProperty("peer_communication_info", out var pci) &&
            pci.ValueKind == System.Text.Json.JsonValueKind.Object)
        {
            foreach (var prop in pci.EnumerateObject())
                ev.PeerCommunicationInfo[prop.Name] = prop.Value.GetString() ?? string.Empty;
        }
        return ev;
    }

    private static ReplicaPairedEvent ParseReplicaPaired(System.Text.Json.JsonElement root) => new()
    {
        ChannelId = ReadId(root.GetProperty("channel_id")),
        PeerReplicaId = ReadId(root.GetProperty("peer_replica_id")),
    };
}
