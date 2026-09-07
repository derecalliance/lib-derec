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
    SyncCheck = 7,
    /// <summary>
    /// Remove a member from the replica group. Replica-only. Naming this
    /// device is a voluntary departure; naming another is an eviction.
    /// </summary>
    RemoveReplica = 8,
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
    [JsonPropertyName("secret_id")] public required string SecretId { get; init; }
    [JsonPropertyName("version")] public required uint Version { get; init; }
    [JsonPropertyName("target")] public Target? Target { get; init; }
}

/// <summary>Params for <see cref="FlowKind.RecoverSecret"/>.</summary>
public sealed record RecoverSecretParams
{
    [JsonPropertyName("secret_id")] public required string SecretId { get; init; }
    [JsonPropertyName("version")] public required uint Version { get; init; }
}

/// <summary>Params for <see cref="FlowKind.Unpair"/>.</summary>
public sealed record UnpairParams
{
    [JsonPropertyName("channel_id")] public required string ChannelId { get; init; }
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
    /// Replaces the target(s)' view of this node's transport endpoint.
    /// </summary>
    /// <remarks>
    /// Superseded by <see cref="OwnTransports"/>, which carries every
    /// endpoint rather than one. Scheduled for removal in v0.0.5;
    /// <see cref="OwnTransports"/> takes precedence when both are set.
    /// </remarks>
    [Obsolete("Superseded by OwnTransports. Scheduled for removal in v0.0.5.")]
    [JsonPropertyName("transport_protocol")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public TransportProtocolDto? TransportProtocol { get; init; }

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
/// Params for <see cref="FlowKind.SyncCheck"/>.
/// </summary>
/// <remarks>
/// The flow takes none: the group and this device's own version are both read
/// from the stores. Present so every flow kind has a params type and
/// <see cref="DeRecProtocol.StartAsync"/> reads uniformly at the call site.
/// </remarks>
public sealed record SyncCheckParams;

/// <summary>
/// Params for <see cref="FlowKind.RemoveReplica"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ReplicaId"/> is a <b>decimal</b> string — the same form
/// <c>ReplicaPairedEvent.PeerReplicaId</c> hands back, and the form every
/// other id takes across this boundary. A string rather than a
/// <see cref="ulong"/> so values above 2^53 survive the JSON round trip
/// through hosts whose numbers are doubles. Naming no current member is
/// rejected, not silently ignored.
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
/// </remarks>
public sealed record RemoveReplicaParams
{
    [JsonPropertyName("replica_id")] public required string ReplicaId { get; init; }

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
    public required string ChannelId { get; init; }

    /// <summary>
    /// Transient <c>channel_id</c> that traveled on the <c>ContactMessage</c>
    /// and the pairing envelopes. No longer resolves in library state after
    /// this event fires — provided so applications that persisted it can
    /// rekey their own records.
    /// </summary>
    public required string PairingChannelId { get; init; }
    public required Pairing.SenderKind Kind { get; init; }
    public Dictionary<string, string> PeerCommunicationInfo { get; init; } = new();
}

/// <summary>
/// Fired alongside <see cref="PairingCompletedEvent"/> on replica-mode
/// pairings. Carries the peer's <c>replica_id</c> as a decimal-encoded
/// string.
/// </summary>
public sealed record ReplicaPairedEvent : DeRecEvent
{
    public override string EventType => "ReplicaPaired";

    public required string ChannelId { get; init; }
    public required string PeerReplicaId { get; init; }
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

    public required string ChannelId { get; init; }

    /// <summary>Opaque PendingAction bytes — round-trip verbatim.</summary>
    public required byte[] Action { get; init; }
}

public sealed record ShareStoredEvent : DeRecEvent
{
    public override string EventType => "ShareStored";
    public required string ChannelId { get; init; }
    public required uint Version { get; init; }
}

public sealed record ShareConfirmedEvent : DeRecEvent
{
    public override string EventType => "ShareConfirmed";
    public required string ChannelId { get; init; }
    public required uint Version { get; init; }
}

public sealed record ShareRejectedEvent : DeRecEvent
{
    public override string EventType => "ShareRejected";
    public required string ChannelId { get; init; }
    public required uint Version { get; init; }
    public required int Status { get; init; }
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
    public required string ChannelId { get; init; }
    public required uint Version { get; init; }
}

public sealed record DiscoveredSecretVersion(uint Version, string Description);

public sealed record DiscoveredSecret(string SecretId, IReadOnlyList<DiscoveredSecretVersion> Versions);

public sealed record SecretsDiscoveredEvent : DeRecEvent
{
    public override string EventType => "SecretsDiscovered";
    public required string ChannelId { get; init; }
    public required IReadOnlyList<DiscoveredSecret> Secrets { get; init; }
}

public sealed record RecoveryShareReceivedEvent : DeRecEvent
{
    public override string EventType => "RecoveryShareReceived";
    public required string ChannelId { get; init; }
    public required uint SharesReceived { get; init; }
}

public sealed record RecoveryShareErrorEvent : DeRecEvent
{
    public override string EventType => "RecoveryShareError";
    public required string ChannelId { get; init; }
    public required uint SharesReceived { get; init; }
    public required string Error { get; init; }
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
    public required string ChannelId { get; init; }
}

public sealed record UnpairRejectedEvent : DeRecEvent
{
    public override string EventType => "UnpairRejected";
    public required string ChannelId { get; init; }
    public required int Status { get; init; }
    public required string Memo { get; init; }
}

public sealed record PrePairRejectedEvent : DeRecEvent
{
    public override string EventType => "PrePairRejected";
    public required string ChannelId { get; init; }
    public required int Status { get; init; }
    public required string Memo { get; init; }
}

public sealed record HelperInfo(
    [property: JsonPropertyName("channel_id")] string ChannelId,
    [property: JsonPropertyName("transports")] IReadOnlyList<TransportProtocol> Transports,
    [property: JsonPropertyName("shared_key")] byte[] SharedKey,
    [property: JsonPropertyName("communication_info")] Dictionary<string, string> CommunicationInfo);

/// <summary>
/// One member of the replica group. <c>Role</c> is <c>"Source"</c> or
/// <c>"Destination"</c>; exactly one member of a group carries
/// <c>"Source"</c>, and that member is the one the secret originated from.
/// </summary>
public sealed record ReplicaInfo(
    [property: JsonPropertyName("replica_id")] string ReplicaId,
    [property: JsonPropertyName("transports")] IReadOnlyList<TransportProtocol> Transports,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("communication_info")] Dictionary<string, string> CommunicationInfo);

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
    [property: JsonPropertyName("channel_id")] string ChannelId,
    [property: JsonPropertyName("members")] IReadOnlyList<ReplicaInfo> Members,
    [property: JsonPropertyName("shared_key")] byte[] SharedKey);

public sealed record ChannelShare(
    [property: JsonPropertyName("channel_id")] string ChannelId,
    [property: JsonPropertyName("committed_share")] byte[] CommittedShare);

public sealed record ReplicaSecretReceivedEvent : DeRecEvent
{
    public override string EventType => "ReplicaSecretReceived";
    public required string ChannelId { get; init; }
    public required string FromReplicaId { get; init; }
    public required string SecretId { get; init; }
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
    public required string ReplicaId { get; init; }
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
    public required string ReplicaId { get; init; }
}

/// <summary>
/// This device left the group and dropped its whole <c>SecretId</c>
/// partition. Fires only once it was told to leave and has since seen a
/// roster excluding it.
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
public sealed record SyncCheckCompleteEvent : DeRecEvent
{
    public override string EventType => "SyncCheckComplete";
    public required uint LocalVersion { get; init; }
    public required uint GroupVersion { get; init; }
    public string? FetchedFrom { get; init; }
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
    public required string ChannelId { get; init; }
    public required string FromReplicaId { get; init; }
    public required string SecretId { get; init; }
    public required uint Version { get; init; }
    public required Secret Secret { get; init; }
    public required IReadOnlyList<ChannelShare> Shares { get; init; }
}

/// <summary>
/// A group member refused a secret sync. Keyed by <c>ReplicaId</c>, not
/// <c>ChannelId</c>: every member answers on the one group channel.
/// A <c>VERSION_CONFLICT</c> status means the round must be resolved and
/// republished at a new version.
/// </summary>
public sealed record ReplicaSyncRejectedEvent : DeRecEvent
{
    public override string EventType => "ReplicaSyncRejected";
    public required string ReplicaId { get; init; }
    public required string SecretId { get; init; }
    public required uint Version { get; init; }
    public required int Status { get; init; }
    public required string Memo { get; init; }
}

/// <summary>
/// A secret sync could not be delivered to a member at all — distinct from
/// <see cref="ReplicaSyncRejectedEvent"/>, which is the member answering "no".
/// </summary>
public sealed record ReplicaSyncFailedEvent : DeRecEvent
{
    public override string EventType => "ReplicaSyncFailed";
    public required string ReplicaId { get; init; }
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
    public required IReadOnlyList<string> Synced { get; init; }
    public required IReadOnlyList<string> Behind { get; init; }
}

public sealed record ReplicaSecretAckedEvent : DeRecEvent
{
    public override string EventType => "ReplicaSecretAcked";
    public required string ChannelId { get; init; }
    public required string FromReplicaId { get; init; }
    public required string SecretId { get; init; }
    public required uint Version { get; init; }
    public required int Status { get; init; }
    public required string Memo { get; init; }
}

public sealed record ChannelInfoUpdatedEvent : DeRecEvent
{
    public override string EventType => "ChannelInfoUpdated";
    public required string ChannelId { get; init; }
}

public sealed record ChannelInfoUpdateRejectedEvent : DeRecEvent
{
    public override string EventType => "ChannelInfoUpdateRejected";
    public required string ChannelId { get; init; }
    public required int Status { get; init; }
    public required string Memo { get; init; }
}

public sealed record NoOpEvent : DeRecEvent
{
    public override string EventType => "NoOp";
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
    public required string ChannelId { get; init; }
    public required Pairing.SenderKind Kind { get; init; }
}

public sealed record DiscoveryStartedEvent : DeRecEvent
{
    public override string EventType => "DiscoveryStarted";
    public required string ChannelId { get; init; }
}

public sealed record DiscoveryFailedEvent : DeRecEvent
{
    public override string EventType => "DiscoveryFailed";
    public required string ChannelId { get; init; }
    public required string Error { get; init; }
}

public sealed record ProtectSecretStartedEvent : DeRecEvent
{
    public override string EventType => "ProtectSecretStarted";
    public required string ChannelId { get; init; }
    public required uint Version { get; init; }
}

public sealed record ProtectSecretFailedEvent : DeRecEvent
{
    public override string EventType => "ProtectSecretFailed";
    public required string ChannelId { get; init; }
    public required uint Version { get; init; }
    public required string Error { get; init; }
}

public sealed record VerifySharesStartedEvent : DeRecEvent
{
    public override string EventType => "VerifySharesStarted";
    public required string ChannelId { get; init; }
    public required uint Version { get; init; }
}

public sealed record VerifySharesFailedEvent : DeRecEvent
{
    public override string EventType => "VerifySharesFailed";
    public required string ChannelId { get; init; }
    public required uint Version { get; init; }
    public required string Error { get; init; }
}

public sealed record RecoverSecretStartedEvent : DeRecEvent
{
    public override string EventType => "RecoverSecretStarted";
    public required string ChannelId { get; init; }
    public required uint Version { get; init; }
}

public sealed record RecoverSecretFailedEvent : DeRecEvent
{
    public override string EventType => "RecoverSecretFailed";
    public required string ChannelId { get; init; }
    public required uint Version { get; init; }
    public required string Error { get; init; }
}

public sealed record UnpairFailedEvent : DeRecEvent
{
    public override string EventType => "UnpairFailed";
    public required string ChannelId { get; init; }
    public required string Error { get; init; }
}

public sealed record UnpairStartedEvent : DeRecEvent
{
    public override string EventType => "UnpairStarted";
    public required string ChannelId { get; init; }
}

public sealed record UpdateChannelInfoStartedEvent : DeRecEvent
{
    public override string EventType => "UpdateChannelInfoStarted";
    public required string ChannelId { get; init; }
}

public sealed record UpdateChannelInfoFailedEvent : DeRecEvent
{
    public override string EventType => "UpdateChannelInfoFailed";
    public required string ChannelId { get; init; }
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
    public required string ChannelId { get; init; }
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
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
            },
            "ShareConfirmed" => new ShareConfirmedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
            },
            "ShareRejected" => new ShareRejectedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
                Status = root.GetProperty("status").GetInt32(),
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
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
            },
            "SecretsDiscovered" => ParseSecretsDiscovered(root),
            "RecoveryShareReceived" => new RecoveryShareReceivedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                SharesReceived = root.GetProperty("shares_received").GetUInt32(),
            },
            "RecoveryShareError" => new RecoveryShareErrorEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                SharesReceived = root.GetProperty("shares_received").GetUInt32(),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "SecretRecovered" => new SecretRecoveredEvent
            {
                Secret = ParseSecretObject(root.GetProperty("secret")),
            },
            "Unpaired" => new UnpairedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
            },
            "UnpairRejected" => new UnpairRejectedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Status = root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "PrePairRejected" => new PrePairRejectedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Status = root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "ReplicaSecretReceived" => ParseReplicaSecretReceived(root),
            "ReplicaSecretInstalled" => ParseReplicaSecretInstalled(root),
            "ReplicaSyncRejected" => new ReplicaSyncRejectedEvent
            {
                ReplicaId = root.GetProperty("replica_id").GetString()!,
                SecretId = root.GetProperty("secret_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
                Status = root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString()!,
            },
            "ReplicaSyncFailed" => new ReplicaSyncFailedEvent
            {
                ReplicaId = root.GetProperty("replica_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
                Reason = root.GetProperty("reason").GetString()!,
            },
            "ReplicaRemoved" => new ReplicaRemovedEvent
            {
                ReplicaId = root.GetProperty("replica_id").GetString()!,
            },
            "ReplicaSourceChanged" => new ReplicaSourceChangedEvent
            {
                ReplicaId = root.GetProperty("replica_id").GetString()!,
            },
            "SelfRemovedFromGroup" => new SelfRemovedFromGroupEvent
            {
                Version = root.GetProperty("version").GetUInt32(),
            },
            "SyncCheckComplete" => new SyncCheckCompleteEvent
            {
                LocalVersion = root.GetProperty("local_version").GetUInt32(),
                GroupVersion = root.GetProperty("group_version").GetUInt32(),
                FetchedFrom = root.TryGetProperty("fetched_from", out var ff)
                    ? ff.GetString()
                    : null,
            },
            "ReplicaSyncComplete" => new ReplicaSyncCompleteEvent
            {
                Version = root.GetProperty("version").GetUInt32(),
                Synced = ReadStringList(root.GetProperty("synced")),
                Behind = ReadStringList(root.GetProperty("behind")),
            },
            "ReplicaSecretAcked" => new ReplicaSecretAckedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                FromReplicaId = root.GetProperty("from_replica_id").GetString()!,
                SecretId = root.GetProperty("secret_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
                Status = root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "ChannelInfoUpdated" => new ChannelInfoUpdatedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
            },
            "ChannelInfoUpdateRejected" => new ChannelInfoUpdateRejectedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Status = root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "AutoAccepted" => new AutoAcceptedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                ActionKind = root.GetProperty("action_kind").GetString() ?? string.Empty,
            },
            "NoOp" => new NoOpEvent(),
            "PairingStarted" => new PairingStartedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Kind = (Pairing.SenderKind)root.GetProperty("kind").GetInt32(),
            },
            "DiscoveryStarted" => new DiscoveryStartedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
            },
            "DiscoveryFailed" => new DiscoveryFailedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "ProtectSecretStarted" => new ProtectSecretStartedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
            },
            "ProtectSecretFailed" => new ProtectSecretFailedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "VerifySharesStarted" => new VerifySharesStartedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
            },
            "VerifySharesFailed" => new VerifySharesFailedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "RecoverSecretStarted" => new RecoverSecretStartedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
            },
            "RecoverSecretFailed" => new RecoverSecretFailedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "UnpairFailed" => new UnpairFailedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Error = root.GetProperty("error").GetString() ?? string.Empty,
            },
            "UnpairStarted" => new UnpairStartedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
            },
            "UpdateChannelInfoStarted" => new UpdateChannelInfoStartedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
            },
            "UpdateChannelInfoFailed" => new UpdateChannelInfoFailedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
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

    private static List<string> ReadStringList(System.Text.Json.JsonElement el)
    {
        var out_ = new List<string>(el.GetArrayLength());
        foreach (var item in el.EnumerateArray()) out_.Add(item.GetString()!);
        return out_;
    }

    /// <summary>
    /// Reads a member's <c>transports</c> array. Absent on a payload written
    /// before the list existed, where the single endpoint was recorded under
    /// <c>transport_uri</c> with no protocol discriminant — read as HTTPS,
    /// which is the only protocol those payloads could carry.
    /// </summary>
    private static IReadOnlyList<TransportProtocol> ReadEndpoints(System.Text.Json.JsonElement member)
    {
        if (member.TryGetProperty("transports", out var transports)
            && transports.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            var endpoints = new List<TransportProtocol>();
            foreach (var t in transports.EnumerateArray())
            {
                endpoints.Add(new TransportProtocol(
                    t.GetProperty("uri").GetString()!,
                    (Protocol)(t.TryGetProperty("protocol", out var p) ? p.GetInt32() : 0)));
            }
            return endpoints;
        }
        if (member.TryGetProperty("transport_uri", out var legacy)
            && legacy.ValueKind == System.Text.Json.JsonValueKind.String)
        {
            return new[] { new TransportProtocol(legacy.GetString()!) };
        }
        return Array.Empty<TransportProtocol>();
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
                    s.GetProperty("secret_id").GetString()!,
                    versions));
            }
        }
        return new SecretsDiscoveredEvent
        {
            ChannelId = root.GetProperty("channel_id").GetString()!,
            Secrets = secrets,
        };
    }

    /// <summary>
    /// Parse the nested <c>secret</c> JSON object common to
    /// <see cref="ReplicaSecretReceivedEvent"/> and
    /// <see cref="SecretRecoveredEvent"/>. Both events expose the
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
                h.GetProperty("channel_id").GetString()!,
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
                    r.GetProperty("replica_id").GetString()!,
                    ReadEndpoints(r),
                    r.GetProperty("role").GetString()!,
                    r.TryGetProperty("communication_info", out var rci) ? ReadStringMap(rci) : new()));
            }
            var sharedKey = replicasEl.TryGetProperty("shared_key", out var sk)
                ? ReadByteArray(sk)
                : Array.Empty<byte>();
            replicas = new Replicas(
                replicasEl.GetProperty("channel_id").GetString()!,
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
                s.GetProperty("channel_id").GetString()!,
                ReadByteArray(s.GetProperty("committed_share"))));
        }

        return new ReplicaSecretReceivedEvent
        {
            ChannelId = root.GetProperty("channel_id").GetString()!,
            FromReplicaId = root.GetProperty("from_replica_id").GetString()!,
            SecretId = root.GetProperty("secret_id").GetString()!,
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
                s.GetProperty("channel_id").GetString()!,
                ReadByteArray(s.GetProperty("committed_share"))));
        }

        return new ReplicaSecretInstalledEvent
        {
            ChannelId = root.GetProperty("channel_id").GetString()!,
            FromReplicaId = root.GetProperty("from_replica_id").GetString()!,
            SecretId = root.GetProperty("secret_id").GetString()!,
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
        return new ActionRequiredEvent
        {
            ChannelId = root.GetProperty("channel_id").GetString()!,
            Action = bytes.ToArray(),
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
            ChannelId = root.GetProperty("channel_id").GetString()!,
            PairingChannelId = root.GetProperty("pairing_channel_id").GetString()!,
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
        ChannelId = root.GetProperty("channel_id").GetString()!,
        PeerReplicaId = root.GetProperty("peer_replica_id").GetString()!,
    };
}
