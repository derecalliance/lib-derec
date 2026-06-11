// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

using DeRec.Library.Primitives;

namespace DeRec.Library.Orchestrator;

/// <summary>
/// Numeric flow-kind discriminator passed to
/// <see cref="DeRecProtocol.StartAsync"/>. Values MUST match the
/// Rust-side constants in <c>library/src/ffi/protocol/flow.rs</c>.
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
    public required int Kind { get; init; }

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

/// <summary>Params for <see cref="FlowKind.ProtectSecret"/>.</summary>
public sealed record ProtectSecretParams
{
    [JsonPropertyName("secret_id")] public required string SecretId { get; init; }
    [JsonPropertyName("target")] public Target? Target { get; init; }
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
    [JsonPropertyName("target")] public Target? Target { get; init; }
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
    [JsonPropertyName("transport_protocol")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public TransportProtocolDto? TransportProtocol { get; init; }

    public sealed record TransportProtocolDto
    {
        [JsonPropertyName("uri")] public required string Uri { get; init; }
        [JsonPropertyName("protocol")] public required int Protocol { get; init; }
    }
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

    public required string ChannelId { get; init; }
    public required int Kind { get; init; }
    public Dictionary<string, string> PeerCommunicationInfo { get; init; } = new();
}

/// <summary>
/// Fired alongside <see cref="PairingCompletedEvent"/> on replica-mode
/// pairings. Carries the peer's hex-encoded <c>replica_id</c>.
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

public sealed record SecretRecoveredEvent : DeRecEvent
{
    public override string EventType => "SecretRecovered";
    public required byte[] Secret { get; init; }
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
    string ChannelId,
    string TransportUri,
    byte[] SharedKey,
    Dictionary<string, string> CommunicationInfo);

public sealed record ReplicaInfo(
    string ChannelId,
    string TransportUri,
    byte[] SharedKey,
    Dictionary<string, string> CommunicationInfo,
    string ReplicaId,
    int SenderKind);

public sealed record VaultUserSecret(byte[] Id, string Name, byte[] Data);

public sealed record SecretContainer(
    IReadOnlyList<HelperInfo> Helpers,
    IReadOnlyList<VaultUserSecret> Secrets,
    IReadOnlyList<ReplicaInfo> Replicas,
    string OwnerReplicaId);

public sealed record ChannelShare(string ChannelId, byte[] CommittedShare);

public sealed record ReplicaVaultReceivedEvent : DeRecEvent
{
    public override string EventType => "ReplicaVaultReceived";
    public required string ChannelId { get; init; }
    public required string FromReplicaId { get; init; }
    public required string SecretId { get; init; }
    public required uint Version { get; init; }
    public required SecretContainer Vault { get; init; }
    public required IReadOnlyList<ChannelShare> Shares { get; init; }
}

public sealed record ReplicaVaultAckedEvent : DeRecEvent
{
    public override string EventType => "ReplicaVaultAcked";
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
    public Dictionary<string, string>? CommunicationInfo { get; init; }
    public string? TransportUri { get; init; }
    public int? TransportProtocol { get; init; }
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
                Secret = ReadByteArray(root.GetProperty("secret")),
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
            "ReplicaVaultReceived" => ParseReplicaVaultReceived(root),
            "ReplicaVaultAcked" => new ReplicaVaultAckedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                FromReplicaId = root.GetProperty("from_replica_id").GetString()!,
                SecretId = root.GetProperty("secret_id").GetString()!,
                Version = root.GetProperty("version").GetUInt32(),
                Status = root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "ChannelInfoUpdated" => ParseChannelInfoUpdated(root),
            "ChannelInfoUpdateRejected" => new ChannelInfoUpdateRejectedEvent
            {
                ChannelId = root.GetProperty("channel_id").GetString()!,
                Status = root.GetProperty("status").GetInt32(),
                Memo = root.GetProperty("memo").GetString() ?? string.Empty,
            },
            "NoOp" => new NoOpEvent(),
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

    private static ChannelInfoUpdatedEvent ParseChannelInfoUpdated(System.Text.Json.JsonElement root)
    {
        Dictionary<string, string>? info = null;
        if (root.TryGetProperty("communication_info", out var ci))
            info = ReadStringMap(ci);
        string? uri = root.TryGetProperty("transport_uri", out var tu) ? tu.GetString() : null;
        int? proto = root.TryGetProperty("transport_protocol", out var tp) ? tp.GetInt32() : null;
        return new ChannelInfoUpdatedEvent
        {
            ChannelId = root.GetProperty("channel_id").GetString()!,
            CommunicationInfo = info,
            TransportUri = uri,
            TransportProtocol = proto,
        };
    }

    private static ReplicaVaultReceivedEvent ParseReplicaVaultReceived(System.Text.Json.JsonElement root)
    {
        var vault = root.GetProperty("vault");
        var helpers = new List<HelperInfo>();
        foreach (var h in vault.GetProperty("helpers").EnumerateArray())
        {
            helpers.Add(new HelperInfo(
                h.GetProperty("channel_id").GetString()!,
                h.GetProperty("transport_uri").GetString()!,
                ReadByteArray(h.GetProperty("shared_key")),
                h.TryGetProperty("communication_info", out var hci) ? ReadStringMap(hci) : new()));
        }
        var secrets = new List<VaultUserSecret>();
        foreach (var s in vault.GetProperty("secrets").EnumerateArray())
        {
            secrets.Add(new VaultUserSecret(
                ReadByteArray(s.GetProperty("id")),
                s.GetProperty("name").GetString()!,
                ReadByteArray(s.GetProperty("data"))));
        }
        var replicas = new List<ReplicaInfo>();
        foreach (var r in vault.GetProperty("replicas").EnumerateArray())
        {
            replicas.Add(new ReplicaInfo(
                r.GetProperty("channel_id").GetString()!,
                r.GetProperty("transport_uri").GetString()!,
                ReadByteArray(r.GetProperty("shared_key")),
                r.TryGetProperty("communication_info", out var rci) ? ReadStringMap(rci) : new(),
                r.GetProperty("replica_id").GetString()!,
                r.GetProperty("sender_kind").GetInt32()));
        }
        var container = new SecretContainer(
            helpers, secrets, replicas,
            vault.GetProperty("owner_replica_id").GetString()!);

        var shares = new List<ChannelShare>();
        foreach (var s in root.GetProperty("shares").EnumerateArray())
        {
            shares.Add(new ChannelShare(
                s.GetProperty("channel_id").GetString()!,
                ReadByteArray(s.GetProperty("committed_share"))));
        }

        return new ReplicaVaultReceivedEvent
        {
            ChannelId = root.GetProperty("channel_id").GetString()!,
            FromReplicaId = root.GetProperty("from_replica_id").GetString()!,
            SecretId = root.GetProperty("secret_id").GetString()!,
            Version = root.GetProperty("version").GetUInt32(),
            Vault = container,
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
            Kind = root.GetProperty("kind").GetInt32(),
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
