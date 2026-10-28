// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DeRec.Library.Orchestrator;

/// <summary>
/// Every data setting of <see cref="DeRecProtocolBuilder"/> in one
/// serializable record, mirroring the Rust <c>DeRecProtocolConfig</c> field for
/// field. Apply it with <see cref="DeRecProtocolBuilder.WithConfig"/>.
/// </summary>
/// <remarks>
/// <para>
/// Every property is optional; <c>null</c> means unset, and
/// <see cref="DeRecProtocolBuilder.WithConfig"/> leaves an unset setting
/// untouched. Layering a general config, then a per-user one, then individual
/// <c>WithX</c> calls gives last-write-wins per setting. <see cref="Timeouts"/>
/// layers per timeout: a later config that sets only one keeps the others an
/// earlier config set. Every other nested value is replaced as a whole.
/// </para>
/// <para>
/// The record reads and writes the canonical config JSON shared by every DeRec
/// SDK, so a config file or user record loads with
/// <c>JsonSerializer.Deserialize&lt;DeRecProtocolConfig&gt;(json, DeRecJsonOptions.Wire)</c>.
/// Keys are snake_case; <see cref="MaxSubshares"/> and <see cref="ReplicaId"/>
/// are decimal strings; timeouts are whole seconds under
/// <c>timeouts.inbound_message_secs</c>, <c>sharing_round_secs</c>,
/// <c>unpair_ack_secs</c> and <c>expired_channels</c>. An unknown key, at any
/// level, fails the read with a <see cref="JsonException"/> naming it, so a
/// misspelled setting is never silently dropped.
/// </para>
/// <para>
/// Nothing is validated here or in <see cref="DeRecProtocolBuilder.WithConfig"/>:
/// a value set through the record is checked by the library at
/// <see cref="DeRecProtocolBuilder.Build"/>, exactly like the same value set
/// through its <c>WithX</c> method.
/// </para>
/// </remarks>
[JsonConverter(typeof(DeRecProtocolConfigJsonConverter))]
public sealed record DeRecProtocolConfig
{
    /// <summary>See <see cref="DeRecProtocolBuilder.WithThreshold"/>.</summary>
    public int? Threshold { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithMaxSubshares"/>.</summary>
    public ulong? MaxSubshares { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithTimeouts"/>. Layers per timeout.</summary>
    public Timeouts? Timeouts { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithParameterRange"/>.</summary>
    public ParameterRange? ParameterRange { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithAutoAccept"/>.</summary>
    public AutoAcceptPolicy? AutoAccept { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithAutoRespondOnFailure"/>.</summary>
    public bool? AutoRespondOnFailure { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithAutoReplyTo"/>.</summary>
    public bool? AutoReplyTo { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithUnpairAck"/>.</summary>
    public UnpairAck? UnpairAck { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithUnsafeConnection"/>.</summary>
    public bool? UnsafeConnection { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithCommunicationInfo"/>.</summary>
    public Dictionary<string, string>? CommunicationInfo { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithOwnTransports"/>.</summary>
    public IReadOnlyList<TransportProtocol>? OwnTransports { get; init; }

    /// <summary>See <see cref="DeRecProtocolBuilder.WithReplicaId"/>.</summary>
    public ulong? ReplicaId { get; init; }
}

/// <summary>
/// Reads and writes <see cref="DeRecProtocolConfig"/> as the canonical config
/// JSON, the shape <c>DeRecProtocolConfig</c> in
/// <c>library/src/protocol/protocol_config.rs</c> defines.
/// </summary>
internal sealed class DeRecProtocolConfigJsonConverter : JsonConverter<DeRecProtocolConfig>
{
    public override DeRecProtocolConfig Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var w = JsonSerializer.Deserialize<ConfigWire>(ref reader, options)
            ?? throw new JsonException("a DeRecProtocolConfig must be a JSON object");
        return new DeRecProtocolConfig
        {
            Threshold = w.Threshold,
            MaxSubshares = ParseU64(w.MaxSubshares, "max_subshares"),
            Timeouts = w.Timeouts is null
                ? null
                : new Timeouts(
                    InboundMessage: FromSecs(w.Timeouts.InboundMessageSecs, "inbound_message_secs"),
                    SharingRound: FromSecs(w.Timeouts.SharingRoundSecs, "sharing_round_secs"),
                    UnpairAck: FromSecs(w.Timeouts.UnpairAckSecs, "unpair_ack_secs"),
                    ExpiredChannels: w.Timeouts.ExpiredChannels is null
                        ? null
                        : new RemoveExpiredChannelsPolicy(
                            w.Timeouts.ExpiredChannels.Enabled,
                            w.Timeouts.ExpiredChannels.TimeoutInSecs)),
            ParameterRange = w.ParameterRange is null
                ? null
                : new ParameterRange
                {
                    MinShareSize = w.ParameterRange.MinShareSize,
                    MaxShareSize = w.ParameterRange.MaxShareSize,
                    MinTimeBetweenVerifications = w.ParameterRange.MinTimeBetweenVerifications,
                    MaxTimeBetweenVerifications = w.ParameterRange.MaxTimeBetweenVerifications,
                    MinTimeBetweenShareUpdates = w.ParameterRange.MinTimeBetweenShareUpdates,
                    MaxTimeBetweenShareUpdates = w.ParameterRange.MaxTimeBetweenShareUpdates,
                    MinUnresponsiveDeletionTimeout = w.ParameterRange.MinUnresponsiveDeletionTimeout,
                    MaxUnresponsiveDeletionTimeout = w.ParameterRange.MaxUnresponsiveDeletionTimeout,
                    MinUnresponsiveDeactivationTimeout = w.ParameterRange.MinUnresponsiveDeactivationTimeout,
                    MaxUnresponsiveDeactivationTimeout = w.ParameterRange.MaxUnresponsiveDeactivationTimeout,
                },
            AutoAccept = w.AutoAccept is null
                ? null
                : new AutoAcceptPolicy
                {
                    Pairing = w.AutoAccept.Pairing,
                    PrePair = w.AutoAccept.PrePair,
                    StoreShare = w.AutoAccept.StoreShare,
                    VerifyShare = w.AutoAccept.VerifyShare,
                    Discovery = w.AutoAccept.Discovery,
                    GetShare = w.AutoAccept.GetShare,
                    Unpair = w.AutoAccept.Unpair,
                    UpdateChannelInfo = w.AutoAccept.UpdateChannelInfo,
                },
            AutoRespondOnFailure = w.AutoRespondOnFailure,
            AutoReplyTo = w.AutoReplyTo,
            UnpairAck = w.UnpairAck,
            UnsafeConnection = w.UnsafeConnection,
            CommunicationInfo = w.CommunicationInfo,
            OwnTransports = w.OwnTransports?.Select(t => new TransportProtocol(t.Uri, t.Protocol)).ToList(),
            ReplicaId = ParseU64(w.ReplicaId, "replica_id"),
        };
    }

    public override void Write(Utf8JsonWriter writer, DeRecProtocolConfig value, JsonSerializerOptions options)
    {
        var w = new ConfigWire
        {
            Threshold = value.Threshold,
            MaxSubshares = value.MaxSubshares?.ToString(CultureInfo.InvariantCulture),
            Timeouts = value.Timeouts is null
                ? null
                : new TimeoutsWire
                {
                    InboundMessageSecs = value.Timeouts.InboundMessage?.TotalSeconds,
                    SharingRoundSecs = value.Timeouts.SharingRound?.TotalSeconds,
                    UnpairAckSecs = value.Timeouts.UnpairAck?.TotalSeconds,
                    ExpiredChannels = value.Timeouts.ExpiredChannels is null
                        ? null
                        : new ExpiredChannelsWire
                        {
                            Enabled = value.Timeouts.ExpiredChannels.Enabled,
                            TimeoutInSecs = value.Timeouts.ExpiredChannels.TimeoutInSecs,
                        },
                },
            ParameterRange = value.ParameterRange is null
                ? null
                : new ParameterRangeWire
                {
                    MinShareSize = value.ParameterRange.MinShareSize,
                    MaxShareSize = value.ParameterRange.MaxShareSize,
                    MinTimeBetweenVerifications = value.ParameterRange.MinTimeBetweenVerifications,
                    MaxTimeBetweenVerifications = value.ParameterRange.MaxTimeBetweenVerifications,
                    MinTimeBetweenShareUpdates = value.ParameterRange.MinTimeBetweenShareUpdates,
                    MaxTimeBetweenShareUpdates = value.ParameterRange.MaxTimeBetweenShareUpdates,
                    MinUnresponsiveDeletionTimeout = value.ParameterRange.MinUnresponsiveDeletionTimeout,
                    MaxUnresponsiveDeletionTimeout = value.ParameterRange.MaxUnresponsiveDeletionTimeout,
                    MinUnresponsiveDeactivationTimeout = value.ParameterRange.MinUnresponsiveDeactivationTimeout,
                    MaxUnresponsiveDeactivationTimeout = value.ParameterRange.MaxUnresponsiveDeactivationTimeout,
                },
            AutoAccept = value.AutoAccept is null
                ? null
                : new AutoAcceptWire
                {
                    Pairing = value.AutoAccept.Pairing,
                    PrePair = value.AutoAccept.PrePair,
                    StoreShare = value.AutoAccept.StoreShare,
                    VerifyShare = value.AutoAccept.VerifyShare,
                    Discovery = value.AutoAccept.Discovery,
                    GetShare = value.AutoAccept.GetShare,
                    Unpair = value.AutoAccept.Unpair,
                    UpdateChannelInfo = value.AutoAccept.UpdateChannelInfo,
                },
            AutoRespondOnFailure = value.AutoRespondOnFailure,
            AutoReplyTo = value.AutoReplyTo,
            UnpairAck = value.UnpairAck,
            UnsafeConnection = value.UnsafeConnection,
            CommunicationInfo = value.CommunicationInfo,
            // Order is preserved verbatim: it is this node's preference order.
            OwnTransports = value.OwnTransports?.Select(t => new TransportWire { Uri = t.Uri, Protocol = t.Protocol }).ToList(),
            ReplicaId = value.ReplicaId?.ToString(CultureInfo.InvariantCulture),
        };
        JsonSerializer.Serialize(writer, w, options);
    }

    // A u64 travels as a decimal string so values above 2^53 survive JSON
    // number handling; a bare number is refused by the string-typed wire
    // property, as the library refuses it.
    private static ulong? ParseU64(string? value, string key) =>
        value is null
            ? null
            : ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ulong parsed)
                ? parsed
                : throw new JsonException($"{key} is not a decimal u64: \"{value}\"");

    // Seconds are carried as given; the library accepts only a whole,
    // non-negative number of seconds and refuses anything else. A value
    // outside the range a `TimeSpan` can represent throws
    // `OverflowException` from `TimeSpan.FromSeconds`; read errors are
    // reported as `JsonException` throughout this converter, so that is
    // caught and re-thrown as one.
    private static TimeSpan? FromSecs(double? secs, string key)
    {
        if (secs is not double s)
        {
            return null;
        }
        try
        {
            return TimeSpan.FromSeconds(s);
        }
        catch (OverflowException)
        {
            throw new JsonException($"{key} is out of range: {s}");
        }
    }

    private sealed class SnakeCaseEnumConverter : JsonStringEnumConverter
    {
        public SnakeCaseEnumConverter() : base(JsonNamingPolicy.SnakeCaseLower) { }
    }

    // `unpair_ack` is written as its name, or as its number when it has none,
    // for the library to refuse. It is read from exactly the names the library
    // takes, "required" and "not_required", or from a number.
    private sealed class UnpairAckConverter : JsonConverter<UnpairAck?>
    {
        public override UnpairAck? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            reader.TokenType switch
            {
                JsonTokenType.Number when reader.TryGetInt32(out int code) => (UnpairAck)code,
                JsonTokenType.String => reader.GetString() switch
                {
                    "required" => UnpairAck.Required,
                    "not_required" => UnpairAck.NotRequired,
                    var name => throw new JsonException($"invalid unpair_ack: \"{name}\""),
                },
                _ => throw new JsonException("unpair_ack must be \"required\", \"not_required\" or a number"),
            };

        public override void Write(Utf8JsonWriter writer, UnpairAck? value, JsonSerializerOptions options)
        {
            switch (value)
            {
                case UnpairAck.Required: writer.WriteStringValue("required"); break;
                case UnpairAck.NotRequired: writer.WriteStringValue("not_required"); break;
                case { } other: writer.WriteNumberValue((int)other); break;
                default: writer.WriteNullValue(); break;
            }
        }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed class ConfigWire
    {
        [JsonPropertyName("threshold"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public int? Threshold { get; init; }

        [JsonPropertyName("max_subshares"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? MaxSubshares { get; init; }

        [JsonPropertyName("timeouts"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public TimeoutsWire? Timeouts { get; init; }

        [JsonPropertyName("parameter_range"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public ParameterRangeWire? ParameterRange { get; init; }

        [JsonPropertyName("auto_accept"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public AutoAcceptWire? AutoAccept { get; init; }

        [JsonPropertyName("auto_respond_on_failure"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public bool? AutoRespondOnFailure { get; init; }

        [JsonPropertyName("auto_reply_to"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public bool? AutoReplyTo { get; init; }

        [JsonPropertyName("unpair_ack"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        [JsonConverter(typeof(UnpairAckConverter))]
        public UnpairAck? UnpairAck { get; init; }

        [JsonPropertyName("unsafe_connection"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public bool? UnsafeConnection { get; init; }

        [JsonPropertyName("communication_info"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull), OmitWhenEmpty]
        public Dictionary<string, string>? CommunicationInfo { get; init; }

        [JsonPropertyName("own_transports"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<TransportWire>? OwnTransports { get; init; }

        [JsonPropertyName("replica_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? ReplicaId { get; init; }
    }

    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed class TimeoutsWire
    {
        [JsonPropertyName("inbound_message_secs"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public double? InboundMessageSecs { get; init; }

        [JsonPropertyName("sharing_round_secs"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public double? SharingRoundSecs { get; init; }

        [JsonPropertyName("unpair_ack_secs"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public double? UnpairAckSecs { get; init; }

        [JsonPropertyName("expired_channels"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public ExpiredChannelsWire? ExpiredChannels { get; init; }
    }

    // Both fields are always written, including when Enabled is false: the
    // library decides that a disabled policy ignores its timeout.
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed class ExpiredChannelsWire
    {
        [JsonPropertyName("enabled"), JsonRequired]
        public bool Enabled { get; init; }

        [JsonPropertyName("timeout_in_secs"), JsonRequired]
        public ulong TimeoutInSecs { get; init; }
    }

    // Every bound is written; an absent bound reads as 0, which the proto
    // reads as "no constraint on this dimension". A bound may be read from a
    // decimal string, as the library reads it.
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    [JsonNumberHandling(JsonNumberHandling.AllowReadingFromString)]
    private sealed class ParameterRangeWire
    {
        [JsonPropertyName("min_share_size")] public long MinShareSize { get; init; }
        [JsonPropertyName("max_share_size")] public long MaxShareSize { get; init; }
        [JsonPropertyName("min_time_between_verifications")] public long MinTimeBetweenVerifications { get; init; }
        [JsonPropertyName("max_time_between_verifications")] public long MaxTimeBetweenVerifications { get; init; }
        [JsonPropertyName("min_time_between_share_updates")] public long MinTimeBetweenShareUpdates { get; init; }
        [JsonPropertyName("max_time_between_share_updates")] public long MaxTimeBetweenShareUpdates { get; init; }
        [JsonPropertyName("min_unresponsive_deletion_timeout")] public long MinUnresponsiveDeletionTimeout { get; init; }
        [JsonPropertyName("max_unresponsive_deletion_timeout")] public long MaxUnresponsiveDeletionTimeout { get; init; }
        [JsonPropertyName("min_unresponsive_deactivation_timeout")] public long MinUnresponsiveDeactivationTimeout { get; init; }
        [JsonPropertyName("max_unresponsive_deactivation_timeout")] public long MaxUnresponsiveDeactivationTimeout { get; init; }
    }

    // Every flow is written; an absent flow reads as false, the library's
    // default for it.
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed class AutoAcceptWire
    {
        [JsonPropertyName("pairing")] public bool Pairing { get; init; }
        [JsonPropertyName("pre_pair")] public bool PrePair { get; init; }
        [JsonPropertyName("store_share")] public bool StoreShare { get; init; }
        [JsonPropertyName("verify_share")] public bool VerifyShare { get; init; }
        [JsonPropertyName("discovery")] public bool Discovery { get; init; }
        [JsonPropertyName("get_share")] public bool GetShare { get; init; }
        [JsonPropertyName("unpair")] public bool Unpair { get; init; }
        [JsonPropertyName("update_channel_info")] public bool UpdateChannelInfo { get; init; }
    }

    // `protocol` is written as its lowercase name; a name or a numeric
    // discriminant is read. A discriminant naming no protocol is written as
    // the number, for the library to refuse.
    [JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
    private sealed class TransportWire
    {
        [JsonPropertyName("uri"), JsonRequired]
        public string Uri { get; init; } = "";

        [JsonPropertyName("protocol"), JsonRequired, JsonConverter(typeof(SnakeCaseEnumConverter))]
        public Protocol Protocol { get; init; }
    }
}
