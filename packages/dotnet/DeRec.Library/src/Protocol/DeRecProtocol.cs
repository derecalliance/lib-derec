// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

using DeRec.Library.Native;
using NP = DeRec.Library.Native.Protocol;
using LibPairing = DeRec.Library.Primitives.Pairing;

namespace DeRec.Library.Orchestrator;

/// <summary>
/// Managed wrapper around the FFI <c>DeRecProtocol</c> handle. Each
/// instance owns an opaque pointer + a set of pinned managed delegates
/// that satisfy the store/transport trait callbacks on the Rust side.
///
/// Not thread-safe — callers MUST NOT invoke multiple methods on the
/// same instance concurrently.
/// </summary>
public sealed class DeRecProtocol : IDisposable
{
    private IntPtr _handle;

    // GC roots for managed delegates — must outlive the handle.
    // ReSharper disable NotAccessedField.Local
    private readonly NP.ChannelStoreLoadDelegate _channelLoad;
    private readonly NP.ChannelStoreSaveDelegate _channelSave;
    private readonly NP.ChannelStoreRemoveDelegate _channelRemove;
    private readonly NP.ChannelStoreListDelegate _channelListHelpers;
    private readonly NP.ChannelStoreListDelegate _channelListReplicas;
    private readonly NP.ChannelStoreLinkDelegate _channelLink;
    private readonly NP.ChannelStoreLinkedDelegate _channelLinked;
    private readonly NP.FreeBufferDelegate _channelFreeBuffer;
    private readonly NP.SecretStoreLoadDelegate _secretLoad;
    private readonly NP.SecretStoreSaveDelegate _secretSave;
    private readonly NP.SecretStoreRemoveDelegate _secretRemove;
    private readonly NP.FreeBufferDelegate _secretFreeBuffer;
    private readonly NP.ShareStoreLoadDelegate _shareLoad;
    private readonly NP.ShareStoreLoadManyDelegate _shareLoadMany;
    private readonly NP.ShareStoreLoadAllDelegate _shareLoadAll;
    private readonly NP.ShareStoreLatestVersionDelegate _shareLatest;
    private readonly NP.ShareStoreSaveDelegate _shareSave;
    private readonly NP.ShareStoreRemoveChannelDelegate _shareRemoveChannel;
    private readonly NP.FreeBufferDelegate _shareFreeBuffer;
    private readonly NP.UserSecretStoreLoadLatestDelegate _userSecretLoadLatest;
    private readonly NP.UserSecretStoreSaveLatestDelegate _userSecretSaveLatest;
    private readonly NP.UserSecretStoreRemoveDelegate _userSecretRemove;
    private readonly NP.FreeBufferDelegate _userSecretFreeBuffer;
    private readonly NP.StateStoreSaveDelegate _stateSave;
    private readonly NP.StateStoreLoadDelegate _stateLoad;
    private readonly NP.StateStoreRemoveDelegate _stateRemove;
    private readonly NP.StateStoreLoadAllDelegate _stateLoadAll;
    private readonly NP.FreeBufferDelegate _stateFreeBuffer;
    private readonly NP.TransportSendDelegate _transportSend;
    // ReSharper restore NotAccessedField.Local

    // Strong refs so the store/transport interfaces outlive any callback.
    private readonly IChannelStore _channelStore;
    private readonly ISecretStore _secretStore;
    // ReSharper disable PrivateFieldCanBeConvertedToLocalVariable
    private readonly IShareStore _shareStore;
    private readonly IUserSecretStore _userSecretStore;
    private readonly IStateStore _stateStore;
    private readonly ITransport _transport;
    // ReSharper restore PrivateFieldCanBeConvertedToLocalVariable

    private static JsonSerializerOptions JsonOpts => DeRecJsonOptions.Wire;

    /// <summary>
    /// Identifier of the single secret this protocol instance manages.
    /// Set at construction via <see cref="DeRecProtocolBuilder"/>.
    /// </summary>
    public ulong SecretId { get; }

    /// <summary>
    /// Construct a protocol instance. Internal — callers go through
    /// <see cref="DeRecProtocolBuilder"/> so the surface stays in step
    /// with the Rust / JS SDK builders.
    /// </summary>
    internal DeRecProtocol(
        ulong secretId,
        IChannelStore channelStore,
        IShareStore shareStore,
        ISecretStore secretStore,
        IUserSecretStore userSecretStore,
        IStateStore stateStore,
        ITransport transport,
        string ownTransportUri,
        string ownTransportProtocol = "https",
        int threshold = 3,
        int keepVersionsCount = 3,
        Dictionary<string, string>? communicationInfo = null,
        bool autoRespondOnFailure = false,
        UnpairAck unpairAck = UnpairAck.Required,
        bool autoReplyTo = false,
        AutoAcceptPolicy? autoAccept = null,
        ulong? replicaId = null,
        Timeouts? timeouts = null)
    {
        SecretId = secretId;
        _channelStore = channelStore;
        _shareStore = shareStore;
        _secretStore = secretStore;
        _userSecretStore = userSecretStore;
        _stateStore = stateStore;
        _transport = transport;

        _channelLoad = ChannelLoadImpl;
        _channelSave = ChannelSaveImpl;
        _channelRemove = ChannelRemoveImpl;
        _channelListHelpers = ChannelListHelpersImpl;
        _channelListReplicas = ChannelListReplicasImpl;
        _channelLink = ChannelLinkImpl;
        _channelLinked = ChannelLinkedImpl;
        _channelFreeBuffer = FreeBufferImpl;

        _secretLoad = SecretLoadImpl;
        _secretSave = SecretSaveImpl;
        _secretRemove = SecretRemoveImpl;
        _secretFreeBuffer = FreeBufferImpl;

        _shareLoad = ShareLoadImpl;
        _shareLoadMany = ShareLoadManyImpl;
        _shareLoadAll = ShareLoadAllImpl;
        _shareLatest = ShareLatestVersionImpl;
        _shareSave = ShareSaveImpl;
        _shareRemoveChannel = ShareRemoveChannelImpl;
        _shareFreeBuffer = FreeBufferImpl;

        _userSecretLoadLatest = UserSecretLoadLatestImpl;
        _userSecretSaveLatest = UserSecretSaveLatestImpl;
        _userSecretRemove = UserSecretRemoveImpl;
        _userSecretFreeBuffer = FreeBufferImpl;

        _stateSave = StateSaveImpl;
        _stateLoad = StateLoadImpl;
        _stateRemove = StateRemoveImpl;
        _stateLoadAll = StateLoadAllImpl;
        _stateFreeBuffer = FreeBufferImpl;

        _transportSend = TransportSendImpl;

        var channelCb = new NP.ChannelStoreCallbacks
        {
            UserData = IntPtr.Zero,
            Load = Marshal.GetFunctionPointerForDelegate(_channelLoad),
            Save = Marshal.GetFunctionPointerForDelegate(_channelSave),
            Remove = Marshal.GetFunctionPointerForDelegate(_channelRemove),
            ListHelpers = Marshal.GetFunctionPointerForDelegate(_channelListHelpers),
            ListReplicas = Marshal.GetFunctionPointerForDelegate(_channelListReplicas),
            LinkChannel = Marshal.GetFunctionPointerForDelegate(_channelLink),
            LinkedChannels = Marshal.GetFunctionPointerForDelegate(_channelLinked),
            FreeBuffer = Marshal.GetFunctionPointerForDelegate(_channelFreeBuffer),
        };
        var secretCb = new NP.SecretStoreCallbacks
        {
            UserData = IntPtr.Zero,
            Load = Marshal.GetFunctionPointerForDelegate(_secretLoad),
            Save = Marshal.GetFunctionPointerForDelegate(_secretSave),
            Remove = Marshal.GetFunctionPointerForDelegate(_secretRemove),
            FreeBuffer = Marshal.GetFunctionPointerForDelegate(_secretFreeBuffer),
        };
        var shareCb = new NP.ShareStoreCallbacks
        {
            UserData = IntPtr.Zero,
            Load = Marshal.GetFunctionPointerForDelegate(_shareLoad),
            LoadMany = Marshal.GetFunctionPointerForDelegate(_shareLoadMany),
            LoadAll = Marshal.GetFunctionPointerForDelegate(_shareLoadAll),
            LatestVersion = Marshal.GetFunctionPointerForDelegate(_shareLatest),
            Save = Marshal.GetFunctionPointerForDelegate(_shareSave),
            RemoveChannel = Marshal.GetFunctionPointerForDelegate(_shareRemoveChannel),
            FreeBuffer = Marshal.GetFunctionPointerForDelegate(_shareFreeBuffer),
        };
        var userSecretCb = new NP.UserSecretStoreCallbacks
        {
            UserData = IntPtr.Zero,
            LoadLatest = Marshal.GetFunctionPointerForDelegate(_userSecretLoadLatest),
            SaveLatest = Marshal.GetFunctionPointerForDelegate(_userSecretSaveLatest),
            Remove = Marshal.GetFunctionPointerForDelegate(_userSecretRemove),
            FreeBuffer = Marshal.GetFunctionPointerForDelegate(_userSecretFreeBuffer),
        };
        var stateCb = new NP.StateStoreCallbacks
        {
            UserData = IntPtr.Zero,
            Save = Marshal.GetFunctionPointerForDelegate(_stateSave),
            Load = Marshal.GetFunctionPointerForDelegate(_stateLoad),
            Remove = Marshal.GetFunctionPointerForDelegate(_stateRemove),
            LoadAll = Marshal.GetFunctionPointerForDelegate(_stateLoadAll),
            FreeBuffer = Marshal.GetFunctionPointerForDelegate(_stateFreeBuffer),
        };
        var transportCb = new NP.TransportCallbacks
        {
            UserData = IntPtr.Zero,
            Send = Marshal.GetFunctionPointerForDelegate(_transportSend),
        };

        int ownProtocolNum = ownTransportProtocol.ToLowerInvariant() switch
        {
            "https" => 0,
            _ => throw new ArgumentException($"unknown protocol: {ownTransportProtocol}", nameof(ownTransportProtocol)),
        };

        byte[]? commInfoBytes = null;
        UIntPtr commInfoLen = UIntPtr.Zero;

        var policy = autoAccept ?? new AutoAcceptPolicy();
        var config = new ProtocolConfigDto(
            SecretId: secretId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            OwnTransportUri: ownTransportUri,
            OwnTransportProtocol: ownProtocolNum,
            Threshold: (uint)threshold,
            KeepVersionsCount: (uint)keepVersionsCount,
            AutoRespondOnFailure: autoRespondOnFailure,
            UnpairAck: (int)unpairAck,
            AutoReplyTo: autoReplyTo,
            AutoAccept: new AutoAcceptConfigDto(
                Pairing: policy.Pairing,
                PrePair: policy.PrePair,
                StoreShare: policy.StoreShare,
                VerifyShare: policy.VerifyShare,
                Discovery: policy.Discovery,
                GetShare: policy.GetShare,
                Unpair: policy.Unpair,
                UpdateChannelInfo: policy.UpdateChannelInfo),
            Timeouts: timeouts is null
                ? null
                : new TimeoutsConfigDto(
                    InboundMessageSecs: ToSecs(timeouts.InboundMessage),
                    SharingRoundSecs: ToSecs(timeouts.SharingRound),
                    UnpairAckSecs: ToSecs(timeouts.UnpairAck),
                    ExpiredChannels: timeouts.ExpiredChannels is null
                        ? null
                        : new RemoveExpiredChannelsConfigDto(
                            Enabled: timeouts.ExpiredChannels.Enabled,
                            TimeoutInSecs: timeouts.ExpiredChannels.TimeoutInSecs)),
            ReplicaId: replicaId?.ToString(System.Globalization.CultureInfo.InvariantCulture));
        byte[] configJsonBytes = JsonSerializer.SerializeToUtf8Bytes(config, JsonOpts);

        var result = NP.derec_protocol_new(
            configJsonBytes, (UIntPtr)configJsonBytes.Length,
            commInfoBytes, commInfoLen,
            ref channelCb, ref secretCb, ref shareCb, ref userSecretCb, ref stateCb, ref transportCb);

        ThrowOnError(result.Error);
        _handle = result.Handle;
        if (_handle == IntPtr.Zero)
            throw new InvalidOperationException("derec_protocol_new returned a null handle without error.");
    }

    /// <summary>
    /// Derive the human-readable fingerprint for a paired channel — see
    /// <see cref="DeRecProtocol"/> on the Rust side for the canonical
    /// docs. Both sides of a replica pair derive the same fingerprint
    /// from the shared key.
    /// </summary>
    public Task<string> GetFingerprintAsync(ulong channelId)
    {
        EnsureNotDisposed();
        return Task.Run(() =>
        {
            var result = NP.derec_protocol_get_fingerprint(_handle, channelId);
            try
            {
                ThrowOnError(result.Error);
                if (result.Fingerprint == IntPtr.Zero)
                    throw new InvalidOperationException("get_fingerprint returned null without an error.");
                return Marshal.PtrToStringUTF8(result.Fingerprint)
                    ?? throw new InvalidOperationException("get_fingerprint returned an invalid UTF-8 string.");
            }
            finally
            {
                if (result.Fingerprint != IntPtr.Zero)
                    DeRec.Library.Native.Utils.derec_free_string(result.Fingerprint);
            }
        });
    }

    /// <summary>
    /// Verify <paramref name="fingerprint"/> against the locally-derived
    /// one. On match, transitions the channel from <c>Pending</c> to
    /// <c>Paired</c>. Returns <c>true</c> on match, <c>false</c> on
    /// mismatch.
    /// </summary>
    public Task<bool> VerifyFingerprintAsync(ulong channelId, string fingerprint)
    {
        EnsureNotDisposed();
        byte[] fpBytes = Encoding.UTF8.GetBytes(fingerprint + '\0');
        return Task.Run(() =>
        {
            var err = NP.derec_protocol_verify_fingerprint(_handle, channelId, fpBytes, out uint matched);
            ThrowOnError(err);
            return matched != 0;
        });
    }

    /// <summary>
    /// Remove <c>Pending</c> channels older than <paramref name="olderThanSecs"/>,
    /// along with their pairing keys, and return the ids removed.
    /// </summary>
    /// <remarks>
    /// Independent of the cleanup policy the protocol was constructed with —
    /// this sweeps at the threshold given even when that policy is disabled.
    /// The age comparison is strict, so a channel created within the current
    /// second survives even <c>0</c>.
    /// </remarks>
    public Task<IReadOnlyList<ulong>> RemoveExpiredChannelsAsync(ulong olderThanSecs)
    {
        EnsureNotDisposed();
        return Task.Run<IReadOnlyList<ulong>>(() =>
        {
            var result = NP.derec_protocol_remove_expired_channels(_handle, olderThanSecs);
            try
            {
                ThrowOnError(result.Error);
                byte[] json = DeRec.Library.Utils.CopyBuffer(result.Channels);
                var ids = JsonSerializer.Deserialize<List<string>>(json, JsonOpts)
                    ?? new List<string>();
                return ids.ConvertAll(id =>
                    ulong.Parse(id, System.Globalization.CultureInfo.InvariantCulture));
            }
            finally
            {
                DeRec.Library.Utils.FreeBuffer(result.Channels);
            }
        });
    }

    /// <summary>
    /// Generate an out-of-band contact message used to bootstrap pairing.
    /// Single entry point for all three <see cref="ContactMode"/> variants.
    /// </summary>
    /// <param name="channelId"><c>null</c> lets the library mint a random id;
    /// otherwise the supplied value is used verbatim.</param>
    /// <param name="contactMode">Mode-selects how the initiator's public
    /// pairing material is delivered.</param>
    /// <param name="nonce"><c>null</c> lets the library generate a fresh
    /// cryptographically-random <c>ulong</c>. Required for
    /// <see cref="ContactMode.NoKeys"/> where callers typically pick a small
    /// human-typable value; also valid on the other modes if the app wants
    /// deterministic control.</param>
    public Task<byte[]> CreateContactAsync(
        ulong? channelId,
        ContactMode contactMode,
        ulong? nonce = null)
    {
        EnsureNotDisposed();
        uint has = channelId.HasValue ? 1u : 0u;
        ulong id = channelId ?? 0ul;
        uint hasNonce = nonce.HasValue ? 1u : 0u;
        ulong nonceValue = nonce ?? 0ul;
        return Task.Run(() =>
        {
            var result = NP.derec_protocol_create_contact(
                _handle,
                has,
                id,
                (int)contactMode,
                hasNonce,
                nonceValue);
            try
            {
                ThrowOnError(result.Error);
                return DeRec.Library.Utils.CopyBuffer(result.ContactWireBytes);
            }
            finally
            {
                DeRec.Library.Utils.FreeBuffer(result.ContactWireBytes);
            }
        });
    }

    /// <summary>
    /// Kick off a new flow. Returns the per-target
    /// <c>*Started</c> / <c>*Failed</c> events describing what was
    /// dispatched — for <see cref="FlowKind.Pairing"/> a single
    /// <see cref="PairingStartedEvent"/> (its <c>ChannelId</c> is the
    /// freshly minted long-term id); for fan-out flows one event per
    /// targeted channel.
    /// </summary>
    public Task<IReadOnlyList<DeRecEvent>> StartAsync(FlowKind flowKind, object @params)
    {
        EnsureNotDisposed();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(@params, JsonOpts);
        return Task.Run<IReadOnlyList<DeRecEvent>>(() =>
        {
            var result = NP.derec_protocol_start(_handle, (uint)flowKind, json, (UIntPtr)json.Length);
            try
            {
                ThrowOnError(result.Error);
                byte[] eventsJson = DeRec.Library.Utils.CopyBuffer(result.EventsJson);
                return JsonSerializer.Deserialize<List<DeRecEvent>>(eventsJson, JsonOpts)
                    ?? new List<DeRecEvent>();
            }
            finally
            {
                DeRec.Library.Utils.FreeBuffer(result.EventsJson);
            }
        });
    }

    /// <summary>
    /// Accept a pending action from an <see cref="ActionRequiredEvent"/>.
    /// Pass the action bytes from the event verbatim; the orchestrator
    /// resumes whichever flow was suspended and returns the resulting
    /// event stream (e.g. <see cref="PairingCompletedEvent"/>).
    /// </summary>
    public Task<IReadOnlyList<DeRecEvent>> AcceptAsync(byte[] actionBytes)
    {
        EnsureNotDisposed();
        return Task.Run<IReadOnlyList<DeRecEvent>>(() =>
        {
            var result = NP.derec_protocol_accept(_handle, actionBytes, (UIntPtr)actionBytes.Length);
            try
            {
                ThrowOnError(result.Error);
                byte[] json = DeRec.Library.Utils.CopyBuffer(result.EventsJson);
                return JsonSerializer.Deserialize<List<DeRecEvent>>(json, JsonOpts)
                    ?? new List<DeRecEvent>();
            }
            finally
            {
                DeRec.Library.Utils.FreeBuffer(result.EventsJson);
            }
        });
    }

    /// <summary>
    /// Reject a pending action with a status + memo. <paramref name="status"/>
    /// matches the wire <c>StatusEnum</c>.
    /// </summary>
    public Task RejectAsync(byte[] actionBytes, int status, string memo)
    {
        EnsureNotDisposed();
        byte[]? memoBytes = string.IsNullOrEmpty(memo) ? null : Encoding.UTF8.GetBytes(memo);
        UIntPtr memoLen = (UIntPtr)(memoBytes?.Length ?? 0);
        return Task.Run(() =>
        {
            var err = NP.derec_protocol_reject(
                _handle, actionBytes, (UIntPtr)actionBytes.Length,
                status, memoBytes, memoLen);
            ThrowOnError(err);
        });
    }

    /// <summary>
    /// Drive <see cref="ProcessAsync"/> and auto-<see cref="AcceptAsync"/>
    /// every <see cref="ActionRequiredEvent"/> the protocol emits, then
    /// return the flat list of events. Mirrors the JS smoke's
    /// <c>processAll</c> helper.
    /// </summary>
    public async Task<IReadOnlyList<DeRecEvent>> ProcessAndAcceptAllAsync(byte[] message)
    {
        var initial = await ProcessAsync(message);
        var combined = new List<DeRecEvent>(initial);
        foreach (var ev in initial)
        {
            if (ev is ActionRequiredEvent ar)
            {
                var follow = await AcceptAsync(ar.Action);
                combined.AddRange(follow);
            }
        }
        return combined;
    }

    /// <summary>
    /// Process an inbound envelope. Returns every <see cref="DeRecEvent"/>
    /// the orchestrator emits while handling it.
    /// </summary>
    public Task<IReadOnlyList<DeRecEvent>> ProcessAsync(byte[] message)
    {
        EnsureNotDisposed();
        return Task.Run<IReadOnlyList<DeRecEvent>>(() =>
        {
            var result = NP.derec_protocol_process(_handle, message, (UIntPtr)message.Length);
            try
            {
                ThrowOnError(result.Error);
                byte[] json = DeRec.Library.Utils.CopyBuffer(result.EventsJson);
                return JsonSerializer.Deserialize<List<DeRecEvent>>(json, JsonOpts)
                    ?? new List<DeRecEvent>();
            }
            finally
            {
                DeRec.Library.Utils.FreeBuffer(result.EventsJson);
            }
        });
    }

    /// <summary>
    /// Advance time-driven state without an inbound message.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Timeouts are otherwise only evaluated by <see cref="ProcessAsync"/>, so
    /// a publish whose helpers all go quiet has nothing left to close it: the
    /// round stays open and no <c>SharingComplete</c> is ever raised. Call
    /// this from a scheduler — a timer, a hosted background service, a cron
    /// trigger — at an interval shorter than the configured timeout.
    /// </para>
    /// <para>
    /// Safe to call at any time; with nothing in flight it returns an empty
    /// list. It mutates the same round state an inbound response does, so it
    /// must be serialized against <see cref="ProcessAsync"/> for the same
    /// <c>secret_id</c>.
    /// </para>
    /// </remarks>
    public Task<IReadOnlyList<DeRecEvent>> TickAsync()
    {
        EnsureNotDisposed();
        return Task.Run<IReadOnlyList<DeRecEvent>>(() =>
        {
            var result = NP.derec_protocol_tick(_handle);
            try
            {
                ThrowOnError(result.Error);
                byte[] json = DeRec.Library.Utils.CopyBuffer(result.EventsJson);
                return JsonSerializer.Deserialize<List<DeRecEvent>>(json, JsonOpts)
                    ?? new List<DeRecEvent>();
            }
            finally
            {
                DeRec.Library.Utils.FreeBuffer(result.EventsJson);
            }
        });
    }

    /// <summary>
    /// Rebuild this protocol's <c>secret_id</c> namespace from a recovered
    /// <see cref="Secret"/>. Mirrors the Rust <c>DeRecProtocol::restore</c>
    /// — see that method for the full contract. <paramref name="recoveredSecret"/>
    /// is the <see cref="Secret"/> carried by <see cref="SecretRecoveredEvent.Secret"/>;
    /// pass it verbatim.
    /// </summary>
    /// <exception cref="DeRecException">
    /// Thrown with <see cref="DeRecCode.AlreadyRestored"/>,
    /// <see cref="DeRecCode.RestoreConflict"/>, <see cref="DeRecCode.Invariant"/>,
    /// or a store-category code on failure.
    /// </exception>
    public Task<IReadOnlyList<DeRecEvent>> RestoreAsync(Secret recoveredSecret, uint version)
    {
        EnsureNotDisposed();
        var dto = new RestoreParamsDto { Version = version, RecoveredSecret = recoveredSecret };
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(dto, JsonOpts);
        return Task.Run<IReadOnlyList<DeRecEvent>>(() =>
        {
            var result = NP.derec_protocol_restore(_handle, json, (UIntPtr)json.Length);
            try
            {
                ThrowOnError(result.Error);
                byte[] eventsJson = DeRec.Library.Utils.CopyBuffer(result.EventsJson);
                return JsonSerializer.Deserialize<List<DeRecEvent>>(eventsJson, JsonOpts)
                    ?? new List<DeRecEvent>();
            }
            finally
            {
                DeRec.Library.Utils.FreeBuffer(result.EventsJson);
            }
        });
    }

    private sealed record RestoreParamsDto
    {
        [JsonPropertyName("version")] public required uint Version { get; init; }
        [JsonPropertyName("recovered_secret")] public required Secret RecoveredSecret { get; init; }
    }

    /// <summary>
    /// Replace this node's local <c>communication_info</c> map. Does
    /// not contact peers — follow up with
    /// <c>StartAsync(FlowKind.UpdateChannelInfo, ...)</c> to propagate.
    /// </summary>
    public void SetCommunicationInfo(Dictionary<string, string> info)
    {
        EnsureNotDisposed();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(info, JsonOpts);
        var err = NP.derec_protocol_set_communication_info(_handle, json, (UIntPtr)json.Length);
        ThrowOnError(err);
    }

    /// <summary>
    /// Replace this node's local transport endpoint. IMPORTANT: keep
    /// the old endpoint operational during the changeover (see the Rust
    /// docs on the matching setter for the discipline).
    /// </summary>
    public void SetOwnTransport(string uri, string protocol = "https")
    {
        EnsureNotDisposed();
        int protocolNum = protocol.ToLowerInvariant() switch
        {
            "https" => 0,
            _ => throw new ArgumentException($"unknown protocol: {protocol}", nameof(protocol)),
        };
        byte[] uriBytes = Encoding.UTF8.GetBytes(uri);
        var err = NP.derec_protocol_set_own_transport(_handle, uriBytes, (UIntPtr)uriBytes.Length, protocolNum);
        ThrowOnError(err);
    }

    public void Dispose()
    {
        if (_handle != IntPtr.Zero)
        {
            NP.derec_protocol_free(_handle);
            _handle = IntPtr.Zero;
        }
        GC.SuppressFinalize(this);
    }

    private void EnsureNotDisposed()
    {
        if (_handle == IntPtr.Zero)
            throw new ObjectDisposedException(nameof(DeRecProtocol));
    }

    private static void ThrowOnError(DeRecError err) =>
        DeRec.Library.Utils.ThrowIfError(err);

    private static int WriteOut(byte[]? bytes, out IntPtr outPtr, out UIntPtr outLen)
    {
        if (bytes is null || bytes.Length == 0)
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return 0;
        }
        IntPtr p = Marshal.AllocCoTaskMem(bytes.Length);
        Marshal.Copy(bytes, 0, p, bytes.Length);
        outPtr = p;
        outLen = (UIntPtr)bytes.Length;
        return 0;
    }

    private static void FreeBufferImpl(IntPtr userData, IntPtr ptr, UIntPtr len)
    {
        if (ptr != IntPtr.Zero)
            Marshal.FreeCoTaskMem(ptr);
    }

    private static HelperChannelDto ToDto(HelperChannel h) => new(
        h.ChannelId,
        new TransportDto(h.Transport.Uri, (int)h.Transport.Protocol),
        h.CommunicationInfo,
        h.PeerRole.ToString(),
        h.Status.ToString(),
        h.CreatedAt);

    private static ReplicaMemberDto ToDto(ReplicaMember m) => new(
        m.ChannelId,
        m.ReplicaId,
        new TransportDto(m.Transport.Uri, (int)m.Transport.Protocol),
        m.CommunicationInfo,
        m.Role.ToString(),
        m.Status.ToString(),
        m.CreatedAt);

    private static HelperChannel FromDto(HelperChannelDto d) => new(
        d.channel_id,
        new TransportProtocol(d.transport.uri, (Protocol)d.transport.protocol),
        d.communication_info ?? new(),
        Enum.Parse<ChannelStatus>(d.status ?? nameof(ChannelStatus.Paired)),
        d.created_at,
        Enum.Parse<LibPairing.SenderKind>(d.peer_role));

    private static ReplicaMember FromDto(ReplicaMemberDto d) => new(
        d.channel_id,
        d.replica_id,
        new TransportProtocol(d.transport.uri, (Protocol)d.transport.protocol),
        d.communication_info ?? new(),
        Enum.Parse<ReplicaRole>(d.role),
        Enum.Parse<ChannelStatus>(d.status ?? nameof(ChannelStatus.Paired)),
        d.created_at);

    private int ChannelLoadImpl(IntPtr userData, ulong secretId, ulong channelId, ulong replicaId, out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var record = _channelStore.Load(secretId, channelId, replicaId);
            if (record is null)
            {
                outPtr = IntPtr.Zero;
                outLen = UIntPtr.Zero;
                return 1;
            }
            var dto = new ChannelRecordDto(
                record.Helper is null ? null : ToDto(record.Helper),
                record.Replica is null ? null : ToDto(record.Replica));
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(dto, JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private int ChannelSaveImpl(IntPtr userData, ulong secretId, ulong channelId, ulong replicaId, IntPtr bytes, UIntPtr len)
    {
        try
        {
            byte[] buf = new byte[(int)len];
            Marshal.Copy(bytes, buf, 0, buf.Length);
            var dto = JsonSerializer.Deserialize<ChannelRecordDto>(buf, JsonOpts)
                ?? throw new InvalidOperationException("null ChannelRecord JSON");
            var record = (dto.Helper, dto.Replica) switch
            {
                ({ } h, null) => ChannelRecord.Of(FromDto(h)),
                (null, { } r) => ChannelRecord.Of(FromDto(r)),
                _ => throw new InvalidOperationException(
                    "ChannelRecord JSON must carry exactly one of Helper / Replica"),
            };
            _channelStore.Save(secretId, record);
            return 0;
        }
        catch { return -1; }
    }

    private int ChannelRemoveImpl(IntPtr userData, ulong secretId, ulong channelId, ulong replicaId, out uint outExisted)
    {
        try
        {
            outExisted = _channelStore.Remove(secretId, channelId, replicaId) ? 1u : 0u;
            return 0;
        }
        catch
        {
            outExisted = 0;
            return -1;
        }
    }

    private int ChannelListHelpersImpl(IntPtr userData, ulong secretId, out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var dtos = new List<HelperChannelDto>();
            foreach (var h in _channelStore.ListHelpers(secretId))
                dtos.Add(ToDto(h));
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(dtos, JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private int ChannelListReplicasImpl(IntPtr userData, ulong secretId, out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var dtos = new List<ReplicaMemberDto>();
            foreach (var m in _channelStore.ListReplicas(secretId))
                dtos.Add(ToDto(m));
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(dtos, JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private int ChannelLinkImpl(IntPtr userData, ulong secretId, ulong a, ulong b)
    {
        try { _channelStore.LinkChannel(secretId, a, b); return 0; }
        catch { return -1; }
    }

    private int ChannelLinkedImpl(IntPtr userData, ulong secretId, ulong channelId, out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var ids = new List<ulong>(_channelStore.LinkedChannels(secretId, channelId));
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(ids, JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private int SecretLoadImpl(IntPtr userData, ulong secretId, ulong channelId, uint kind, out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var sv = _secretStore.Load(secretId, channelId, (SecretKind)kind);
            if (sv is null)
            {
                outPtr = IntPtr.Zero;
                outLen = UIntPtr.Zero;
                return 1;
            }
            var rec = new SecretValueDto((uint)sv.Kind, sv.Bytes);
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(rec, JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private int SecretSaveImpl(IntPtr userData, ulong secretId, ulong channelId, uint kind, IntPtr bytes, UIntPtr len)
    {
        try
        {
            byte[] buf = new byte[(int)len];
            Marshal.Copy(bytes, buf, 0, buf.Length);
            var rec = JsonSerializer.Deserialize<SecretValueDto>(buf, JsonOpts)
                ?? throw new InvalidOperationException("null SecretValue");
            _secretStore.Save(secretId, channelId, new SecretValue((SecretKind)rec.kind, rec.bytes));
            return 0;
        }
        catch { return -1; }
    }

    private int SecretRemoveImpl(IntPtr userData, ulong secretId, ulong channelId, uint kind)
    {
        try { _secretStore.Remove(secretId, channelId, (SecretKind)kind); return 0; }
        catch { return -1; }
    }

    private int ShareLoadImpl(
        IntPtr userData, ulong secretId, ulong channelId,
        IntPtr versionsJsonPtr, UIntPtr versionsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            uint[] versions = DeserializeJsonArray<uint>(versionsJsonPtr, versionsJsonLen) ?? Array.Empty<uint>();
            var records = _shareStore.Load(secretId, channelId, versions)
                .Select(s => new ShareRecordDto(s.SecretId.ToString(), s.Version, s.Bytes))
                .ToList();
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(records, JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private int ShareLoadManyImpl(
        IntPtr userData, ulong secretId,
        IntPtr channelIdsJsonPtr, UIntPtr channelIdsJsonLen,
        IntPtr versionsJsonPtr, UIntPtr versionsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            ulong[] channelIds = DeserializeJsonArray<ulong>(channelIdsJsonPtr, channelIdsJsonLen) ?? Array.Empty<ulong>();
            uint[] versions = DeserializeJsonArray<uint>(versionsJsonPtr, versionsJsonLen) ?? Array.Empty<uint>();
            var records = _shareStore.LoadMany(secretId, channelIds, versions)
                .Select(s => new ShareRecordDto(s.SecretId.ToString(), s.Version, s.Bytes))
                .ToList();
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(records, JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private int ShareLoadAllImpl(
        IntPtr userData, ulong secretId,
        IntPtr channelIdsJsonPtr, UIntPtr channelIdsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            ulong[] channelIds = DeserializeJsonArray<ulong>(channelIdsJsonPtr, channelIdsJsonLen) ?? Array.Empty<ulong>();
            var records = _shareStore.LoadAll(secretId, channelIds)
                .Select(s => new ShareRecordDto(s.SecretId.ToString(), s.Version, s.Bytes))
                .ToList();
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(records, JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private int ShareLatestVersionImpl(IntPtr userData, ulong secretId, out uint outHasVersion, out uint outVersion)
    {
        try
        {
            var v = _shareStore.LatestVersion(secretId);
            if (v.HasValue) { outHasVersion = 1; outVersion = v.Value; }
            else { outHasVersion = 0; outVersion = 0; }
            return 0;
        }
        catch
        {
            outHasVersion = 0; outVersion = 0;
            return -1;
        }
    }

    private int ShareSaveImpl(IntPtr userData, ulong secretId, ulong channelId, IntPtr shareJsonPtr, UIntPtr shareJsonLen)
    {
        try
        {
            byte[] buf = new byte[(int)shareJsonLen];
            Marshal.Copy(shareJsonPtr, buf, 0, buf.Length);
            var rec = JsonSerializer.Deserialize<ShareRecordDto>(buf, JsonOpts)
                ?? throw new InvalidOperationException("null ShareRecord");
            _shareStore.Save(secretId, channelId, new Share(ulong.Parse(rec.secret_id), rec.version, rec.bytes));
            return 0;
        }
        catch { return -1; }
    }

    private int ShareRemoveChannelImpl(IntPtr userData, ulong secretId, ulong channelId)
    {
        try { _shareStore.RemoveChannel(secretId, channelId); return 0; }
        catch { return -1; }
    }

    private int UserSecretLoadLatestImpl(
        IntPtr userData, ulong secretId,
        out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var value = _userSecretStore.LoadLatest(secretId);
            if (value is null) { outPtr = IntPtr.Zero; outLen = UIntPtr.Zero; return 0; }
            var dto = new UserSecretsDto(
                value.Version,
                value.Secrets.Select(s => new UserSecretDto(s.Id, s.Name, s.Data)).ToArray(),
                value.Description);
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(dto, JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private int UserSecretSaveLatestImpl(
        IntPtr userData, ulong secretId, IntPtr valueJsonPtr, UIntPtr valueJsonLen)
    {
        try
        {
            byte[] buf = new byte[(int)valueJsonLen];
            Marshal.Copy(valueJsonPtr, buf, 0, buf.Length);
            var dto = JsonSerializer.Deserialize<UserSecretsDto>(buf, JsonOpts)
                ?? throw new InvalidOperationException("null UserSecrets");
            var entries = (dto.secrets ?? Array.Empty<UserSecretDto>())
                .Select(s => new UserSecretEntry(s.id ?? Array.Empty<byte>(), s.name ?? string.Empty, s.data ?? Array.Empty<byte>()))
                .ToArray();
            _userSecretStore.SaveLatest(secretId, new UserSecrets(dto.version, entries, dto.description));
            return 0;
        }
        catch { return -1; }
    }

    private int UserSecretRemoveImpl(IntPtr userData, ulong secretId)
    {
        try { _userSecretStore.Remove(secretId); return 0; }
        catch { return -1; }
    }

    private sealed record UserSecretsDto(uint version, UserSecretDto[] secrets, string? description);
    private sealed record UserSecretDto(byte[] id, string name, byte[] data);

    // Wire shape matches Rust `StateItemRecord` — snake_case field names, byte[]
    // as JSON number arrays via ByteArrayJsonNumberConverter.
    private sealed record StateItemDto(
        uint kind,
        string? channel_id,
        string? secret_id,
        uint? version,
        string? started_at,
        byte[]? bytes,
        byte[][]? shares,
        string[]? pending,
        string[]? confirmed,
        string[]? failed,
        string[]? pending_replicas,
        string[]? synced_replicas,
        string[]? behind_replicas);

    // Wire shape matches Rust `StateKeyRecord`.
    private sealed record StateKeyDto(
        uint kind,
        string? channel_id,
        string? secret_id,
        uint? version);

    private static StateItemDto ToDto(StateItem item) => new(
        (uint)item.Kind,
        item.ChannelId?.ToString(),
        item.SecretId?.ToString(),
        item.Version,
        item.StartedAt?.ToString(),
        item.Bytes,
        item.Shares,
        item.Pending?.Select(c => c.ToString()).ToArray(),
        item.Confirmed?.Select(c => c.ToString()).ToArray(),
        item.Failed?.Select(c => c.ToString()).ToArray(),
        item.PendingReplicas?.Select(r => r.ToString()).ToArray(),
        item.SyncedReplicas?.Select(r => r.ToString()).ToArray(),
        item.BehindReplicas?.Select(r => r.ToString()).ToArray());

    private static StateItem FromDto(StateItemDto dto)
    {
        var kind = (StateKind)dto.kind;
        ulong? channelId = dto.channel_id is null
            ? null
            : ulong.Parse(dto.channel_id, System.Globalization.CultureInfo.InvariantCulture);
        ulong? secretId = dto.secret_id is null
            ? null
            : ulong.Parse(dto.secret_id, System.Globalization.CultureInfo.InvariantCulture);
        ulong? startedAt = dto.started_at is null
            ? null
            : ulong.Parse(dto.started_at, System.Globalization.CultureInfo.InvariantCulture);
        ulong[]? pending = dto.pending?
            .Select(s => ulong.Parse(s, System.Globalization.CultureInfo.InvariantCulture))
            .ToArray();
        ulong[]? confirmed = dto.confirmed?
            .Select(s => ulong.Parse(s, System.Globalization.CultureInfo.InvariantCulture))
            .ToArray();
        ulong[]? failed = dto.failed?
            .Select(s => ulong.Parse(s, System.Globalization.CultureInfo.InvariantCulture))
            .ToArray();
        ulong[]? pendingReplicas = dto.pending_replicas?
            .Select(s => ulong.Parse(s, System.Globalization.CultureInfo.InvariantCulture))
            .ToArray();
        ulong[]? syncedReplicas = dto.synced_replicas?
            .Select(s => ulong.Parse(s, System.Globalization.CultureInfo.InvariantCulture))
            .ToArray();
        ulong[]? behindReplicas = dto.behind_replicas?
            .Select(s => ulong.Parse(s, System.Globalization.CultureInfo.InvariantCulture))
            .ToArray();
        return new StateItem(
            kind, channelId, secretId, dto.version, startedAt, dto.bytes, dto.shares,
            pending, confirmed, failed, pendingReplicas, syncedReplicas, behindReplicas);
    }

    private static StateKey ParseKeyBuffer(IntPtr ptr, UIntPtr len)
    {
        byte[] buf = new byte[(int)len];
        Marshal.Copy(ptr, buf, 0, buf.Length);
        var dto = JsonSerializer.Deserialize<StateKeyDto>(buf, JsonOpts)
            ?? throw new InvalidOperationException("null StateKey");
        var kind = (StateKind)dto.kind;
        return kind switch
        {
            StateKind.PendingVerification => StateKey.PendingVerification(
                ulong.Parse(dto.channel_id
                    ?? throw new InvalidOperationException("PendingVerification requires channel_id"),
                    System.Globalization.CultureInfo.InvariantCulture)),
            StateKind.PendingRecovery => StateKey.PendingRecovery(
                ulong.Parse(dto.secret_id
                    ?? throw new InvalidOperationException("PendingRecovery requires secret_id"),
                    System.Globalization.CultureInfo.InvariantCulture),
                dto.version
                    ?? throw new InvalidOperationException("PendingRecovery requires version")),
            StateKind.PendingUnpair => StateKey.PendingUnpair(
                ulong.Parse(dto.channel_id
                    ?? throw new InvalidOperationException("PendingUnpair requires channel_id"),
                    System.Globalization.CultureInfo.InvariantCulture)),
            StateKind.SharingRound => StateKey.SharingRound(),
            _ => throw new InvalidOperationException($"unknown StateKind: {dto.kind}"),
        };
    }

    private int StateSaveImpl(
        IntPtr userData, ulong secretId, IntPtr itemJsonPtr, UIntPtr itemJsonLen)
    {
        try
        {
            byte[] buf = new byte[(int)itemJsonLen];
            Marshal.Copy(itemJsonPtr, buf, 0, buf.Length);
            var dto = JsonSerializer.Deserialize<StateItemDto>(buf, JsonOpts)
                ?? throw new InvalidOperationException("null StateItem");
            _stateStore.Save(secretId, FromDto(dto));
            return 0;
        }
        catch { return -1; }
    }

    private int StateLoadImpl(
        IntPtr userData, ulong secretId,
        IntPtr keyJsonPtr, UIntPtr keyJsonLen,
        out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var key = ParseKeyBuffer(keyJsonPtr, keyJsonLen);
            var item = _stateStore.Load(secretId, key);
            if (item is null)
            {
                outPtr = IntPtr.Zero;
                outLen = UIntPtr.Zero;
                return 1;
            }
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(ToDto(item), JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private int StateRemoveImpl(
        IntPtr userData, ulong secretId,
        IntPtr keyJsonPtr, UIntPtr keyJsonLen,
        out uint outRemoved)
    {
        try
        {
            var key = ParseKeyBuffer(keyJsonPtr, keyJsonLen);
            outRemoved = _stateStore.Remove(secretId, key) ? 1u : 0u;
            return 0;
        }
        catch
        {
            outRemoved = 0;
            return -1;
        }
    }

    private int StateLoadAllImpl(
        IntPtr userData, ulong secretId, uint kind,
        out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var items = _stateStore.LoadAll(secretId, (StateKind)kind)
                .Select(ToDto)
                .ToArray();
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(items, JsonOpts);
            return WriteOut(json, out outPtr, out outLen);
        }
        catch
        {
            outPtr = IntPtr.Zero;
            outLen = UIntPtr.Zero;
            return -1;
        }
    }

    private static T[]? DeserializeJsonArray<T>(IntPtr ptr, UIntPtr len)
    {
        if (ptr == IntPtr.Zero || (int)len == 0) return null;
        byte[] buf = new byte[(int)len];
        Marshal.Copy(ptr, buf, 0, buf.Length);
        return JsonSerializer.Deserialize<T[]>(buf, JsonOpts);
    }

    private sealed record ShareRecordDto(string secret_id, uint version, byte[] bytes);

    private int TransportSendImpl(IntPtr userData, IntPtr uriPtr, UIntPtr uriLen, int protocol, IntPtr bytes, UIntPtr len)
    {
        try
        {
            byte[] uriBuf = new byte[(int)uriLen];
            Marshal.Copy(uriPtr, uriBuf, 0, uriBuf.Length);
            string uri = Encoding.UTF8.GetString(uriBuf);
            byte[] msg = new byte[(int)len];
            Marshal.Copy(bytes, msg, 0, msg.Length);
            _transport.Send(uri, protocol, msg);
            return 0;
        }
        catch { return -1; }
    }

    // Mirror the Rust-side `crate::protocol::types::ChannelRecord` /
    // `HelperChannel` / `ReplicaMember` / `TransportProtocol` shapes produced
    // by serde's default derives. Wire field names are snake_case to match
    // serde; `status`, `peer_role` and `role` are variant-name strings
    // ("Pending" / "Paired", "Owner" / "Helper" / "ReplicaSource" /
    // "ReplicaDestination", "Source" / "Destination"). `ChannelRecord` is an
    // externally tagged enum, so exactly one of `Helper` / `Replica` is
    // present. The public records on the dotnet side use native types and the
    // bridge translates in `ChannelLoadImpl` / `ChannelSaveImpl`.

    private sealed record TransportDto(string uri, int protocol);

    private sealed record HelperChannelDto(
        ulong channel_id,
        TransportDto transport,
        Dictionary<string, string>? communication_info,
        string peer_role,
        string? status,
        ulong created_at);

    private sealed record ReplicaMemberDto(
        ulong channel_id,
        ulong replica_id,
        TransportDto transport,
        Dictionary<string, string>? communication_info,
        string role,
        string? status,
        ulong created_at);

    private sealed record ChannelRecordDto(
        HelperChannelDto? Helper,
        ReplicaMemberDto? Replica);

    private sealed record SecretValueDto(uint kind, byte[] bytes);

    // Wire shape for `derec_protocol_new`'s `config_json` argument.
    // Field names match Rust `ProtocolConfig` exactly (see
    // library/src/ffi/protocol/handle/mod.rs). `SecretId`/`ReplicaId` are
    // decimal strings, not JSON numbers, so u64 values above 2^53 survive
    // the round trip through System.Text.Json without precision loss.
    // `ReplicaId` is omitted entirely (not `null`) when there is no
    // replica id, per `JsonOpts`'s `WhenWritingNull` ignore condition.
    private sealed record ProtocolConfigDto(
        [property: JsonPropertyName("secret_id")] string SecretId,
        [property: JsonPropertyName("own_transport_uri")] string OwnTransportUri,
        [property: JsonPropertyName("own_transport_protocol")] int OwnTransportProtocol,
        [property: JsonPropertyName("threshold")] uint Threshold,
        [property: JsonPropertyName("keep_versions_count")] uint KeepVersionsCount,
        [property: JsonPropertyName("auto_respond_on_failure")] bool AutoRespondOnFailure,
        [property: JsonPropertyName("unpair_ack")] int UnpairAck,
        [property: JsonPropertyName("auto_reply_to")] bool AutoReplyTo,
        [property: JsonPropertyName("auto_accept")] AutoAcceptConfigDto AutoAccept,
        [property: JsonPropertyName("timeouts")] TimeoutsConfigDto? Timeouts,
        [property: JsonPropertyName("replica_id")] string? ReplicaId);

    // Field-for-field equivalent of Rust `RemoveExpiredChannelsConfig`.
    // Both fields are always serialized, including when Enabled is false —
    // the library decides that a disabled policy ignores its timeout.
    // The whole object is omitted (not `null`) when the caller did not
    // configure a policy, so Rust's `#[serde(default)]` supplies the
    // default rather than this wrapper restating it.
    private sealed record RemoveExpiredChannelsConfigDto(
        [property: JsonPropertyName("enabled")] bool Enabled,
        [property: JsonPropertyName("timeout_in_secs")] ulong TimeoutInSecs);

    // Field-for-field equivalent of Rust `TimeoutsConfig`. Every field is
    // omitted when null so Rust's `#[serde(default)]` supplies the default —
    // the values live there, not in this wrapper.
    private sealed record TimeoutsConfigDto(
        [property: JsonPropertyName("inbound_message_secs")] ulong? InboundMessageSecs,
        [property: JsonPropertyName("sharing_round_secs")] ulong? SharingRoundSecs,
        [property: JsonPropertyName("unpair_ack_secs")] ulong? UnpairAckSecs,
        [property: JsonPropertyName("expired_channels")] RemoveExpiredChannelsConfigDto? ExpiredChannels);

    /// Whole seconds, or null when the caller left the value unset.
    private static ulong? ToSecs(TimeSpan? span) =>
        span is null ? null : (ulong)Math.Max(0, Math.Floor(span.Value.TotalSeconds));

    // Field-for-field equivalent of Rust `AutoAcceptConfig`.
    private sealed record AutoAcceptConfigDto(
        [property: JsonPropertyName("pairing")] bool Pairing,
        [property: JsonPropertyName("pre_pair")] bool PrePair,
        [property: JsonPropertyName("store_share")] bool StoreShare,
        [property: JsonPropertyName("verify_share")] bool VerifyShare,
        [property: JsonPropertyName("discovery")] bool Discovery,
        [property: JsonPropertyName("get_share")] bool GetShare,
        [property: JsonPropertyName("unpair")] bool Unpair,
        [property: JsonPropertyName("update_channel_info")] bool UpdateChannelInfo);
}

/// <summary>
/// Unpair-acknowledgement mode. See
/// <c>DeRecProtocolBuilder::with_unpair_ack</c> on the Rust side.
/// Integer values must match the Rust-side enum.
/// </summary>
public enum UnpairAck
{
    Required = 0,
    NotRequired = 1,
}

/// <summary>
/// Per-flow auto-accept policy. Mirrors the Rust
/// <c>AutoAcceptPolicy</c> struct. When a flow's property is
/// <c>true</c>, <see cref="DeRecProtocol.ProcessAsync"/> internally
/// runs the equivalent of <see cref="DeRecProtocol.AcceptAsync"/> for
/// that flow and emits an <see cref="AutoAcceptedEvent"/> in place of
/// <see cref="ActionRequiredEvent"/>.
///
/// <para>
/// Default = all properties <c>false</c> (no flow auto-accepted —
/// every incoming request surfaces as <see cref="ActionRequiredEvent"/>
/// like today).
/// </para>
///
/// <para>
/// Per-flow caveats (read these before enabling):
/// <list type="bullet">
/// <item><see cref="Pairing"/> covers standard and replica pairing.
/// Replica pairing remains <c>Pending</c> until both sides run
/// <see cref="DeRecProtocol.VerifyFingerprintAsync"/>, so auto-accept
/// is safe there. Standard pairing transitions to <c>Paired</c>
/// immediately.</item>
/// <item><see cref="PrePair"/> turns this initiator into a
/// request-amplification oracle (anyone with the contact's nonce can
/// elicit a key-publish). Keep off unless you control both ends of
/// the transport.</item>
/// <item><see cref="StoreShare"/> is the helper's only admission-control
/// point for inbound shares. The protocol enforces no size, quota or
/// rate limit of its own, and <c>maxShareSize</c> is checked for range
/// overlap at pairing time only, never against an actual share. While
/// this is <c>false</c>, the <see cref="ActionRequiredEvent"/> carries
/// the decoded request, so the application can inspect the share and
/// call <see cref="DeRecProtocol.RejectAsync"/> with
/// <c>StatusEnum.SizeLimitExceeded</c>. Setting it <c>true</c> removes
/// that opportunity entirely: every share from every paired Owner is
/// stored unconditionally, at whatever size it arrives. Keep off in any
/// deployment with per-user storage limits.</item>
/// <item><see cref="Unpair"/> is destructive — accepting deletes the
/// local channel record before any UI confirmation.</item>
/// <item><see cref="UpdateChannelInfo"/> silently overwrites the
/// channel record with the peer's announced transport / communication
/// info.</item>
/// </list>
/// </para>
/// </summary>
/// <summary>
/// Automatic removal of expired <c>Pending</c> channels during
/// <see cref="DeRecProtocol.ProcessAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Pass <c>null</c> (the default) to leave the library's own default in
/// force. Both properties are always sent to the library, including when
/// <see cref="Enabled"/> is <c>false</c> — the library decides that a
/// disabled policy ignores its timeout.
/// </para>
/// <para>
/// <c>Pending</c> covers both an in-flight pairing handshake and a
/// replica channel awaiting out-of-band fingerprint verification, and one
/// timeout governs both. Fingerprint verification is paced by a human, so
/// deployments that pair replicas should raise
/// <see cref="TimeoutInSecs"/> or set <see cref="Enabled"/> to
/// <c>false</c> and call
/// <see cref="DeRecProtocol.RemoveExpiredChannelsAsync"/> on their own
/// schedule.
/// </para>
/// </remarks>
public sealed record RemoveExpiredChannelsPolicy(bool Enabled, ulong TimeoutInSecs);

/// <summary>
/// How long the protocol waits on each thing that can keep it waiting. A
/// <c>null</c> property means "use the library default"; the defaults live in
/// the Rust library, not here.
/// </summary>
/// <remarks>
/// <para>
/// These were one setting until it became clear they answer different
/// questions. <see cref="InboundMessage"/> is a <b>security</b> boundary — it
/// bounds how stale a message may be and still be accepted, so it must
/// tolerate transport latency and clock skew. The other three are
/// <b>liveness</b> budgets: how long to keep hoping a peer will answer.
/// </para>
/// </remarks>
/// <param name="InboundMessage">
/// Staleness boundary for inbound envelopes — the replay-defence window. Any
/// message older than this is discarded on receipt, whatever the flow.
/// Lowering it starts refusing legitimately old messages from slow transports
/// or skewed clocks. Library default: 300s.
/// </param>
/// <param name="SharingRound">
/// How long a publishing round waits on a peer that has not answered. This
/// bounds how long <c>SharingCompleteEvent</c> can be delayed by one
/// unreachable peer. Library default: 60s.
/// </param>
/// <param name="UnpairAck">
/// How long to wait for an unpair acknowledgement before dropping local
/// channel state anyway. Library default: 60s.
/// </param>
/// <param name="ExpiredChannels">
/// Removal of channels still awaiting out-of-band fingerprint confirmation.
/// Unlike the others this can be disabled. The budget is a <b>human</b> one —
/// someone comparing a fingerprint, possibly over the phone. Library default:
/// enabled at 300s.
/// </param>
public sealed record Timeouts(
    TimeSpan? InboundMessage = null,
    TimeSpan? SharingRound = null,
    TimeSpan? UnpairAck = null,
    RemoveExpiredChannelsPolicy? ExpiredChannels = null);

public sealed class AutoAcceptPolicy
{
    public bool Pairing { get; set; } = false;
    public bool PrePair { get; set; } = false;
    public bool StoreShare { get; set; } = false;
    public bool VerifyShare { get; set; } = false;
    public bool Discovery { get; set; } = false;
    public bool GetShare { get; set; } = false;
    public bool Unpair { get; set; } = false;
    public bool UpdateChannelInfo { get; set; } = false;

    /// <summary>
    /// Convenience constructor that flips every flow on. Read the
    /// per-property caveats above before using in production.
    /// </summary>
    public static AutoAcceptPolicy All() => new()
    {
        Pairing = true,
        PrePair = true,
        StoreShare = true,
        VerifyShare = true,
        Discovery = true,
        GetShare = true,
        Unpair = true,
        UpdateChannelInfo = true,
    };
}
