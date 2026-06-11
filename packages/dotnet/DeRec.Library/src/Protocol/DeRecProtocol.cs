// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
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
    private readonly NP.ChannelStoreListDelegate _channelList;
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
    private readonly NP.TransportSendDelegate _transportSend;
    // ReSharper restore NotAccessedField.Local

    // Strong refs so the store/transport interfaces outlive any callback.
    private readonly IChannelStore _channelStore;
    private readonly ISecretStore _secretStore;
    // ReSharper disable PrivateFieldCanBeConvertedToLocalVariable
    private readonly IShareStore _shareStore;
    private readonly ITransport _transport;
    // ReSharper restore PrivateFieldCanBeConvertedToLocalVariable

    private static JsonSerializerOptions JsonOpts => DeRecJsonOptions.Wire;

    /// <summary>
    /// Construct a protocol instance. Internal — callers go through
    /// <see cref="DeRecProtocolBuilder"/> so the surface stays in step
    /// with the Rust / JS SDK builders.
    /// </summary>
    internal DeRecProtocol(
        IChannelStore channelStore,
        IShareStore shareStore,
        ISecretStore secretStore,
        ITransport transport,
        string ownTransportUri,
        string ownTransportProtocol = "https",
        int threshold = 3,
        int keepVersionsCount = 3,
        Dictionary<string, string>? communicationInfo = null,
        int timeoutInSecs = 300,
        bool autoRespondOnFailure = false,
        UnpairAck unpairAck = UnpairAck.Required,
        bool autoReplyTo = false,
        ulong? replicaId = null)
    {
        _channelStore = channelStore;
        _shareStore = shareStore;
        _secretStore = secretStore;
        _transport = transport;

        _channelLoad = ChannelLoadImpl;
        _channelSave = ChannelSaveImpl;
        _channelRemove = ChannelRemoveImpl;
        _channelList = ChannelListImpl;
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

        _transportSend = TransportSendImpl;

        var channelCb = new NP.ChannelStoreCallbacks
        {
            UserData = IntPtr.Zero,
            Load = Marshal.GetFunctionPointerForDelegate(_channelLoad),
            Save = Marshal.GetFunctionPointerForDelegate(_channelSave),
            Remove = Marshal.GetFunctionPointerForDelegate(_channelRemove),
            ListChannels = Marshal.GetFunctionPointerForDelegate(_channelList),
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
        var transportCb = new NP.TransportCallbacks
        {
            UserData = IntPtr.Zero,
            Send = Marshal.GetFunctionPointerForDelegate(_transportSend),
        };

        byte[] uriBytes = Encoding.UTF8.GetBytes(ownTransportUri);
        int ownProtocolNum = ownTransportProtocol.ToLowerInvariant() switch
        {
            "https" => 0,
            _ => throw new ArgumentException($"unknown protocol: {ownTransportProtocol}", nameof(ownTransportProtocol)),
        };

        byte[]? commInfoBytes = null;
        UIntPtr commInfoLen = UIntPtr.Zero;

        var result = NP.derec_protocol_new(
            ref channelCb, ref secretCb, ref shareCb, ref transportCb,
            uriBytes, (UIntPtr)uriBytes.Length,
            ownProtocolNum,
            (uint)threshold,
            (uint)keepVersionsCount,
            commInfoBytes, commInfoLen,
            (uint)timeoutInSecs,
            autoRespondOnFailure ? 1u : 0u,
            (int)unpairAck,
            autoReplyTo ? 1u : 0u,
            replicaId.HasValue ? 1u : 0u,
            replicaId ?? 0ul);

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
        var result = NP.derec_protocol_get_fingerprint(_handle, channelId);
        try
        {
            ThrowOnError(result.Error);
            if (result.Fingerprint == IntPtr.Zero)
                throw new InvalidOperationException("get_fingerprint returned null without an error.");
            string fp = Marshal.PtrToStringUTF8(result.Fingerprint)
                ?? throw new InvalidOperationException("get_fingerprint returned an invalid UTF-8 string.");
            return Task.FromResult(fp);
        }
        finally
        {
            if (result.Fingerprint != IntPtr.Zero)
                DeRec.Library.Native.Utils.derec_free_string(result.Fingerprint);
        }
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
        var err = NP.derec_protocol_verify_fingerprint(_handle, channelId, fpBytes, out uint matched);
        ThrowOnError(err);
        return Task.FromResult(matched != 0);
    }

    /// <summary>
    /// Generate an out-of-band contact message used to bootstrap pairing.
    /// Pass <paramref name="channelId"/> = <c>null</c> to have the library
    /// mint the channel id; otherwise supply it explicitly.
    /// </summary>
    public Task<byte[]> CreateContactAsync(ulong? channelId, ContactMode contactMode)
    {
        EnsureNotDisposed();
        uint has = channelId.HasValue ? 1u : 0u;
        var result = NP.derec_protocol_create_contact(
            _handle, has, channelId ?? 0ul, (int)contactMode);
        try
        {
            ThrowOnError(result.Error);
            return Task.FromResult(DeRec.Library.Utils.CopyBuffer(result.ContactWireBytes));
        }
        finally
        {
            DeRec.Library.Utils.FreeBuffer(result.ContactWireBytes);
        }
    }

    /// <summary>
    /// Kick off a new flow. Returns the freshly minted channel id for
    /// <see cref="FlowKind.Pairing"/>, <c>null</c> otherwise.
    /// </summary>
    public Task<ulong?> StartAsync(FlowKind flowKind, object @params)
    {
        EnsureNotDisposed();
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(@params, JsonOpts);
        var result = NP.derec_protocol_start(
            _handle, (uint)flowKind, json, (UIntPtr)json.Length);
        ThrowOnError(result.Error);
        return Task.FromResult<ulong?>(result.HasChannelId != 0 ? result.ChannelId : null);
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
        var result = NP.derec_protocol_accept(
            _handle, actionBytes, (UIntPtr)actionBytes.Length);
        try
        {
            ThrowOnError(result.Error);
            byte[] json = DeRec.Library.Utils.CopyBuffer(result.EventsJson);
            var events = JsonSerializer.Deserialize<List<DeRecEvent>>(json, JsonOpts)
                ?? new List<DeRecEvent>();
            return Task.FromResult<IReadOnlyList<DeRecEvent>>(events);
        }
        finally
        {
            DeRec.Library.Utils.FreeBuffer(result.EventsJson);
        }
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
        var err = NP.derec_protocol_reject(
            _handle, actionBytes, (UIntPtr)actionBytes.Length,
            status, memoBytes, memoLen);
        ThrowOnError(err);
        return Task.CompletedTask;
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
        var result = NP.derec_protocol_process(
            _handle, message, (UIntPtr)message.Length);
        try
        {
            ThrowOnError(result.Error);
            byte[] json = DeRec.Library.Utils.CopyBuffer(result.EventsJson);
            var events = JsonSerializer.Deserialize<List<DeRecEvent>>(json, JsonOpts)
                ?? new List<DeRecEvent>();
            return Task.FromResult<IReadOnlyList<DeRecEvent>>(events);
        }
        finally
        {
            DeRec.Library.Utils.FreeBuffer(result.EventsJson);
        }
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

    private int ChannelLoadImpl(IntPtr userData, ulong channelId, out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var ch = _channelStore.Load(channelId);
            if (ch is null)
            {
                outPtr = IntPtr.Zero;
                outLen = UIntPtr.Zero;
                return 1;
            }
            var dto = new ChannelDto(
                ch.Id,
                new TransportDto(ch.Transport.Uri, (int)ch.Transport.Protocol),
                ch.CommunicationInfo,
                ch.Status.ToString(),
                ch.CreatedAt,
                ch.Role.ToString(),
                ch.ReplicaId);
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

    private int ChannelSaveImpl(IntPtr userData, ulong channelId, IntPtr bytes, UIntPtr len)
    {
        try
        {
            byte[] buf = new byte[(int)len];
            Marshal.Copy(bytes, buf, 0, buf.Length);
            var dto = JsonSerializer.Deserialize<ChannelDto>(buf, JsonOpts)
                ?? throw new InvalidOperationException("null Channel JSON");
            var transport = new TransportProtocol(
                dto.transport.uri, (Protocol)dto.transport.protocol);
            var status = Enum.Parse<ChannelStatus>(dto.status ?? nameof(ChannelStatus.Paired));
            var role = Enum.Parse<LibPairing.SenderKind>(dto.role);
            _channelStore.Save(new Channel(
                dto.id,
                transport,
                dto.communication_info ?? new(),
                status,
                dto.created_at,
                role,
                dto.replica_id));
            return 0;
        }
        catch { return -1; }
    }

    private int ChannelRemoveImpl(IntPtr userData, ulong channelId, out uint outExisted)
    {
        try
        {
            outExisted = _channelStore.Remove(channelId) ? 1u : 0u;
            return 0;
        }
        catch
        {
            outExisted = 0;
            return -1;
        }
    }

    private int ChannelListImpl(IntPtr userData, out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var ids = new List<ulong>(_channelStore.ListChannelIds());
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

    private int ChannelLinkImpl(IntPtr userData, ulong a, ulong b)
    {
        try { _channelStore.LinkChannel(a, b); return 0; }
        catch { return -1; }
    }

    private int ChannelLinkedImpl(IntPtr userData, ulong channelId, out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var ids = new List<ulong>(_channelStore.LinkedChannels(channelId));
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

    private int SecretLoadImpl(IntPtr userData, ulong channelId, uint kind, out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            var sv = _secretStore.Load(channelId, (SecretKind)kind);
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

    private int SecretSaveImpl(IntPtr userData, ulong channelId, uint kind, IntPtr bytes, UIntPtr len)
    {
        try
        {
            byte[] buf = new byte[(int)len];
            Marshal.Copy(bytes, buf, 0, buf.Length);
            var rec = JsonSerializer.Deserialize<SecretValueDto>(buf, JsonOpts)
                ?? throw new InvalidOperationException("null SecretValue");
            _secretStore.Save(channelId, new SecretValue((SecretKind)rec.kind, rec.bytes));
            return 0;
        }
        catch { return -1; }
    }

    private int SecretRemoveImpl(IntPtr userData, ulong channelId, uint kind)
    {
        try { _secretStore.Remove(channelId, (SecretKind)kind); return 0; }
        catch { return -1; }
    }

    private int ShareLoadImpl(
        IntPtr userData, ulong channelId, ulong secretId,
        IntPtr versionsJsonPtr, UIntPtr versionsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            uint[] versions = DeserializeJsonArray<uint>(versionsJsonPtr, versionsJsonLen) ?? Array.Empty<uint>();
            var records = _shareStore.Load(channelId, secretId, versions)
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
        IntPtr userData,
        IntPtr channelIdsJsonPtr, UIntPtr channelIdsJsonLen,
        ulong secretId,
        IntPtr versionsJsonPtr, UIntPtr versionsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            ulong[] channelIds = DeserializeJsonArray<ulong>(channelIdsJsonPtr, channelIdsJsonLen) ?? Array.Empty<ulong>();
            uint[] versions = DeserializeJsonArray<uint>(versionsJsonPtr, versionsJsonLen) ?? Array.Empty<uint>();
            var records = _shareStore.LoadMany(channelIds, secretId, versions)
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
        IntPtr userData,
        IntPtr channelIdsJsonPtr, UIntPtr channelIdsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen)
    {
        try
        {
            ulong[] channelIds = DeserializeJsonArray<ulong>(channelIdsJsonPtr, channelIdsJsonLen) ?? Array.Empty<ulong>();
            var records = _shareStore.LoadAll(channelIds)
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

    private int ShareLatestVersionImpl(IntPtr userData, out uint outHasVersion, out uint outVersion)
    {
        try
        {
            var v = _shareStore.LatestVersion();
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

    private int ShareSaveImpl(IntPtr userData, ulong channelId, IntPtr shareJsonPtr, UIntPtr shareJsonLen)
    {
        try
        {
            byte[] buf = new byte[(int)shareJsonLen];
            Marshal.Copy(shareJsonPtr, buf, 0, buf.Length);
            var rec = JsonSerializer.Deserialize<ShareRecordDto>(buf, JsonOpts)
                ?? throw new InvalidOperationException("null ShareRecord");
            _shareStore.Save(channelId, new Share(ulong.Parse(rec.secret_id), rec.version, rec.bytes));
            return 0;
        }
        catch { return -1; }
    }

    private int ShareRemoveChannelImpl(IntPtr userData, ulong channelId)
    {
        try { _shareStore.RemoveChannel(channelId); return 0; }
        catch { return -1; }
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

    // Mirror the Rust-side `crate::protocol::types::Channel` /
    // `TransportProtocol` shapes produced by serde's default derives.
    // Wire field names are snake_case to match serde; `status` and `role`
    // are variant-name strings ("Pending" / "Paired", "Owner" /
    // "Helper" / "ReplicaSource" / "ReplicaDestination"). The public
    // `Channel` record on the dotnet side uses native types
    // (`TransportProtocol`, `ChannelStatus`, `Pairing.SenderKind`)
    // and the bridge translates in `ChannelLoadImpl` /
    // `ChannelSaveImpl`.

    private sealed record TransportDto(string uri, int protocol);

    private sealed record ChannelDto(
        ulong id,
        TransportDto transport,
        Dictionary<string, string>? communication_info,
        string? status,
        ulong created_at,
        string role,
        ulong? replica_id);

    private sealed record SecretValueDto(uint kind, byte[] bytes);
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
