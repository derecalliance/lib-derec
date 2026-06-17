// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

namespace DeRec.Library.Orchestrator;

/// <summary>
/// Fluent builder for <see cref="DeRecProtocol"/>. Mirrors the Rust
/// <c>DeRecProtocolBuilder</c> method-for-method so a developer who
/// already knows one SDK can move between them without reaching for
/// reference docs.
///
/// <para>
/// Required setters: <see cref="WithChannelStore"/>,
/// <see cref="WithShareStore"/>, <see cref="WithSecretStore"/>,
/// <see cref="WithTransport"/>, <see cref="WithOwnTransport"/>.
/// Calling <see cref="Build"/> without all five throws
/// <see cref="InvalidOperationException"/>.
/// </para>
///
/// <para>
/// Optional setters all carry the defaults documented on the Rust
/// builder: <see cref="WithThreshold"/> (3), <see cref="WithKeepVersionsCount"/> (3),
/// <see cref="WithTimeout"/> (5 minutes), <see cref="WithCommunicationInfo"/> (empty),
/// <see cref="WithAutoRespondOnFailure"/> (false),
/// <see cref="WithUnpairAck"/> (<see cref="UnpairAck.Required"/>),
/// <see cref="WithAutoReplyTo"/> (false), <see cref="WithReplicaId"/> (unset).
/// </para>
/// </summary>
public sealed class DeRecProtocolBuilder
{
    private readonly ulong _secretId;
    private IChannelStore? _channelStore;
    private IShareStore? _shareStore;
    private ISecretStore? _secretStore;
    private IUserSecretStore? _userSecretStore;
    private ITransport? _transport;
    private TransportProtocol? _ownTransport;
    private int _threshold = 3;
    private int _keepVersionsCount = 3;
    private TimeSpan _timeout = TimeSpan.FromSeconds(300);
    private Dictionary<string, string> _communicationInfo = new();
    private bool _autoRespondOnFailure = false;
    private UnpairAck _unpairAck = UnpairAck.Required;
    private bool _autoReplyTo = false;
    private ulong? _replicaId = null;

    /// <summary>
    /// Construct a builder bound to a specific vault.
    ///
    /// <paramref name="secretId"/> identifies the single vault this
    /// protocol instance manages. Apps that juggle multiple vaults
    /// instantiate one <see cref="DeRecProtocol"/> per id.
    /// </summary>
    public DeRecProtocolBuilder(ulong secretId)
    {
        _secretId = secretId;
    }

    /// <summary>Set the channel-store implementation. Required.</summary>
    public DeRecProtocolBuilder WithChannelStore(IChannelStore store)
    {
        _channelStore = store ?? throw new ArgumentNullException(nameof(store));
        return this;
    }

    /// <summary>Set the share-store implementation. Required.</summary>
    public DeRecProtocolBuilder WithShareStore(IShareStore store)
    {
        _shareStore = store ?? throw new ArgumentNullException(nameof(store));
        return this;
    }

    /// <summary>Set the secret-store implementation. Required.</summary>
    public DeRecProtocolBuilder WithSecretStore(ISecretStore store)
    {
        _secretStore = store ?? throw new ArgumentNullException(nameof(store));
        return this;
    }

    /// <summary>Set the user-secret-store implementation. Required.</summary>
    public DeRecProtocolBuilder WithUserSecretStore(IUserSecretStore store)
    {
        _userSecretStore = store ?? throw new ArgumentNullException(nameof(store));
        return this;
    }

    /// <summary>Set the transport implementation. Required.</summary>
    public DeRecProtocolBuilder WithTransport(ITransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        return this;
    }

    /// <summary>Set this node's transport endpoint. Required.</summary>
    public DeRecProtocolBuilder WithOwnTransport(TransportProtocol endpoint)
    {
        _ownTransport = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
        return this;
    }

    /// <summary>
    /// Minimum number of shares required to reconstruct the secret.
    /// Default: 3.
    /// </summary>
    public DeRecProtocolBuilder WithThreshold(int threshold)
    {
        _threshold = threshold;
        return this;
    }

    /// <summary>
    /// Number of recent versions each helper must retain. Default: 3.
    /// </summary>
    public DeRecProtocolBuilder WithKeepVersionsCount(int count)
    {
        _keepVersionsCount = count;
        return this;
    }

    /// <summary>
    /// Protocol-wide staleness boundary. Truncated to seconds; clamped
    /// to at least 1 second. Default: 5 minutes.
    /// </summary>
    public DeRecProtocolBuilder WithTimeout(TimeSpan timeout)
    {
        _timeout = timeout;
        return this;
    }

    /// <summary>
    /// Key/value pairs included in pairing-request and pairing-response
    /// <c>CommunicationInfo</c>. Default: empty.
    /// </summary>
    public DeRecProtocolBuilder WithCommunicationInfo(Dictionary<string, string> info)
    {
        _communicationInfo = info ?? throw new ArgumentNullException(nameof(info));
        return this;
    }

    /// <summary>
    /// Whether the protocol auto-replies on failed inbound processing.
    /// Default: false.
    /// </summary>
    public DeRecProtocolBuilder WithAutoRespondOnFailure(bool enabled)
    {
        _autoRespondOnFailure = enabled;
        return this;
    }

    /// <summary>
    /// Whether the unpair initiator waits for the peer's ack before
    /// dropping local state. Default: <see cref="UnpairAck.Required"/>.
    /// </summary>
    public DeRecProtocolBuilder WithUnpairAck(UnpairAck ack)
    {
        _unpairAck = ack;
        return this;
    }

    /// <summary>
    /// Whether outbound requests carry an ephemeral <c>replyTo</c>
    /// pointing at this node's own transport. Default: false.
    /// </summary>
    public DeRecProtocolBuilder WithAutoReplyTo(bool enabled)
    {
        _autoReplyTo = enabled;
        return this;
    }

    /// <summary>
    /// Configure this node's local <c>replica_id</c>. Required for any
    /// replica-mode pairing. Default: unset.
    /// </summary>
    public DeRecProtocolBuilder WithReplicaId(ulong id)
    {
        _replicaId = id;
        return this;
    }

    /// <summary>
    /// Finalize the configuration. Throws
    /// <see cref="InvalidOperationException"/> if any of the required
    /// setters was not called.
    /// </summary>
    public DeRecProtocol Build()
    {
        if (_channelStore is null) throw new InvalidOperationException("WithChannelStore is required");
        if (_shareStore is null) throw new InvalidOperationException("WithShareStore is required");
        if (_secretStore is null) throw new InvalidOperationException("WithSecretStore is required");
        if (_userSecretStore is null) throw new InvalidOperationException("WithUserSecretStore is required");
        if (_transport is null) throw new InvalidOperationException("WithTransport is required");
        if (_ownTransport is null) throw new InvalidOperationException("WithOwnTransport is required");

        long secs = (long)Math.Floor(_timeout.TotalSeconds);
        int timeoutInSecs = (int)Math.Max(1, Math.Min(secs, int.MaxValue));

        return new DeRecProtocol(
            secretId: _secretId,
            channelStore: _channelStore,
            shareStore: _shareStore,
            secretStore: _secretStore,
            userSecretStore: _userSecretStore,
            transport: _transport,
            ownTransportUri: _ownTransport.Uri,
            ownTransportProtocol: _ownTransport.Protocol.ToString().ToLowerInvariant(),
            threshold: _threshold,
            keepVersionsCount: _keepVersionsCount,
            communicationInfo: _communicationInfo,
            timeoutInSecs: timeoutInSecs,
            autoRespondOnFailure: _autoRespondOnFailure,
            unpairAck: _unpairAck,
            autoReplyTo: _autoReplyTo,
            replicaId: _replicaId);
    }
}
