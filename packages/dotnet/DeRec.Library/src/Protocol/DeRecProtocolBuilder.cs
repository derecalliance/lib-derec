// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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
/// <see cref="WithTransport"/>, and either <see cref="WithOwnTransport"/>
/// or <see cref="WithOwnTransports"/>.
/// Calling <see cref="Build"/> without all five throws
/// <see cref="InvalidOperationException"/>.
/// </para>
///
/// <para>
/// Optional setters all carry the defaults documented on the Rust
/// builder: <see cref="WithThreshold"/> (3), <see cref="WithKeepVersionsCount"/> (3),
/// <see cref="WithTimeouts"/> (library defaults), <see cref="WithCommunicationInfo"/> (empty),
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
    private IStateStore? _stateStore;
    private ITransport? _transport;
    private TransportProtocol? _ownTransport;
    private IReadOnlyList<TransportProtocol>? _ownTransports;
    private int _threshold = 3;
    private int _keepVersionsCount = 3;
    private Dictionary<string, string> _communicationInfo = new();
    private bool _autoRespondOnFailure = false;
    private UnpairAck _unpairAck = UnpairAck.Required;
    private bool _autoReplyTo = false;
    private AutoAcceptPolicy _autoAccept = new();
    private ulong? _replicaId = null;
    private ParameterRange? _parameterRange = null;
    private Timeouts? _timeouts = null;
    private bool? _unsafeHttp = null;
    private bool? _unsafeConnection = null;

    /// <summary>
    /// Construct a builder bound to a specific secret.
    ///
    /// <paramref name="secretId"/> identifies the single secret this
    /// protocol instance manages. Apps that juggle multiple secrets
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

    /// <summary>Set the state-store implementation. Required.</summary>
    public DeRecProtocolBuilder WithStateStore(IStateStore store)
    {
        _stateStore = store ?? throw new ArgumentNullException(nameof(store));
        return this;
    }

    /// <summary>Set the transport implementation. Required.</summary>
    public DeRecProtocolBuilder WithTransport(ITransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
        return this;
    }

    /// <summary>
    /// Set this node's transport endpoint. Required in place of
    /// <see cref="WithOwnTransports"/>.
    /// </summary>
    [Obsolete("Use WithOwnTransports, which takes the whole preference list. " +
              "WithOwnTransports(new[] { endpoint }) is the direct replacement. " +
              "Removed at 0.0.5.")]
    public DeRecProtocolBuilder WithOwnTransport(TransportProtocol endpoint)
    {
        _ownTransport = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
        return this;
    }

    /// <summary>
    /// Set every transport endpoint this application serves, in the order
    /// given. Required (in place of <see cref="WithOwnTransport"/>) for
    /// applications serving more than one transport.
    /// </summary>
    /// <remarks>
    /// The order is this application's own preference and decides which of
    /// a peer's offered endpoints gets used — it is not sorted, deduplicated,
    /// or reordered. Every listed transport must actually be served, because
    /// delivery is push-only: listing an endpoint this application does not
    /// serve makes pairing succeed and replies vanish.
    ///
    /// Supersedes <see cref="WithOwnTransport"/> for applications serving
    /// more than one transport; the single-endpoint setter remains fully
    /// supported and is equivalent to passing a one-element list.
    /// </remarks>
    public DeRecProtocolBuilder WithOwnTransports(IEnumerable<TransportProtocol> transports)
    {
        if (transports is null) throw new ArgumentNullException(nameof(transports));
        _ownTransports = new List<TransportProtocol>(transports);
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
    /// Configure how long the protocol waits on each thing that can keep it
    /// waiting. Not calling this leaves every library default in force, as
    /// does leaving any individual field of <see cref="Timeouts"/> null.
    /// </summary>
    /// <remarks>
    /// These were one setting until it became clear they answer different
    /// questions. <see cref="Timeouts.InboundMessage"/> is a security
    /// boundary — how stale a message may be and still be accepted — so it
    /// must tolerate transport latency and clock skew. The other three are
    /// liveness budgets. Values are forwarded verbatim; clamping and
    /// defaulting are library decisions.
    /// </remarks>
    public DeRecProtocolBuilder WithTimeouts(Timeouts timeouts)
    {
        _timeouts = timeouts;
        return this;
    }

    /// <summary>
    /// Accept plaintext <c>http://</c> transport endpoints.
    /// <b>Development only.</b> Default: <c>false</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// With <c>false</c>, plaintext is accepted in exactly one situation: an
    /// endpoint this device configured for <em>itself</em> that names loopback
    /// (<c>localhost</c>, <c>127.0.0.1</c>, <c>::1</c>). A local dev server
    /// therefore needs no configuration at all.
    /// </para>
    /// <para>
    /// With <c>true</c>, plaintext is accepted for any host on any path,
    /// including endpoints a peer supplies. That is what makes the LAN case
    /// work — a phone talking to a laptop, where neither side is loopback —
    /// and why the name is blunt.
    /// </para>
    /// <para>
    /// This is a guardrail, not transport security. The SDK opens no sockets;
    /// delivery is your <c>ITransport</c>. Nothing here stops an application
    /// sending plaintext — it governs which endpoints the protocol will
    /// record, propagate to peers, and reply to.
    /// </para>
    /// </remarks>
    [Obsolete("Use WithUnsafeConnection, which names both gated schemes. Removed at 0.0.5.")]
    public DeRecProtocolBuilder WithUnsafeHttp(bool allow)
    {
        _unsafeHttp = allow;
        return this;
    }

    /// <summary>
    /// Accept plaintext <c>http://</c> and <c>grpc://</c> transport endpoints.
    /// <b>Development only.</b> Default: <c>false</c>. Supersedes
    /// <see cref="WithUnsafeHttp"/>, which names only the HTTP scheme.
    /// </summary>
    /// <remarks>
    /// <para>
    /// With <c>false</c>, plaintext is accepted in exactly one situation: an
    /// endpoint this device configured for <em>itself</em> that names loopback
    /// (<c>localhost</c>, <c>127.0.0.1</c>, <c>::1</c>). A local dev server
    /// therefore needs no configuration at all.
    /// </para>
    /// <para>
    /// With <c>true</c>, plaintext is accepted for any host on any path,
    /// including endpoints a peer supplies. That is what makes the LAN case
    /// work — a phone talking to a laptop, where neither side is loopback —
    /// and why the name is blunt.
    /// </para>
    /// <para>
    /// This is a guardrail, not transport security. The SDK opens no sockets;
    /// delivery is your <c>ITransport</c>. Nothing here stops an application
    /// sending plaintext — it governs which endpoints the protocol will
    /// record, propagate to peers, and reply to.
    /// </para>
    /// </remarks>
    public DeRecProtocolBuilder WithUnsafeConnection(bool allow)
    {
        _unsafeConnection = allow;
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
    /// Per-flow auto-accept policy. When a flow's property on the
    /// policy is <c>true</c>, <see cref="DeRecProtocol.ProcessAsync"/>
    /// internally accepts the inbound request and emits
    /// <see cref="AutoAcceptedEvent"/> in place of
    /// <see cref="ActionRequiredEvent"/>. Read the per-property
    /// caveats on <see cref="AutoAcceptPolicy"/> before enabling.
    /// Default: every property <c>false</c>.
    /// </summary>
    public DeRecProtocolBuilder WithAutoAccept(AutoAcceptPolicy policy)
    {
        _autoAccept = policy ?? throw new ArgumentNullException(nameof(policy));
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
    /// Declare the bounds this node advertises during pair negotiation.
    /// </summary>
    /// <remarks>
    /// Embedded in outbound <c>PairRequest</c>/<c>PairResponse</c> envelopes
    /// and checked against the peer's range on inbound ones: a range that
    /// fails to intersect rejects the pairing with
    /// <see cref="DeRecCode.IncompatibleParameterRange"/>. Default: unset —
    /// no constraints advertised, every peer range accepted.
    /// </remarks>
    public DeRecProtocolBuilder WithParameterRange(ParameterRange range)
    {
        _parameterRange = range;
        return this;
    }

    /// <summary>
    /// Configure automatic removal of expired <c>Pending</c> channels
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
        if (_stateStore is null) throw new InvalidOperationException("WithStateStore is required");
        if (_transport is null) throw new InvalidOperationException("WithTransport is required");
        if (_ownTransport is null && (_ownTransports is null || _ownTransports.Count == 0))
            throw new InvalidOperationException("WithOwnTransport or WithOwnTransports is required");

        return new DeRecProtocol(
            secretId: _secretId,
            channelStore: _channelStore,
            shareStore: _shareStore,
            secretStore: _secretStore,
            userSecretStore: _userSecretStore,
            stateStore: _stateStore,
            transport: _transport,
            ownTransportUri: _ownTransport?.Uri ?? string.Empty,
            ownTransportProtocol: _ownTransport?.Protocol.ToString().ToLowerInvariant() ?? "https",
            ownTransports: _ownTransports,
            threshold: _threshold,
            keepVersionsCount: _keepVersionsCount,
            communicationInfo: _communicationInfo,
            autoRespondOnFailure: _autoRespondOnFailure,
            unpairAck: _unpairAck,
            autoReplyTo: _autoReplyTo,
            autoAccept: _autoAccept,
            replicaId: _replicaId,
            parameterRange: _parameterRange,
            timeouts: _timeouts,
            unsafeHttp: _unsafeHttp,
            unsafeConnection: _unsafeConnection);
    }
}
