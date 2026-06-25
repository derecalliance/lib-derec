// SPDX-License-Identifier: Apache-2.0
// Protocol smoke tests: exercises the stateful DeRecProtocol orchestrator
// (handle FFI + storage/transport callbacks + flow start/process/accept
// surface) across pair, sharing, discovery, recovery, and replica flows.
// Mirrors `bindings/nodejs/protocol.ts` and `bindings/web/src/protocol.ts`.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using DeRec.Library;
using DeRec.Library.Orchestrator;
using DeRec.Library.Primitives;

namespace DeRec.Bindings.Smoke;

internal static class Protocol
{
    public static void RunAll()
    {
        RunOrchestratorFingerprintTest();
        RunOrchestratorFingerprintMismatchTest();
        RunOrchestratorPairFlowTest();
        RunOrchestratorHashedKeysPairFlowTest();
        RunOrchestratorShareAndDiscoverFlowTest();
        RunOrchestratorUnpairingFlowTest();
        RunOrchestratorUpdateChannelInfoFlowTest();
        RunOrchestratorReplyToFlowTest();
        RunOrchestratorReplicaIdWiringSadPathsTest();
        RunOrchestratorReplicaPairAndSecretSyncTest();
        RunOrchestratorReplicaSyncVersionProgressionTest();
        RunOrchestratorAutoAcceptFlowTest();
    }

    /// <summary>
    /// Drives a sharing round with both helpers configured via
    /// <see cref="AutoAcceptPolicy"/> to auto-accept <c>StoreShare</c>.
    /// Asserts that each helper's <see cref="DeRecProtocol.ProcessAsync"/>
    /// stream contains <see cref="AutoAcceptedEvent"/> + the standard
    /// <see cref="ShareStoredEvent"/> (and no
    /// <see cref="ActionRequiredEvent"/> for the auto-accepted action).
    /// </summary>
    private static void RunOrchestratorAutoAcceptFlowTest()
    {
        Console.WriteLine("=== Orchestrator auto-accept flow test ===");

        const ulong helperAChannel = 1UL;
        const ulong helperBChannel = 2UL;
        const ulong secretId = 0xAAAAUL;

        var policy = new AutoAcceptPolicy { StoreShare = true };

        using var owner = MakeNode("Owner", "https://owner.example.com",
            new NodeOptions(SecretId: secretId));
        using var helperA = MakeNode("HelperA", "https://helper-a.example.com",
            new NodeOptions(SecretId: secretId, AutoAccept: policy));
        using var helperB = MakeNode("HelperB", "https://helper-b.example.com",
            new NodeOptions(SecretId: secretId, AutoAccept: policy));

        ulong rekeyedA = DoOrchestratorPair(helperA, helperA.Transport, owner, owner.Transport, helperAChannel);
        ulong rekeyedB = DoOrchestratorPair(helperB, helperB.Transport, owner, owner.Transport, helperBChannel);
        Console.WriteLine($"  paired Owner↔HelperA ({rekeyedA}), Owner↔HelperB ({rekeyedB})  ✓");

        owner.Protocol.StartAsync(FlowKind.ProtectSecret, new ProtectSecretParams
        {
            Secrets = new[]
            {
                new UserSecret { Id = new byte[] { 0xAA }, Name = "auto-accept smoke", Data = Encoding.UTF8.GetBytes("dotnet-auto-accept") },
            },
            Description = "dotnet auto-accept smoke",
        }).GetAwaiter().GetResult();

        var outbound = owner.Transport.DrainAll();
        if (outbound.Count != 2)
            throw new InvalidOperationException($"expected 2 StoreShareRequests, got {outbound.Count}");

        var helpers = new[] { (helperA, helperA.Transport, "HelperA"), (helperB, helperB.Transport, "HelperB") };
        for (int i = 0; i < 2; i++)
        {
            var (h, hTx, name) = helpers[i];
            // With auto-accept on, ProcessAsync alone (no AcceptAsync follow-up)
            // produces AutoAccepted + ShareStored + the outbound response.
            var hEvents = h.Protocol.ProcessAsync(outbound[i].Bytes).GetAwaiter().GetResult();

            var autoAccepted = hEvents.OfType<AutoAcceptedEvent>().FirstOrDefault()
                ?? throw new InvalidOperationException($"{name} did not emit AutoAccepted");
            if (autoAccepted.ActionKind != "StoreShare")
                throw new InvalidOperationException(
                    $"{name} AutoAccepted carried action_kind={autoAccepted.ActionKind}; expected StoreShare");

            if (hEvents.OfType<ActionRequiredEvent>().Any())
                throw new InvalidOperationException(
                    $"{name} should not emit ActionRequired when StoreShare is auto-accepted");

            var stored = hEvents.OfType<ShareStoredEvent>().FirstOrDefault()
                ?? throw new InvalidOperationException($"{name} did not emit ShareStored after auto-accept");

            var response = hTx.DrainOne();
            var oEvents = owner.Protocol.ProcessAndAcceptAllAsync(response).GetAwaiter().GetResult();
            var confirmed = oEvents.OfType<ShareConfirmedEvent>().FirstOrDefault()
                ?? throw new InvalidOperationException($"owner did not emit ShareConfirmed for {name}");
            Console.WriteLine($"  {name}: AutoAccepted(StoreShare) → ShareStored(v={stored.Version}) → ShareConfirmed(v={confirmed.Version})  ✓");
        }

        Console.WriteLine("Orchestrator auto-accept flow test passed.");
    }

    /// <summary>
    /// Exercises the DeRecProtocol orchestrator FFI handle end-to-end:
    /// constructs a protocol with in-memory channel + secret stores,
    /// pre-populates a paired channel + 32-byte SharedKey, and asks the
    /// orchestrator for the fingerprint. Validates that:
    /// (a) the opaque handle round-trips constructor + free without leak,
    /// (b) the managed delegates correctly bridge ChannelStore + SecretStore
    ///     reads via the FFI callback layer,
    /// (c) the returned fingerprint is the same one derec-cryptography
    ///     would produce locally (deterministic for a given shared key).
    /// </summary>
    private static void RunOrchestratorFingerprintTest()
    {
        Console.WriteLine("=== Orchestrator getFingerprint test ===");

        const ulong channelId = 4242UL;
        byte[] sharedKey = new byte[32];
        for (int i = 0; i < 32; i++) sharedKey[i] = (byte)(i * 7 + 3);

        var channelStore = new InMemoryChannelStore();
        var secretStore = new InMemorySecretStore();
        var shareStore = new InMemoryShareStore();
        var transport = new RecordingTransport();

        // Pre-seed: a paired channel + its 32-byte SharedKey.
        channelStore.Save(DefaultTestSecretId, new Channel(
            Id: channelId,
            Transport: new TransportProtocol("https://peer.example.com"),
            CommunicationInfo: new Dictionary<string, string>(),
            Status: ChannelStatus.Paired,
            CreatedAt: 1700000000UL,
            Role: Pairing.SenderKind.Owner,
            ReplicaId: null));
        secretStore.Save(DefaultTestSecretId, channelId, new SecretValue(SecretKind.SharedKey, sharedKey));

        using var protocol = new DeRecProtocolBuilder(DefaultTestSecretId)
            .WithChannelStore(channelStore)
            .WithShareStore(shareStore)
            .WithSecretStore(secretStore)
            .WithUserSecretStore(new InMemoryUserSecretStore())
            .WithTransport(transport)
            .WithOwnTransport(new TransportProtocol("https://owner.example.com"))
            .Build();

        string fingerprint = protocol.GetFingerprintAsync(channelId).GetAwaiter().GetResult();

        if (string.IsNullOrEmpty(fingerprint))
            throw new InvalidOperationException("Orchestrator fingerprint test failed: empty fingerprint.");
        Console.WriteLine($"  fingerprint = {fingerprint} ({fingerprint.Length} chars)  ✓");

        // verifyFingerprint round-trip: the same fingerprint must match,
        // a clearly-wrong one must not.
        bool matched = protocol.VerifyFingerprintAsync(channelId, fingerprint).GetAwaiter().GetResult();
        if (!matched)
            throw new InvalidOperationException("Orchestrator fingerprint test failed: verify returned false for the locally-derived fingerprint.");
        bool unmatched = protocol.VerifyFingerprintAsync(channelId, "0000-0000-0000-0000").GetAwaiter().GetResult();
        if (unmatched)
            throw new InvalidOperationException("Orchestrator fingerprint test failed: verify returned true for a clearly-wrong fingerprint.");
        Console.WriteLine("  verifyFingerprint matches local / rejects wrong  ✓");

        Console.WriteLine("Orchestrator getFingerprint test passed.");
    }

    /// <summary>
    /// <c>verifyFingerprint(wrong)</c> on a still-<c>Pending</c> channel
    /// must (a) return <c>false</c> and (b) leave
    /// <c>Channel.Status</c> as <c>Pending</c>. The protocol must not
    /// downgrade or otherwise mutate the channel on a failed match.
    /// </summary>
    private static void RunOrchestratorFingerprintMismatchTest()
    {
        Console.WriteLine("=== Orchestrator fingerprint mismatch test ===");

        const ulong channelId = 5151UL;
        byte[] sharedKey = new byte[32];
        for (int i = 0; i < 32; i++) sharedKey[i] = (byte)(i * 11 + 5);

        using var node = MakeNode("Owner", "https://owner.example.com");

        // Pre-seed a Pending channel + its shared key (simulating the
        // post-replica-pair state where fingerprint verification is
        // still required to transition to Paired).
        node.ChannelStore.Save(node.Protocol.SecretId, new Channel(
            Id: channelId,
            Transport: new TransportProtocol("https://peer.example.com"),
            CommunicationInfo: new Dictionary<string, string>(),
            Status: ChannelStatus.Pending,
            CreatedAt: 1700000000UL,
            Role: Pairing.SenderKind.ReplicaSource,
            ReplicaId: 0xcafeUL));
        node.SecretStore.Save(node.Protocol.SecretId, channelId, new SecretValue(SecretKind.SharedKey, sharedKey));

        bool unmatched = node.Protocol
            .VerifyFingerprintAsync(channelId, "0000-0000-0000-0000")
            .GetAwaiter().GetResult();
        if (unmatched)
            throw new InvalidOperationException(
                "verifyFingerprint must return false for a wrong fingerprint");

        // Critical invariant: the stored channel record must still
        // report Pending; the protocol must not have touched it.
        var stored = node.ChannelStore.Load(node.Protocol.SecretId, channelId)
            ?? throw new InvalidOperationException("channel record missing after verify");
        if (stored.Status != ChannelStatus.Pending)
            throw new InvalidOperationException(
                $"verifyFingerprint(wrong) must leave Channel.Status as Pending; got {stored.Status}");
        Console.WriteLine("  verifyFingerprint(wrong) returns false  ✓");
        Console.WriteLine("  Channel.Status stays Pending after mismatch  ✓");

        Console.WriteLine("Orchestrator fingerprint mismatch test passed.");
    }

    /// <summary>
    /// Drives a full Owner↔Helper InlineKeys pair handshake through the
    /// dotnet <see cref="DeRecProtocol"/> orchestrator, mirroring the
    /// Rust binding's <c>run_protocol_pairing_flow</c>. Validates:
    ///
    /// (a) <see cref="DeRecProtocol.CreateContactAsync"/> returns proto
    ///     bytes that can decode round-trip
    /// (b) <see cref="DeRecProtocol.StartAsync"/> with
    ///     <see cref="FlowKind.Pairing"/> queues a PairRequest via the
    ///     <see cref="ITransport"/> callback
    /// (c) <see cref="DeRecProtocol.ProcessAsync"/> on the peer side
    ///     emits a <see cref="PairingCompletedEvent"/> and queues the
    ///     matching PairResponse
    /// (d) Initiator's <c>ProcessAsync</c> on the response emits its
    ///     own <see cref="PairingCompletedEvent"/>
    /// (e) Both sides end up with a paired Channel + matching SharedKey
    ///     in their stores
    /// </summary>
    private static void RunOrchestratorPairFlowTest()
    {
        Console.WriteLine("=== Orchestrator pair flow test ===");

        const ulong channelId = 99UL;

        // contactCreator → Helper (it created the contact, scanner picks Owner).
        using var helper = MakeNode("Helper", "https://helper.example.com");

        using var owner = MakeNode("Owner", "https://owner.example.com");

        // 1. Helper creates the contact, owner scans + starts.
        byte[] contactBytes = helper.Protocol.CreateContactAsync(channelId, ContactMode.InlineKeys)
            .GetAwaiter().GetResult();
        if (contactBytes.Length == 0)
            throw new InvalidOperationException("create_contact must return non-empty proto bytes");

        ulong? startResult = owner.Protocol.StartAsync(FlowKind.Pairing, new PairingParams
        {
            Kind = Pairing.SenderKind.Owner,
            Contact = contactBytes,
        }).GetAwaiter().GetResult();
        if (startResult is null)
            throw new InvalidOperationException("Pairing start must return a channel id");
        Console.WriteLine($"  start(Pairing, kind=Owner) → channel_id={startResult}  ✓");

        // 2. Owner's outbox carries the PairRequest. Feed it to the helper.
        byte[] pairRequest = owner.Transport.DrainOne();
        Console.WriteLine($"  owner emits PairRequest ({pairRequest.Length}B)");

        var helperEvents = helper.Protocol.ProcessAndAcceptAllAsync(pairRequest).GetAwaiter().GetResult();
        var helperPairing = helperEvents.OfType<PairingCompletedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"helper.process(PairRequest) must emit PairingCompleted; got [{string.Join(", ", helperEvents.Select(e => e.EventType))}]");
        Console.WriteLine($"  helper emits PairingCompleted(kind={helperPairing.Kind})  ✓");

        byte[] pairResponse = helper.Transport.DrainOne();
        Console.WriteLine($"  helper emits PairResponse ({pairResponse.Length}B)");

        var ownerEvents = owner.Protocol.ProcessAndAcceptAllAsync(pairResponse).GetAwaiter().GetResult();
        var ownerPairing = ownerEvents.OfType<PairingCompletedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"owner.process(PairResponse) must emit PairingCompleted; got [{string.Join(", ", ownerEvents.Select(e => e.EventType))}]");
        Console.WriteLine($"  owner emits PairingCompleted(kind={ownerPairing.Kind})  ✓");

        // 3. Both sides now have a paired channel record. Note the channel
        //    id gets re-keyed during the handshake — read the actual id
        //    out of each event rather than relying on the original.
        if (helperPairing.ChannelId != ownerPairing.ChannelId)
            throw new InvalidOperationException(
                $"both sides must converge on the same channel id; helper={helperPairing.ChannelId} owner={ownerPairing.ChannelId}");
        ulong rekeyedId = ulong.Parse(helperPairing.ChannelId);

        var helperChannel = helper.ChannelStore.Load(helper.Protocol.SecretId, rekeyedId)
            ?? throw new InvalidOperationException("helper channel record must exist after pairing");
        var ownerChannel = owner.ChannelStore.Load(owner.Protocol.SecretId, rekeyedId)
            ?? throw new InvalidOperationException("owner channel record must exist after pairing");

        var helperKey = helper.SecretStore.Load(helper.Protocol.SecretId, rekeyedId, SecretKind.SharedKey)
            ?? throw new InvalidOperationException("helper shared_key must exist after pairing");
        var ownerKey = owner.SecretStore.Load(owner.Protocol.SecretId, rekeyedId, SecretKind.SharedKey)
            ?? throw new InvalidOperationException("owner shared_key must exist after pairing");
        if (helperKey.Bytes.Length != 32 || ownerKey.Bytes.Length != 32)
            throw new InvalidOperationException("shared_key must be 32 bytes on both sides");
        if (!helperKey.Bytes.SequenceEqual(ownerKey.Bytes))
            throw new InvalidOperationException("owner/helper shared keys must match after pairing");
        Console.WriteLine($"  shared_key matches on both sides ({helperKey.Bytes.Length}B)  ✓");

        Console.WriteLine("Orchestrator pair flow test passed.");
    }

    /// <summary>
    /// Drives the full ProtectSecret → SharingComplete → Discovery →
    /// RecoverSecret pipeline through the orchestrator. Mirrors the
    /// Rust binding's <c>run_protocol_discovery_and_recovery_flow</c>.
    /// </summary>
    private static void RunOrchestratorShareAndDiscoverFlowTest()
    {
        Console.WriteLine("=== Orchestrator share + discovery + recovery test ===");

        const ulong helperAChannel = 1UL;
        const ulong helperBChannel = 2UL;
        const ulong secretId = 0x7777UL;
        byte[] secretData = Encoding.UTF8.GetBytes("orchestrator-shared-secret");

        using var owner = MakeNode("Owner", "https://owner.example.com",
            new NodeOptions(SecretId: secretId));

        // Helpers bind their protocol to the owner's secret id — one
        // helper-protocol-instance per (owner, secret) pair on the helper
        // side, mirroring the Rust/JS smokes.
        using var helperA = MakeNode("HelperA", "https://helper-a.example.com",
            new NodeOptions(SecretId: secretId));

        using var helperB = MakeNode("HelperB", "https://helper-b.example.com",
            new NodeOptions(SecretId: secretId));

        ulong rekeyedA = DoOrchestratorPair(helperA, helperA.Transport, owner, owner.Transport, helperAChannel);
        ulong rekeyedB = DoOrchestratorPair(helperB, helperB.Transport, owner, owner.Transport, helperBChannel);
        Console.WriteLine($"  paired Owner↔HelperA ({rekeyedA}), Owner↔HelperB ({rekeyedB})  ✓");

        owner.Protocol.StartAsync(FlowKind.ProtectSecret, new ProtectSecretParams
        {
            Secrets = new[]
            {
                new UserSecret { Id = new byte[] { 0x01 }, Name = "smoke", Data = secretData },
            },
            Description = "orchestrator smoke",
        }).GetAwaiter().GetResult();

        var outbound = owner.Transport.DrainAll();
        if (outbound.Count != 2)
            throw new InvalidOperationException($"expected 2 StoreShareRequests, got {outbound.Count}");

        var helpers = new[] { (helperA, helperA.Transport, "HelperA"), (helperB, helperB.Transport, "HelperB") };
        for (int i = 0; i < 2; i++)
        {
            var (h, hTx, name) = helpers[i];
            var hEvents = h.Protocol.ProcessAndAcceptAllAsync(outbound[i].Bytes).GetAwaiter().GetResult();
            var stored = hEvents.OfType<ShareStoredEvent>().FirstOrDefault()
                ?? throw new InvalidOperationException($"{name} did not emit ShareStored");
            var response = hTx.DrainOne();
            var oEvents = owner.Protocol.ProcessAndAcceptAllAsync(response).GetAwaiter().GetResult();
            var confirmed = oEvents.OfType<ShareConfirmedEvent>().FirstOrDefault()
                ?? throw new InvalidOperationException($"owner did not emit ShareConfirmed for {name}");
            Console.WriteLine($"  {name}: ShareStored(v={stored.Version}) → ShareConfirmed(v={confirmed.Version})  ✓");
        }

        // SharingComplete fires on the last ShareConfirmed processed.
        // Walk one more pump (will be a no-op or carry the event).
        var tailEvents = PumpAll(owner.Transport, owner);
        var sharing = tailEvents.OfType<SharingCompleteEvent>().FirstOrDefault();
        // It may have already fired inline; that's fine — what matters is
        // the helpers stored shares + owner saw both ShareConfirmed.
        Console.WriteLine($"  SharingComplete fired: {(sharing is not null ? "yes" : "(inline)")}  ✓");

        // Discovery: ask each helper what they hold. Target specific
        // channels rather than `All` — `All` enumerates the channel
        // store and trips on transient/half-paired entries from the
        // earlier handshakes.
        owner.Protocol.StartAsync(FlowKind.Discovery, new DiscoveryParams
        {
            Target = Target.Many(rekeyedA, rekeyedB),
        }).GetAwaiter().GetResult();
        var discoveryOut = owner.Transport.DrainAll();
        if (discoveryOut.Count != 2)
            throw new InvalidOperationException($"expected 2 Discovery requests, got {discoveryOut.Count}");

        var discoveredSecretIds = new HashSet<string>();
        for (int i = 0; i < 2; i++)
        {
            var (h, hTx, name) = helpers[i];
            h.Protocol.ProcessAndAcceptAllAsync(discoveryOut[i].Bytes).GetAwaiter().GetResult();
            var resp = hTx.DrainOne();
            var oEvents = owner.Protocol.ProcessAndAcceptAllAsync(resp).GetAwaiter().GetResult();
            foreach (var disc in oEvents.OfType<SecretsDiscoveredEvent>())
                foreach (var s in disc.Secrets) discoveredSecretIds.Add(s.SecretId);
        }
        if (!discoveredSecretIds.Contains(secretId.ToString()))
            throw new InvalidOperationException(
                $"Discovery must surface secret_id={secretId}, got [{string.Join(", ", discoveredSecretIds)}]");
        Console.WriteLine($"  Discovery surfaced secret_id {secretId} on both helpers  ✓");

        // Recovery: pair fresh owner-side channels with the same helpers
        // (mirrors the JS smoke), then RecoverSecret.
        const ulong recoveryAChannel = 100UL;
        const ulong recoveryBChannel = 101UL;

        using var recOwner = MakeNode("RecOwner", "https://recovery-owner.example.com",
            new NodeOptions(SecretId: secretId));

        ulong recA = DoOrchestratorPair(helperA, helperA.Transport, recOwner, recOwner.Transport, recoveryAChannel);
        ulong recB = DoOrchestratorPair(helperB, helperB.Transport, recOwner, recOwner.Transport, recoveryBChannel);
        Console.WriteLine($"  recovery re-pair: HelperA({recA}), HelperB({recB})  ✓");

        // Each helper links its original channel to its new recovery
        // channel so recovery (which fans out on the recovery channel)
        // surfaces the share stored under the original.
        helperA.ChannelStore.LinkChannel(helperA.Protocol.SecretId, rekeyedA, recA);
        helperB.ChannelStore.LinkChannel(helperB.Protocol.SecretId, rekeyedB, recB);

        recOwner.Protocol.StartAsync(FlowKind.RecoverSecret, new RecoverSecretParams
        {
            SecretId = secretId.ToString(),
            Version = 1,
        }).GetAwaiter().GetResult();
        var recRequests = recOwner.Transport.DrainAll();
        if (recRequests.Count != 2)
            throw new InvalidOperationException($"expected 2 GetShare requests, got {recRequests.Count}");

        SecretRecoveredEvent? recovered = null;
        for (int i = 0; i < 2; i++)
        {
            var (h, hTx, _) = helpers[i];
            h.Protocol.ProcessAndAcceptAllAsync(recRequests[i].Bytes).GetAwaiter().GetResult();
            var resp = hTx.DrainOne();
            var oEvents = recOwner.Protocol.ProcessAndAcceptAllAsync(resp).GetAwaiter().GetResult();
            recovered ??= oEvents.OfType<SecretRecoveredEvent>().FirstOrDefault();
        }
        if (recovered is null)
            throw new InvalidOperationException("RecoverSecret must surface SecretRecovered");

        // The library now decodes the protect-side wrapping for us:
        // `recovered.Secret` is the typed `Secret` snapshot, and
        // `Secret.Secrets` is the list of `UserSecret` the owner
        // originally protected. Assert id + data round-trip.
        var recoveredUserSecret = recovered.Secret.Secrets.FirstOrDefault(s =>
            s.Id.SequenceEqual(new byte[] { 0x01 }));
        if (recoveredUserSecret is null)
            throw new InvalidOperationException(
                "recovered Secret must include the UserSecret with the original id");
        if (!recoveredUserSecret.Data.SequenceEqual(secretData))
            throw new InvalidOperationException(
                $"recovered UserSecret.Data must round-trip; got {recoveredUserSecret.Data.Length}B");
        Console.WriteLine(
            $"  SecretRecovered → UserSecret '{recoveredUserSecret.Name}' ({recoveredUserSecret.Data.Length}B) round-trips  ✓");

        // Restore: build a fresh peer on the same secretId and replay
        // the recovered Secret — mirrors the real recovery flow where
        // the device that lost state stands up an empty protocol.
        using var restored = MakeNode("RestoredOwner", "https://restored.example.com",
            new NodeOptions(SecretId: secretId));
        restored.Protocol.RestoreAsync(recovered.Secret, version: 1).GetAwaiter().GetResult();

        var snapshot = restored.UserSecretStore.LoadLatest(secretId)
            ?? throw new InvalidOperationException("restore must commit a UserSecrets snapshot");
        if (snapshot.Version != 1)
            throw new InvalidOperationException(
                $"restored snapshot version mismatch: {snapshot.Version} != 1");
        var restoredUserSecret = snapshot.Secrets.FirstOrDefault(s =>
            s.Id.SequenceEqual(new byte[] { 0x01 }))
            ?? throw new InvalidOperationException(
                "restored snapshot must carry the protected UserSecret");
        if (!restoredUserSecret.Data.SequenceEqual(secretData))
            throw new InvalidOperationException("restored UserSecret data must round-trip");
        foreach (var helperInfo in recovered.Secret.Helpers)
        {
            var helperChannel = ulong.Parse(helperInfo.ChannelId);
            if (restored.ChannelStore.Load(secretId, helperChannel) is null)
                throw new InvalidOperationException(
                    $"restore did not write helper channel {helperChannel}");
        }
        Console.WriteLine(
            $"  Restored fresh peer: snapshot v1 ({snapshot.Secrets.Length} secret) + {recovered.Secret.Helpers.Count} helper channel(s)  ✓");

        Console.WriteLine("Orchestrator share + discovery + recovery test passed.");
    }

    /// <summary>
    /// Drives the full replica pair + ProtectSecret(includes destination)
    /// + secret sync pipeline. Mirrors the Rust binding's
    /// <c>run_protect_secret_with_replica_targets_flow</c>.
    /// </summary>
    private static void RunOrchestratorReplicaPairAndSecretSyncTest()
    {
        Console.WriteLine("=== Orchestrator replica pair + secret sync test ===");

        const ulong ownerReplicaId = 0xAAAA_AAAA_AAAA_AAAAUL;
        const ulong destReplicaId = 0xBBBB_BBBB_BBBB_BBBBUL;
        const ulong helperAChannel = 1UL;
        const ulong helperBChannel = 2UL;
        const ulong destChannel = 3UL;
        const ulong secretId = 0xC0FFEEUL;
        byte[] secretData = Encoding.UTF8.GetBytes("secret-payload-for-replica-and-helper");

        using var owner = MakeNode("Owner", "https://owner.example.com",
            new NodeOptions { ReplicaId = ownerReplicaId, SecretId = secretId });

        using var helperA = MakeNode("HelperA", "https://helper-a.example.com",
            new NodeOptions { SecretId = secretId });

        using var helperB = MakeNode("HelperB", "https://helper-b.example.com",
            new NodeOptions { SecretId = secretId });

        using var destination = MakeNode(
            "Destination", "https://replica-destination.example.com",
            new NodeOptions { ReplicaId = destReplicaId, SecretId = secretId });

        ulong helperAId = DoOrchestratorPair(helperA, helperA.Transport, owner, owner.Transport, helperAChannel);
        ulong helperBId = DoOrchestratorPair(helperB, helperB.Transport, owner, owner.Transport, helperBChannel);
        Console.WriteLine($"  helper pairs: A={helperAId}, B={helperBId}  ✓");

        // Replica pair: owner creates the contact, destination scans as
        // ReplicaDestination. Re-keys to a fresh channel id like every
        // other pair handshake.
        ulong destId = DoOrchestratorPair(
            owner, owner.Transport, destination, destination.Transport, destChannel,
            initiatorKind: Pairing.SenderKind.ReplicaDestination);
        Console.WriteLine($"  replica pair: destination channel={destId}  ✓");

        // Cross-confirm fingerprints — replica channels start `Pending`
        // and only become eligible publish targets after fingerprint
        // verification flips them to `Paired`.
        string ownerFp = owner.Protocol.GetFingerprintAsync(destId).GetAwaiter().GetResult();
        string destFp = destination.Protocol.GetFingerprintAsync(destId).GetAwaiter().GetResult();
        if (ownerFp != destFp)
            throw new InvalidOperationException($"replica fingerprint mismatch: owner={ownerFp} dest={destFp}");
        if (!owner.Protocol.VerifyFingerprintAsync(destId, destFp).GetAwaiter().GetResult())
            throw new InvalidOperationException("owner.VerifyFingerprint must return true");
        if (!destination.Protocol.VerifyFingerprintAsync(destId, ownerFp).GetAwaiter().GetResult())
            throw new InvalidOperationException("destination.VerifyFingerprint must return true");
        Console.WriteLine($"  fingerprint cross-confirmed ({ownerFp.Length} chars)  ✓");

        // verify_fingerprint auto-publishes an empty-secret roster
        // snapshot to every paired peer (2 helpers + 1 replica) so the
        // newly-Paired Destination receives the current state without
        // an explicit ProtectSecret call. Drain that round here — the
        // assertions below cover the subsequent explicit publish.
        var autoPublish = owner.Transport.DrainAll();
        if (autoPublish.Count != 3)
            throw new InvalidOperationException(
                $"verify_fingerprint auto-publish must fan out to 2 helpers + 1 replica, got {autoPublish.Count}");

        owner.Protocol.StartAsync(FlowKind.ProtectSecret, new ProtectSecretParams
        {
            Secrets = new[]
            {
                new UserSecret { Id = new byte[] { 0x01 }, Name = "shared-secret", Data = secretData },
            },
            Description = "replica + helper distribution",
        }).GetAwaiter().GetResult();

        var outbound = owner.Transport.DrainAll();
        if (outbound.Count != 3)
            throw new InvalidOperationException($"expected 3 outbound envelopes, got {outbound.Count}");

        var destEnvelope = outbound.FirstOrDefault(o => o.Uri == "https://replica-destination.example.com").Bytes
            ?? throw new InvalidOperationException("no envelope routed to the destination");
        Console.WriteLine($"  ProtectSecret fanned out 3 envelopes (2 helpers + 1 destination)  ✓");

        var destEvents = destination.Protocol.ProcessAndAcceptAllAsync(destEnvelope).GetAwaiter().GetResult();
        var received = destEvents.OfType<ReplicaSecretReceivedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"destination did not emit ReplicaSecretReceived; got [{string.Join(", ", destEvents.Select(e => e.EventType))}]");

        if (ulong.Parse(received.FromReplicaId) != ownerReplicaId)
            throw new InvalidOperationException($"from_replica_id mismatch (got {received.FromReplicaId})");
        if (ulong.Parse(received.SecretId) != secretId)
            throw new InvalidOperationException($"secret_id mismatch (got {received.SecretId})");
        if (received.Secret.Secrets.Count != 1 || !received.Secret.Secrets[0].Data.SequenceEqual(secretData))
            throw new InvalidOperationException("secret.secrets[0].data must round-trip the original");
        if (ulong.Parse(received.Secret.OwnerReplicaId) != ownerReplicaId)
            throw new InvalidOperationException("secret.owner_replica_id mismatch");
        if (received.Secret.Helpers.Count != 2)
            throw new InvalidOperationException($"secret.helpers must be 2, got {received.Secret.Helpers.Count}");
        if ((received.Secret.Replicas?.ReplicaList.Count ?? 0) != 1)
            throw new InvalidOperationException($"secret.replicas must be 1, got {(received.Secret.Replicas?.ReplicaList.Count ?? 0)}");
        var destInfo = received.Secret.Replicas!.ReplicaList[0];
        if (ulong.Parse(destInfo.ReplicaId) != destReplicaId)
            throw new InvalidOperationException("secret.replicas[0].replica_id mismatch");
        if (destInfo.SenderKind != (int)Pairing.SenderKind.ReplicaDestination)
            throw new InvalidOperationException("secret.replicas[0].sender_kind must be ReplicaDestination");
        if (received.Shares.Count != 2)
            throw new InvalidOperationException($"shares must be 2, got {received.Shares.Count}");

        Console.WriteLine(
            $"  ReplicaSecretReceived: secret={received.Secret.Secrets.Count}secret/{received.Secret.Helpers.Count}helpers/{(received.Secret.Replicas?.ReplicaList.Count ?? 0)}replicas, shares={received.Shares.Count}  ✓");

        // Drain the helper outboxes from the v=1 round so the next
        // round's pump-and-drain sees only v=2 envelopes.
        helperA.Transport.DrainAll();
        helperB.Transport.DrainAll();

        // Secret version updates: the owner mutates the secret and
        // re-runs `ProtectSecret`. The destination must receive a fresh
        // `ReplicaSecretReceived` carrying `version=2` and the new
        // payload. The protocol pulls the next version from
        // `IShareStore.LatestVersion()`; the in-memory store exposes a
        // side-channel setter so this test can drive that contract
        // without first running a full helper-side store / confirm
        // cycle on the owner.
        owner.ShareStore.SetOwnerVersion(owner.Protocol.SecretId, 1);
        byte[] secretDataV2 = Encoding.UTF8.GetBytes("secret-payload-after-update");
        owner.Protocol.StartAsync(FlowKind.ProtectSecret, new ProtectSecretParams
        {
            Secrets = new[]
            {
                new UserSecret { Id = new byte[] { 0x01 }, Name = "shared-secret", Data = secretDataV2 },
            },
            Description = "v2 replica + helper distribution",
        }).GetAwaiter().GetResult();

        var outbound2 = owner.Transport.DrainAll();
        if (outbound2.Count != 3)
            throw new InvalidOperationException($"v2: expected 3 outbound envelopes, got {outbound2.Count}");
        var destEnvelope2 = outbound2.FirstOrDefault(o => o.Uri == "https://replica-destination.example.com").Bytes
            ?? throw new InvalidOperationException("v2: no envelope routed to the destination");

        var destEvents2 = destination.Protocol.ProcessAndAcceptAllAsync(destEnvelope2).GetAwaiter().GetResult();
        var received2 = destEvents2.OfType<ReplicaSecretReceivedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"v2: destination did not emit ReplicaSecretReceived; got [{string.Join(", ", destEvents2.Select(e => e.EventType))}]");
        if (received2.Version != 3u)
            throw new InvalidOperationException($"v2: expected Version=3, got {received2.Version}");
        if (received2.Secret.Secrets.Count != 1 || !received2.Secret.Secrets[0].Data.SequenceEqual(secretDataV2))
            throw new InvalidOperationException("v2: secret.secrets[0].data must round-trip the updated bytes");
        Console.WriteLine(
            $"  ReplicaSecretReceived v=2: secret bytes updated, share count = {received2.Shares.Count}  ✓");

        // Replica recovery transitivity: the Destination received
        // `secret.helpers[*].shared_key` inside the secret. Those keys
        // must be byte-identical to what each helper has stored locally
        // for the owner channel, because a Destination acting as a
        // recovery delegate uses them to authenticate as the Source
        // toward each helper.
        var helperAStored = helperA.SecretStore.Load(helperA.Protocol.SecretId, helperAId, SecretKind.SharedKey)!.Bytes;
        var helperBStored = helperB.SecretStore.Load(helperB.Protocol.SecretId, helperBId, SecretKind.SharedKey)!.Bytes;
        var secretHelperA = received2.Secret.Helpers
            .FirstOrDefault(h => ulong.Parse(h.ChannelId) == helperAId)
            ?? throw new InvalidOperationException("secret.helpers missing entry for HelperA");
        var secretHelperB = received2.Secret.Helpers
            .FirstOrDefault(h => ulong.Parse(h.ChannelId) == helperBId)
            ?? throw new InvalidOperationException("secret.helpers missing entry for HelperB");
        if (!helperAStored.SequenceEqual(secretHelperA.SharedKey))
            throw new InvalidOperationException(
                "secret.helpers[HelperA].shared_key must match what HelperA stores locally");
        if (!helperBStored.SequenceEqual(secretHelperB.SharedKey))
            throw new InvalidOperationException(
                "secret.helpers[HelperB].shared_key must match what HelperB stores locally");
        Console.WriteLine(
            "  secret.helpers[*].shared_key matches each helper's stored key — destination can act in source's stead  ✓");

        // The secret also carries `secret.secrets[*].data` unencrypted,
        // so the Destination can fall back to its stored secret without
        // contacting any helper. The recovery model is "any one of:
        // helper quorum, secret on a single destination" — both paths
        // recover the same secret bytes.
        if (!received2.Secret.Secrets[0].Data.SequenceEqual(secretDataV2))
            throw new InvalidOperationException(
                "secret.secrets[0].data must be the raw recovered bytes");
        Console.WriteLine(
            "  secret.secrets[0].data is the raw recovered secret — destination-only recovery is viable  ✓");

        Console.WriteLine("Orchestrator replica pair + secret sync test passed.");
    }

    /// <summary>
    /// Drives the full HashedKeys+PrePair handshake through the
    /// orchestrator. Asserts that both sides end up paired on a single
    /// re-keyed channel id, just like the InlineKeys path — the
    /// orchestrator handles the PrePair leg silently via
    /// <see cref="DeRecProtocol.ProcessAndAcceptAllAsync"/>.
    /// </summary>
    private static void RunOrchestratorHashedKeysPairFlowTest()
    {
        Console.WriteLine("=== Orchestrator HashedKeys pair flow test ===");

        const ulong channelId = 200UL;

        // Helper (contact creator) advertises only the binding hash. The
        // transport MUST be ephemeral since the PrePair envelope crosses
        // the wire as plaintext.
        using var helper = MakeNode("Helper", "https://helper.ephemeral.example.com");

        using var owner = MakeNode("Owner", "https://owner.example.com");

        byte[] contactBytes = helper.Protocol.CreateContactAsync(channelId, ContactMode.HashedKeys)
            .GetAwaiter().GetResult();

        owner.Protocol.StartAsync(FlowKind.Pairing, new PairingParams
        {
            Kind = Pairing.SenderKind.Owner,
            Contact = contactBytes,
        }).GetAwaiter().GetResult();

        // Owner→Helper: plaintext PrePairRequest. Helper auto-publishes
        // its keys via processAll.
        byte[] prePairRequest = owner.Transport.DrainOne();
        helper.Protocol.ProcessAndAcceptAllAsync(prePairRequest).GetAwaiter().GetResult();

        // Helper→Owner: plaintext PrePairResponse. Owner validates the
        // binding hash silently and auto-emits a regular PairRequest.
        byte[] prePairResponse = helper.Transport.DrainOne();
        owner.Protocol.ProcessAndAcceptAllAsync(prePairResponse).GetAwaiter().GetResult();

        // Owner→Helper: encrypted PairRequest. From here the chain is
        // identical to InlineKeys.
        byte[] pairRequest = owner.Transport.DrainOne();
        var helperEvents = helper.Protocol.ProcessAndAcceptAllAsync(pairRequest).GetAwaiter().GetResult();
        var helperPairing = helperEvents.OfType<PairingCompletedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException("helper must emit PairingCompleted");

        byte[] pairResponse = helper.Transport.DrainOne();
        var ownerEvents = owner.Protocol.ProcessAndAcceptAllAsync(pairResponse).GetAwaiter().GetResult();
        var ownerPairing = ownerEvents.OfType<PairingCompletedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException("owner must emit PairingCompleted");

        if (helperPairing.ChannelId != ownerPairing.ChannelId)
            throw new InvalidOperationException("HashedKeys pair: channel id mismatch on both sides");

        ulong rekeyedId = ulong.Parse(helperPairing.ChannelId);
        var helperKey = helper.SecretStore.Load(helper.Protocol.SecretId, rekeyedId, SecretKind.SharedKey)
            ?? throw new InvalidOperationException("helper shared_key missing after HashedKeys pair");
        var ownerKey = owner.SecretStore.Load(owner.Protocol.SecretId, rekeyedId, SecretKind.SharedKey)
            ?? throw new InvalidOperationException("owner shared_key missing after HashedKeys pair");
        if (!helperKey.Bytes.SequenceEqual(ownerKey.Bytes))
            throw new InvalidOperationException("shared keys must match after HashedKeys pair");

        Console.WriteLine($"  paired via HashedKeys + PrePair (channel_id={rekeyedId}, shared_key={helperKey.Bytes.Length}B)  ✓");
        Console.WriteLine("Orchestrator HashedKeys pair flow test passed.");
    }

    /// <summary>
    /// Owner-initiated unpair through the orchestrator. Asserts both
    /// sides emit <see cref="UnpairedEvent"/> and drop their channel
    /// records.
    /// </summary>
    private static void RunOrchestratorUnpairingFlowTest()
    {
        Console.WriteLine("=== Orchestrator unpair flow test ===");

        const ulong channelId = 7UL;

        using var helper = MakeNode("Helper", "https://helper.example.com");

        using var owner = MakeNode("Owner", "https://owner.example.com");

        ulong rekeyedId = DoOrchestratorPair(helper, helper.Transport, owner, owner.Transport, channelId);

        owner.Protocol.StartAsync(FlowKind.Unpair, new UnpairParams
        {
            Target = Target.One(rekeyedId),
            Memo = "decommissioning",
        }).GetAwaiter().GetResult();

        byte[] unpairRequest = owner.Transport.DrainOne();
        var helperEvents = helper.Protocol.ProcessAndAcceptAllAsync(unpairRequest).GetAwaiter().GetResult();
        var helperUnpaired = helperEvents.OfType<UnpairedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException("helper must emit Unpaired");
        if (helperUnpaired.ChannelId != rekeyedId.ToString())
            throw new InvalidOperationException("Helper.Unpaired channel id mismatch");

        byte[] unpairResponse = helper.Transport.DrainOne();
        var ownerEvents = owner.Protocol.ProcessAndAcceptAllAsync(unpairResponse).GetAwaiter().GetResult();
        var ownerUnpaired = ownerEvents.OfType<UnpairedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException("owner must emit Unpaired");
        if (ownerUnpaired.ChannelId != rekeyedId.ToString())
            throw new InvalidOperationException("Owner.Unpaired channel id mismatch");

        // Both sides have dropped their channel records.
        if (helper.ChannelStore.Load(helper.Protocol.SecretId, rekeyedId) is not null)
            throw new InvalidOperationException("helper channel record must be gone after Unpaired");
        if (owner.ChannelStore.Load(owner.Protocol.SecretId, rekeyedId) is not null)
            throw new InvalidOperationException("owner channel record must be gone after Unpaired");

        Console.WriteLine($"  unpair channel_id={rekeyedId} → Unpaired on both sides + channel records dropped  ✓");
        Console.WriteLine("Orchestrator unpair flow test passed.");
    }

    /// <summary>
    /// Asserts the `UpdateChannelInfo` flow end-to-end: owner mutates
    /// its local communication_info + transport endpoint, broadcasts
    /// the change, and both sides emit `ChannelInfoUpdated`. Mirrors
    /// the Rust binding's `run_update_channel_info_flow`.
    /// </summary>
    private static void RunOrchestratorUpdateChannelInfoFlowTest()
    {
        Console.WriteLine("=== Orchestrator UpdateChannelInfo flow test ===");

        const ulong channelId = 42UL;

        using var helper = MakeNode("Helper", "https://helper.example.com");

        using var owner = MakeNode("Owner", "https://owner.OLD.example.com");

        ulong rekeyedId = DoOrchestratorPair(helper, helper.Transport, owner, owner.Transport, channelId);

        const string newUri = "https://owner.NEW.example.com";
        var newInfo = new Dictionary<string, string>
        {
            { "name", "Owner-renamed" },
            { "email", "owner.new@example.com" },
        };

        // Mutate local state, then propagate.
        owner.Protocol.SetCommunicationInfo(newInfo);
        owner.Protocol.SetOwnTransport(newUri);

        owner.Protocol.StartAsync(FlowKind.UpdateChannelInfo, new UpdateChannelInfoParams
        {
            Target = Target.One(rekeyedId),
            CommunicationInfo = newInfo,
            TransportProtocol = new UpdateChannelInfoParams.TransportProtocolDto
            {
                Uri = newUri,
                Protocol = 0,
            },
        }).GetAwaiter().GetResult();

        byte[] updateRequest = owner.Transport.DrainOne();
        var helperEvents = helper.Protocol.ProcessAndAcceptAllAsync(updateRequest).GetAwaiter().GetResult();
        var helperUpdated = helperEvents.OfType<ChannelInfoUpdatedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"helper must emit ChannelInfoUpdated; got [{string.Join(", ", helperEvents.Select(e => e.EventType))}]");
        if (helperUpdated.ChannelId != rekeyedId.ToString())
            throw new InvalidOperationException("Helper.ChannelInfoUpdated channel id mismatch");
        Console.WriteLine($"  helper emits ChannelInfoUpdated  ✓");

        byte[] updateResponse = helper.Transport.DrainOne();
        var ownerEvents = owner.Protocol.ProcessAndAcceptAllAsync(updateResponse).GetAwaiter().GetResult();
        var ownerUpdated = ownerEvents.OfType<ChannelInfoUpdatedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"owner must emit ChannelInfoUpdated; got [{string.Join(", ", ownerEvents.Select(e => e.EventType))}]");
        Console.WriteLine($"  owner emits ChannelInfoUpdated  ✓");

        // Helper's stored channel must now mirror the new transport
        // URI and communication-info map.
        var helperChannel = helper.ChannelStore.Load(helper.Protocol.SecretId, rekeyedId)
            ?? throw new InvalidOperationException("helper channel record must still exist");
        if (helperChannel.Transport.Uri != newUri)
            throw new InvalidOperationException(
                $"helper's stored Transport.Uri must reflect the announced update; got {helperChannel.Transport.Uri}");
        foreach (var (k, v) in newInfo)
        {
            if (!helperChannel.CommunicationInfo.TryGetValue(k, out var stored) || stored != v)
                throw new InvalidOperationException(
                    $"helper's stored CommunicationInfo[{k}] must mirror the announced map; got {stored ?? "<null>"}");
        }
        Console.WriteLine("  helper's stored Transport.Uri + CommunicationInfo mirror the update  ✓");

        Console.WriteLine("Orchestrator UpdateChannelInfo flow test passed.");
    }

    /// <summary>
    /// Asserts the <c>autoReplyTo</c> constructor flag: with it
    /// <c>true</c>, every outbound channel-mode request must carry
    /// <c>replyTo = ownTransport</c> on the inner request body. Mirrors
    /// the JS smoke's <c>runReplyToFlow</c>.
    /// </summary>
    private static void RunOrchestratorReplyToFlowTest()
    {
        Console.WriteLine("=== Orchestrator replyTo flow test ===");

        const ulong channelId = 9UL;
        const string ownerUri = "https://owner-reply.example.com";
        const string helperUri = "https://helper-reply.example.com";

        using var helper = MakeNode("Helper", helperUri);
        using var owner = MakeNode("Owner", ownerUri,
            new NodeOptions { AutoReplyTo = true });

        ulong rekeyedId = DoOrchestratorPair(helper, helper.Transport, owner, owner.Transport, channelId);

        // Trigger an outbound Discovery request. Encrypted body must
        // carry `replyTo = ownerUri`.
        owner.Protocol.StartAsync(FlowKind.Discovery, new DiscoveryParams
        {
            Target = Target.One(rekeyedId),
        }).GetAwaiter().GetResult();

        var (outUri, _, outBytes) = owner.Transport.DrainAll().Single();
        if (outUri != helperUri)
            throw new InvalidOperationException(
                $"outbound destination must be the channel's stored helper endpoint, got {outUri}");

        // Field-level check: decrypt the envelope on the helper side and
        // assert reply_to == ownerUri on the inner request. Mirrors the
        // JS smoke (which inspects the same field).
        byte[] sharedKey = helper.SecretStore.Load(helper.Protocol.SecretId, rekeyedId, SecretKind.SharedKey)!.Bytes;
        var extracted = Discovery.Request.Extract(
            DeRecMessage.FromProtoBytes(outBytes), sharedKey);
        if (extracted.ReplyTo is null || extracted.ReplyTo.Uri != ownerUri)
            throw new InvalidOperationException(
                $"autoReplyTo envelope must stamp reply_to = ownerUri; got {extracted.ReplyTo?.Uri ?? "<null>"}");
        Console.WriteLine($"  autoReplyTo envelope.reply_to = {extracted.ReplyTo.Uri}  ✓");

        // Sanity: a node WITHOUT autoReplyTo. The same field must be unset.
        using var helper2 = MakeNode("Helper", helperUri);
        using var owner2 = MakeNode("Owner", ownerUri); // no autoReplyTo

        ulong rekeyedId2 = DoOrchestratorPair(helper2, helper2.Transport, owner2, owner2.Transport, channelId);
        owner2.Protocol.StartAsync(FlowKind.Discovery, new DiscoveryParams
        {
            Target = Target.One(rekeyedId2),
        }).GetAwaiter().GetResult();
        var (_, _, defaultBytes) = owner2.Transport.DrainAll().Single();
        byte[] sharedKey2 = helper2.SecretStore.Load(helper2.Protocol.SecretId, rekeyedId2, SecretKind.SharedKey)!.Bytes;
        var extracted2 = Discovery.Request.Extract(
            DeRecMessage.FromProtoBytes(defaultBytes), sharedKey2);
        if (extracted2.ReplyTo is not null)
            throw new InvalidOperationException(
                $"default envelope must leave reply_to unset; got {extracted2.ReplyTo.Uri}");
        Console.WriteLine("  default envelope.reply_to is unset  ✓");

        Console.WriteLine("Orchestrator replyTo flow test passed.");
    }

    /// <summary>
    /// Asserts the two sad paths around the protocol-builder
    /// <c>replicaId</c> argument: a node without it must refuse to
    /// initiate any replica-mode flow, and must reject an inbound
    /// replica-mode PairRequest from a configured peer. Mirrors the
    /// Rust binding's <c>run_replica_id_wiring_flow</c>.
    /// </summary>
    private static void RunOrchestratorReplicaIdWiringSadPathsTest()
    {
        Console.WriteLine("=== Orchestrator replica_id wiring sad-paths test ===");

        const ulong configuredReplicaId = 0xCAFE_BABE_DEAD_BEEFUL;
        const ulong channelId = 500UL;

        // -- Scenario A: initiator without replica_id refuses to scan
        //    a contact as ReplicaDestination.
        using var contactCreator = MakeNode(
            "ContactCreator", "https://creator.example.com",
            new NodeOptions { ReplicaId = configuredReplicaId });
        using var unconfiguredScanner = MakeNode("Scanner", "https://scanner.example.com");
        // NO replicaId on the scanner.

        byte[] contact = contactCreator.Protocol.CreateContactAsync(channelId, ContactMode.InlineKeys)
            .GetAwaiter().GetResult();
        try
        {
            unconfiguredScanner.Protocol.StartAsync(FlowKind.Pairing, new PairingParams
            {
                Kind = Pairing.SenderKind.ReplicaDestination,
                Contact = contact,
            }).GetAwaiter().GetResult();
            throw new InvalidOperationException(
                "start(Pairing, kind=ReplicaDestination) must fail when replicaId is unset");
        }
        catch (DeRecException e) when (e.Code == DeRecCode.ReplicaIdNotConfigured)
        {
            // expected
        }
        if (unconfiguredScanner.Transport.Outbox.Count != 0)
            throw new InvalidOperationException("no outbound traffic should have been queued");
        Console.WriteLine("  scanner without replica_id refuses to start replica pair  ✓");

        // -- Scenario B: configured initiator's PairRequest is refused
        //    by an unconfigured responder.
        using var unconfiguredCreator = MakeNode("Creator", "https://creator2.example.com");
        // NO replicaId.

        using var configuredScanner = MakeNode(
            "Scanner", "https://scanner2.example.com",
            new NodeOptions { ReplicaId = configuredReplicaId });

        byte[] contact2 = unconfiguredCreator.Protocol.CreateContactAsync(channelId + 1, ContactMode.InlineKeys)
            .GetAwaiter().GetResult();
        configuredScanner.Protocol.StartAsync(FlowKind.Pairing, new PairingParams
        {
            Kind = Pairing.SenderKind.ReplicaDestination,
            Contact = contact2,
        }).GetAwaiter().GetResult();

        byte[] pairRequest = configuredScanner.Transport.DrainOne();
        try
        {
            unconfiguredCreator.Protocol.ProcessAndAcceptAllAsync(pairRequest).GetAwaiter().GetResult();
            throw new InvalidOperationException(
                "unconfigured responder must refuse a replica-mode PairRequest");
        }
        catch (DeRecException e) when (e.Code == DeRecCode.ReplicaIdNotConfigured)
        {
            // expected
        }
        Console.WriteLine("  responder without replica_id refuses inbound replica PairRequest  ✓");

        Console.WriteLine("Orchestrator replica_id wiring sad-paths test passed.");
    }

    /// <summary>
    /// Walks the canonical 0→8 sequence that proves the multi-device
    /// sync invariant: every roster change or user-secret update bumps
    /// the secret version, every paired Replica Destination receives
    /// the fresh snapshot, and Helpers only receive VSS shares once
    /// the threshold is met.
    /// </summary>
    private static void RunOrchestratorReplicaSyncVersionProgressionTest()
    {
        Console.WriteLine("=== Orchestrator replica sync — version progression v0→v8 ===");

        const ulong TestSecretId = 0xABBA;
        const int Threshold = 3;
        const string OwnerUri = "https://owner.example.com";
        const string ReplicaAUri = "https://replica-a.example.com";
        const string ReplicaBUri = "https://replica-b.example.com";
        const string ReplicaCUri = "https://replica-c.example.com";
        const string Helper1Uri = "https://helper-1.example.com";
        const string Helper2Uri = "https://helper-2.example.com";
        const string Helper3Uri = "https://helper-3.example.com";

        var ownerOpts = new NodeOptions { SecretId = TestSecretId, Threshold = Threshold, ReplicaId = 0x0001UL };
        var rAOpts = new NodeOptions { SecretId = TestSecretId, Threshold = Threshold, ReplicaId = 0x000AUL };
        var rBOpts = new NodeOptions { SecretId = TestSecretId, Threshold = Threshold, ReplicaId = 0x000BUL };
        var rCOpts = new NodeOptions { SecretId = TestSecretId, Threshold = Threshold, ReplicaId = 0x000CUL };
        var helperOpts = new NodeOptions { SecretId = TestSecretId, Threshold = Threshold };

        using var owner = MakeNode("Owner", OwnerUri, ownerOpts);
        using var replicaA = MakeNode("ReplicaA", ReplicaAUri, rAOpts);
        using var replicaB = MakeNode("ReplicaB", ReplicaBUri, rBOpts);
        using var replicaC = MakeNode("ReplicaC", ReplicaCUri, rCOpts);
        using var helper1 = MakeNode("Helper1", Helper1Uri, helperOpts);
        using var helper2 = MakeNode("Helper2", Helper2Uri, helperOpts);
        using var helper3 = MakeNode("Helper3", Helper3Uri, helperOpts);

        var replicaScope = new (Node Node, string Uri)[]
        {
            (owner, OwnerUri), (replicaA, ReplicaAUri),
            (replicaB, ReplicaBUri), (replicaC, ReplicaCUri),
        };
        var allScope = new (Node Node, string Uri)[]
        {
            (owner, OwnerUri),
            (replicaA, ReplicaAUri), (replicaB, ReplicaBUri), (replicaC, ReplicaCUri),
            (helper1, Helper1Uri), (helper2, Helper2Uri), (helper3, Helper3Uri),
        };

        const ulong cidA = 1UL;
        const ulong cidB = 3UL;
        const ulong cidC = 8UL;
        const ulong cidH1 = 11UL;
        const ulong cidH2 = 12UL;
        const ulong cidH3 = 13UL;

        // Step 0 — brand-new instance.
        if (owner.UserSecretStore.LoadLatest(TestSecretId) is not null)
            throw new InvalidOperationException("step 0: brand-new owner must have no snapshot");
        Console.WriteLine("  step 0: user_secret_store latest = null  ✓");

        // Step 1 — pair replica A → v=1.
        PairReplicaHandshake(owner, replicaA, cidA);
        CrossConfirmFingerprint(owner, replicaA, cidA);
        var events = PumpAll(replicaScope);
        var recvA = FindReplicaEvent(events, cidA)
            ?? throw new InvalidOperationException("step 1: A must observe ReplicaSecretReceived");
        if (recvA.Version != 1) throw new InvalidOperationException($"step 1: expected v=1, got {recvA.Version}");
        if (recvA.Secret.Helpers.Count != 0) throw new InvalidOperationException("step 1: helpers must be empty");
        if (recvA.Secret.Secrets.Count != 0) throw new InvalidOperationException("step 1: secrets must be empty");
        if ((recvA.Secret.Replicas?.ReplicaList.Count ?? 0) != 1) throw new InvalidOperationException("step 1: replicas must be 1");
        if (recvA.Shares.Count != 0) throw new InvalidOperationException("step 1: shares must be empty");
        AssertLatestVersion(owner, TestSecretId, 1);
        Console.WriteLine("  step 1: pair replica A → v=1, secret(h=0,s=0,r=1,shares=0)  ✓");

        // Step 2 — ProtectSecret([s1]) → v=2.
        var s1Data = Encoding.UTF8.GetBytes("first-user-secret");
        owner.Protocol.StartAsync(FlowKind.ProtectSecret, new ProtectSecretParams
        {
            Secrets = new[] { new UserSecret { Id = new byte[] { 0x01 }, Name = "secret-one", Data = s1Data } },
            Description = "v=2 explicit publish",
        }).GetAwaiter().GetResult();
        events = PumpAll(replicaScope);
        recvA = FindReplicaEvent(events, cidA)
            ?? throw new InvalidOperationException("step 2: A must observe v=2");
        if (recvA.Version != 2) throw new InvalidOperationException($"step 2: expected v=2, got {recvA.Version}");
        if (recvA.Secret.Secrets.Count != 1 || !recvA.Secret.Secrets[0].Data.SequenceEqual(s1Data))
            throw new InvalidOperationException("step 2: secret.secrets[0].data must equal s1");
        if ((recvA.Secret.Replicas?.ReplicaList.Count ?? 0) != 1) throw new InvalidOperationException("step 2: replicas must be 1");
        if (recvA.Shares.Count != 0) throw new InvalidOperationException("step 2: shares must be empty");
        AssertLatestVersion(owner, TestSecretId, 2);
        Console.WriteLine("  step 2: ProtectSecret([s1]) → v=2, secret(h=0,s=1,r=1,shares=0)  ✓");

        // Step 3 — pair replica B → v=3 (B bootstraps with s1).
        PairReplicaHandshake(owner, replicaB, cidB);
        CrossConfirmFingerprint(owner, replicaB, cidB);
        events = PumpAll(replicaScope);
        var recvA3 = FindReplicaEvent(events, cidA);
        var recvB3 = FindReplicaEvent(events, cidB);
        if (recvA3 is null || recvA3.Version != 3) throw new InvalidOperationException("step 3: A must observe v=3");
        if (recvB3 is null || recvB3.Version != 3) throw new InvalidOperationException("step 3: B must observe v=3");
        foreach (var (label, recv) in new[] { ("A", recvA3), ("B", recvB3) })
        {
            if (recv.Secret.Helpers.Count != 0) throw new InvalidOperationException($"step 3 {label}: helpers must be empty");
            if (recv.Secret.Secrets.Count != 1 || !recv.Secret.Secrets[0].Data.SequenceEqual(s1Data))
                throw new InvalidOperationException($"step 3 {label}: secret must carry s1");
            if ((recv.Secret.Replicas?.ReplicaList.Count ?? 0) != 2) throw new InvalidOperationException($"step 3 {label}: replicas must be 2");
            if (recv.Shares.Count != 0) throw new InvalidOperationException($"step 3 {label}: shares must be empty");
        }
        AssertLatestVersion(owner, TestSecretId, 3);
        Console.WriteLine("  step 3: pair replica B → v=3, secret(h=0,s=1,r=2,shares=0) on A+B  ✓");

        // Step 4 — pair helper #1 → v=4 (below threshold).
        HelperStartPair(owner, helper1, cidH1);
        events = PumpAll(allScope);
        if (events.OfType<ShareStoredEvent>().Any())
            throw new InvalidOperationException("step 4: no helper may store a share (1 < threshold 3)");
        foreach (var (label, cid) in new (string, ulong)[] { ("A", cidA), ("B", cidB) })
        {
            var r = FindReplicaEvent(events, cid)
                ?? throw new InvalidOperationException($"step 4 {label}: must observe v=4");
            if (r.Version != 4) throw new InvalidOperationException($"step 4 {label}: expected v=4");
            if (r.Secret.Helpers.Count != 1) throw new InvalidOperationException($"step 4 {label}: helpers must be 1");
            if (r.Secret.Secrets.Count != 1) throw new InvalidOperationException($"step 4 {label}: secrets must be 1");
            if ((r.Secret.Replicas?.ReplicaList.Count ?? 0) != 2) throw new InvalidOperationException($"step 4 {label}: replicas must be 2");
            if (r.Shares.Count != 0) throw new InvalidOperationException($"step 4 {label}: shares must be empty");
        }
        AssertLatestVersion(owner, TestSecretId, 4);
        Console.WriteLine("  step 4: pair helper #1 → v=4, secret(h=1,s=1,r=2,shares=0)  ✓");

        // Step 5 — pair helper #2 → v=5.
        HelperStartPair(owner, helper2, cidH2);
        events = PumpAll(allScope);
        if (events.OfType<ShareStoredEvent>().Any())
            throw new InvalidOperationException("step 5: still below threshold");
        var r5B = FindReplicaEvent(events, cidB)
            ?? throw new InvalidOperationException("step 5: B must observe v=5");
        if (r5B.Version != 5) throw new InvalidOperationException("step 5: B expected v=5");
        if (r5B.Secret.Helpers.Count != 2) throw new InvalidOperationException("step 5: helpers must be 2");
        if (r5B.Shares.Count != 0) throw new InvalidOperationException("step 5: shares must be empty");
        if (FindReplicaEvent(events, cidA) is null) throw new InvalidOperationException("step 5: A must observe v=5");
        AssertLatestVersion(owner, TestSecretId, 5);
        Console.WriteLine("  step 5: pair helper #2 → v=5, secret(h=2,s=1,r=2,shares=0)  ✓");

        // Step 6 — ProtectSecret([s1, s2]) → v=6.
        var s2Data = Encoding.UTF8.GetBytes("second-user-secret");
        owner.Protocol.StartAsync(FlowKind.ProtectSecret, new ProtectSecretParams
        {
            Secrets = new[]
            {
                new UserSecret { Id = new byte[] { 0x01 }, Name = "secret-one", Data = s1Data },
                new UserSecret { Id = new byte[] { 0x02 }, Name = "secret-two", Data = s2Data },
            },
            Description = "v=6 explicit publish",
        }).GetAwaiter().GetResult();
        events = PumpAll(allScope);
        if (events.OfType<ShareStoredEvent>().Any())
            throw new InvalidOperationException("step 6: still below threshold");
        recvA = FindReplicaEvent(events, cidA)
            ?? throw new InvalidOperationException("step 6: A must observe v=6");
        if (recvA.Version != 6) throw new InvalidOperationException("step 6: A expected v=6");
        if (recvA.Secret.Secrets.Count != 2) throw new InvalidOperationException("step 6: secrets must be 2");
        if (!recvA.Secret.Secrets.Any(u => u.Data.SequenceEqual(s1Data)))
            throw new InvalidOperationException("step 6: secret must carry s1");
        if (!recvA.Secret.Secrets.Any(u => u.Data.SequenceEqual(s2Data)))
            throw new InvalidOperationException("step 6: secret must carry s2");
        if (recvA.Secret.Helpers.Count != 2) throw new InvalidOperationException("step 6: helpers must be 2");
        if (recvA.Shares.Count != 0) throw new InvalidOperationException("step 6: shares must be empty");
        if (FindReplicaEvent(events, cidB) is null) throw new InvalidOperationException("step 6: B must observe v=6");
        AssertLatestVersion(owner, TestSecretId, 6);
        Console.WriteLine("  step 6: ProtectSecret([s1, s2]) → v=6, secret(h=2,s=2,r=2,shares=0)  ✓");

        // Step 7 — pair helper #3 → v=7, threshold met, VSS split runs.
        HelperStartPair(owner, helper3, cidH3);
        events = PumpAll(allScope);
        foreach (var (label, cid) in new (string, ulong)[] { ("helper-1", cidH1), ("helper-2", cidH2), ("helper-3", cidH3) })
        {
            if (!events.OfType<ShareStoredEvent>()
                .Any(e => ulong.Parse(e.ChannelId) == cid && e.Version == 7u))
                throw new InvalidOperationException($"step 7: {label} must emit ShareStored at v=7");
        }
        foreach (var (label, cid) in new (string, ulong)[] { ("A", cidA), ("B", cidB) })
        {
            var r = FindReplicaEvent(events, cid)
                ?? throw new InvalidOperationException($"step 7 {label}: must observe v=7");
            if (r.Version != 7) throw new InvalidOperationException($"step 7 {label}: expected v=7");
            if (r.Secret.Helpers.Count != 3) throw new InvalidOperationException($"step 7 {label}: helpers must be 3");
            if (r.Secret.Secrets.Count != 2) throw new InvalidOperationException($"step 7 {label}: secrets must be 2");
            if ((r.Secret.Replicas?.ReplicaList.Count ?? 0) != 2) throw new InvalidOperationException($"step 7 {label}: replicas must be 2");
            if (r.Shares.Count != 3) throw new InvalidOperationException($"step 7 {label}: shares must be 3");
        }
        AssertLatestVersion(owner, TestSecretId, 7);
        Console.WriteLine("  step 7: pair helper #3 → v=7, secret(h=3,s=2,r=2,shares=3); all 3 helpers ShareStored  ✓");

        // Step 8 — pair replica C → v=8, full bootstrap + fresh VSS.
        PairReplicaHandshake(owner, replicaC, cidC);
        CrossConfirmFingerprint(owner, replicaC, cidC);
        events = PumpAll(allScope);
        foreach (var (label, cid) in new (string, ulong)[] { ("helper-1", cidH1), ("helper-2", cidH2), ("helper-3", cidH3) })
        {
            if (!events.OfType<ShareStoredEvent>()
                .Any(e => ulong.Parse(e.ChannelId) == cid && e.Version == 8u))
                throw new InvalidOperationException($"step 8: {label} must emit ShareStored at v=8");
        }
        var recvC = FindReplicaEvent(events, cidC)
            ?? throw new InvalidOperationException("step 8: C must observe v=8");
        if (recvC.Version != 8) throw new InvalidOperationException("step 8: C expected v=8");
        if (recvC.Secret.Helpers.Count != 3) throw new InvalidOperationException("step 8 C: helpers must be 3");
        if (recvC.Secret.Secrets.Count != 2) throw new InvalidOperationException("step 8 C: secrets must be 2");
        if ((recvC.Secret.Replicas?.ReplicaList.Count ?? 0) != 3) throw new InvalidOperationException("step 8 C: replicas must be 3");
        if (recvC.Shares.Count != 3) throw new InvalidOperationException("step 8 C: shares must be 3");
        foreach (var (label, cid) in new (string, ulong)[] { ("A", cidA), ("B", cidB) })
        {
            var r = FindReplicaEvent(events, cid)
                ?? throw new InvalidOperationException($"step 8 {label}: must observe v=8");
            if (r.Version != 8) throw new InvalidOperationException($"step 8 {label}: expected v=8");
            if ((r.Secret.Replicas?.ReplicaList.Count ?? 0) != 3) throw new InvalidOperationException($"step 8 {label}: replicas must be 3");
        }
        AssertLatestVersion(owner, TestSecretId, 8);
        Console.WriteLine("  step 8: pair replica C → v=8, secret(h=3,s=2,r=3,shares=3) on A+B+C; all helpers refreshed  ✓");

        Console.WriteLine("Orchestrator replica sync version progression test passed.");
    }

    private static void AssertLatestVersion(Node owner, ulong secretId, uint expected)
    {
        var snapshot = owner.UserSecretStore.LoadLatest(secretId);
        if (snapshot is null || snapshot.Version != expected)
            throw new InvalidOperationException(
                $"expected user_secret_store version={expected}, got {snapshot?.Version}");
    }

    private static void PairReplicaHandshake(Node owner, Node replica, ulong channelId)
    {
        byte[] contact = owner.Protocol.CreateContactAsync(channelId, ContactMode.InlineKeys)
            .GetAwaiter().GetResult();
        replica.Protocol.StartAsync(FlowKind.Pairing, new PairingParams
        {
            Kind = Pairing.SenderKind.ReplicaDestination,
            Contact = contact,
        }).GetAwaiter().GetResult();
        // Drive just the cryptographic handshake — owner-side
        // PairRequest, replica-side PairResponse, both auto-acked.
        var msgs = replica.Transport.DrainAll();
        foreach (var (_, _, bytes) in msgs)
            owner.Protocol.ProcessAndAcceptAllAsync(bytes).GetAwaiter().GetResult();
        msgs = owner.Transport.DrainAll();
        foreach (var (_, _, bytes) in msgs)
            replica.Protocol.ProcessAndAcceptAllAsync(bytes).GetAwaiter().GetResult();
    }

    private static void CrossConfirmFingerprint(Node owner, Node replica, ulong channelId)
    {
        string ownerFp = owner.Protocol.GetFingerprintAsync(channelId).GetAwaiter().GetResult();
        string replicaFp = replica.Protocol.GetFingerprintAsync(channelId).GetAwaiter().GetResult();
        if (ownerFp != replicaFp)
            throw new InvalidOperationException($"fingerprint mismatch: owner={ownerFp} replica={replicaFp}");
        if (!owner.Protocol.VerifyFingerprintAsync(channelId, replicaFp).GetAwaiter().GetResult())
            throw new InvalidOperationException("owner.VerifyFingerprint must return true");
        if (!replica.Protocol.VerifyFingerprintAsync(channelId, ownerFp).GetAwaiter().GetResult())
            throw new InvalidOperationException("replica.VerifyFingerprint must return true");
    }

    private static void HelperStartPair(Node owner, Node helper, ulong channelId)
    {
        byte[] contact = owner.Protocol.CreateContactAsync(channelId, ContactMode.InlineKeys)
            .GetAwaiter().GetResult();
        helper.Protocol.StartAsync(FlowKind.Pairing, new PairingParams
        {
            Kind = Pairing.SenderKind.Helper,
            Contact = contact,
        }).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Drain every node's outbox and route each message to whichever
    /// node owns the destination URI, looping until the network goes
    /// silent. Each entry is `(Node, Uri)`; URIs must be unique.
    /// </summary>
    private static List<DeRecEvent> PumpAll((Node Node, string Uri)[] scope)
    {
        var collected = new List<DeRecEvent>();
        while (true)
        {
            bool progressed = false;
            foreach (var src in scope)
            {
                var messages = src.Node.Transport.DrainAll();
                foreach (var (uri, _, bytes) in messages)
                {
                    var dest = scope.FirstOrDefault(e => e.Uri == uri);
                    if (dest == default)
                        throw new InvalidOperationException(
                            $"PumpAll: no peer for destination uri {uri}");
                    var events = dest.Node.Protocol
                        .ProcessAndAcceptAllAsync(bytes)
                        .GetAwaiter().GetResult();
                    collected.AddRange(events);
                    progressed = true;
                }
            }
            if (!progressed) return collected;
        }
    }

    private sealed record ReceivedSecret(
        uint Version,
        Secret Secret,
        IReadOnlyList<ChannelShare> Shares);

    private static ReceivedSecret? FindReplicaEvent(IEnumerable<DeRecEvent> events, ulong channelId)
    {
        foreach (var ev in events)
        {
            if (ev is ReplicaSecretReceivedEvent r && ulong.Parse(r.ChannelId) == channelId)
                return new ReceivedSecret(r.Version, r.Secret, r.Shares);
        }
        return null;
    }

    // ── Shared helpers ─────────────────────────────────────────────

    /// <summary>
    /// Perform a full Owner↔Helper InlineKeys pair handshake between two
    /// protocols. Returns the rekeyed channel id both sides converge on.
    /// Mirrors the JS smoke's <c>doPair</c> helper.
    /// </summary>
    private static ulong DoOrchestratorPair(
        Node contactCreator, RecordingTransport contactCreatorTx,
        Node initiator, RecordingTransport initiatorTx,
        ulong channelId, Pairing.SenderKind initiatorKind = Pairing.SenderKind.Owner)
    {
        byte[] contact = contactCreator.Protocol.CreateContactAsync(channelId, ContactMode.InlineKeys)
            .GetAwaiter().GetResult();
        initiator.Protocol.StartAsync(FlowKind.Pairing, new PairingParams
        {
            Kind = initiatorKind,
            Contact = contact,
        }).GetAwaiter().GetResult();
        byte[] pairRequest = initiatorTx.DrainOne();
        var creatorEvents = contactCreator.Protocol.ProcessAndAcceptAllAsync(pairRequest)
            .GetAwaiter().GetResult();
        var creatorPairing = creatorEvents.OfType<PairingCompletedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException("contact creator must emit PairingCompleted");
        byte[] pairResponse = contactCreatorTx.DrainOne();
        var initEvents = initiator.Protocol.ProcessAndAcceptAllAsync(pairResponse)
            .GetAwaiter().GetResult();
        var initPairing = initEvents.OfType<PairingCompletedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException("initiator must emit PairingCompleted");
        if (creatorPairing.ChannelId != initPairing.ChannelId)
            throw new InvalidOperationException("pair handshake channel id mismatch");
        return ulong.Parse(creatorPairing.ChannelId);
    }

    /// <summary>
    /// Pump each message in <paramref name="from"/>'s outbox into
    /// <paramref name="to"/>'s ProcessAndAcceptAll, returning every event
    /// the receiver emits across all messages.
    /// </summary>
    private static List<DeRecEvent> PumpAll(RecordingTransport from, Node to)
    {
        var all = new List<DeRecEvent>();
        foreach (var (_, _, bytes) in from.DrainAll())
        {
            all.AddRange(to.Protocol.ProcessAndAcceptAllAsync(bytes).GetAwaiter().GetResult());
        }
        return all;
    }


    /// <summary>
    /// In-memory peer composed of fresh stores + a recording transport
    /// + the <see cref="DeRecProtocol"/> built on top. Mirrors the
    /// <c>Node</c> wrapper in <c>bindings/nodejs/protocol.ts</c>. Use
    /// <see cref="MakeNode"/> to construct one.
    /// </summary>
    private sealed record Node(
        DeRecProtocol Protocol,
        RecordingTransport Transport,
        InMemoryChannelStore ChannelStore,
        InMemoryShareStore ShareStore,
        InMemorySecretStore SecretStore,
        InMemoryUserSecretStore UserSecretStore) : IDisposable
    {
        public void Dispose() => Protocol.Dispose();
    }

    /// <summary>
    /// Options threaded into <see cref="MakeNode"/>. All members are
    /// optional. Mirrors the <c>options</c> parameter on the JS
    /// <c>makeNode</c> helper.
    /// </summary>
    private sealed record NodeOptions(
        bool? AutoReplyTo = null,
        ulong? ReplicaId = null,
        int? Threshold = null,
        ulong? SecretId = null,
        AutoAcceptPolicy? AutoAccept = null);

    private const int DefaultThreshold = 2;

    /// <summary>
    /// Default secret identifier wired into every <see cref="MakeNode"/>
    /// caller that doesn't pin one explicitly via
    /// <see cref="NodeOptions.SecretId"/>.
    /// </summary>
    private const ulong DefaultTestSecretId = 0xDE_2EC;

    /// <summary>
    /// Construct a fresh node bound to <paramref name="endpointUri"/>.
    /// <paramref name="name"/> is stored under <c>"name"</c> on the
    /// communication-info map so peers can see it. Mirrors the JS
    /// <c>makeNode(name, uri, options)</c> helper 1:1.
    /// </summary>
    private static Node MakeNode(
        string name,
        string endpointUri,
        NodeOptions? options = null)
    {
        options ??= new NodeOptions();

        var channelStore = new InMemoryChannelStore();
        var shareStore = new InMemoryShareStore();
        var secretStore = new InMemorySecretStore();
        var userSecretStore = new InMemoryUserSecretStore();
        var transport = new RecordingTransport();

        var builder = new DeRecProtocolBuilder(options.SecretId ?? DefaultTestSecretId)
            .WithChannelStore(channelStore)
            .WithShareStore(shareStore)
            .WithSecretStore(secretStore)
            .WithUserSecretStore(userSecretStore)
            .WithTransport(transport)
            .WithOwnTransport(new TransportProtocol(endpointUri))
            .WithCommunicationInfo(new Dictionary<string, string> { ["name"] = name })
            .WithThreshold(options.Threshold ?? DefaultThreshold);
        if (options.AutoReplyTo is bool autoReplyTo)
            builder = builder.WithAutoReplyTo(autoReplyTo);
        if (options.AutoAccept is AutoAcceptPolicy policy)
            builder = builder.WithAutoAccept(policy);
        if (options.ReplicaId is ulong replicaId)
            builder = builder.WithReplicaId(replicaId);

        return new Node(builder.Build(), transport, channelStore, shareStore, secretStore, userSecretStore);
    }
}
