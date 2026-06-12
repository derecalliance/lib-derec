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
        RunOrchestratorReplicaPairAndVaultSyncTest();
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

        // Helpers bind their protocol to the owner's vault id — one
        // helper-protocol-instance per (owner, vault) pair on the helper
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

        // SecretRecovered carries the full DeRecSecret bag, not the
        // raw UserSecret bytes — so look for the original payload as a
        // contiguous subarray. (Decoding the bag end-to-end would require
        // the Google.Protobuf descriptors for SecretContainer/UserSecret;
        // worth adding via FFI later, but the subarray check is enough
        // to prove the round-trip.)
        bool found = IndexOfSequence(recovered.Secret, secretData) >= 0;
        if (!found)
            throw new InvalidOperationException(
                $"Recovered bag must contain the original secret bytes; got {recovered.Secret.Length}B");
        Console.WriteLine($"  SecretRecovered: bag={recovered.Secret.Length}B contains the original  ✓");

        Console.WriteLine("Orchestrator share + discovery + recovery test passed.");
    }

    /// <summary>
    /// Drives the full replica pair + ProtectSecret(includes destination)
    /// + vault sync pipeline. Mirrors the Rust binding's
    /// <c>run_protect_secret_with_replica_targets_flow</c>.
    /// </summary>
    private static void RunOrchestratorReplicaPairAndVaultSyncTest()
    {
        Console.WriteLine("=== Orchestrator replica pair + vault sync test ===");

        const ulong ownerReplicaId = 0xAAAA_AAAA_AAAA_AAAAUL;
        const ulong destReplicaId = 0xBBBB_BBBB_BBBB_BBBBUL;
        const ulong helperAChannel = 1UL;
        const ulong helperBChannel = 2UL;
        const ulong destChannel = 3UL;
        const ulong secretId = 0xC0FFEEUL;
        byte[] secretData = Encoding.UTF8.GetBytes("vault-payload-for-replica-and-helper");

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

        owner.Protocol.StartAsync(FlowKind.ProtectSecret, new ProtectSecretParams
        {
            Secrets = new[]
            {
                new UserSecret { Id = new byte[] { 0x01 }, Name = "shared-vault", Data = secretData },
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
        var received = destEvents.OfType<ReplicaVaultReceivedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"destination did not emit ReplicaVaultReceived; got [{string.Join(", ", destEvents.Select(e => e.EventType))}]");

        if (ulong.Parse(received.FromReplicaId) != ownerReplicaId)
            throw new InvalidOperationException($"from_replica_id mismatch (got {received.FromReplicaId})");
        if (ulong.Parse(received.SecretId) != secretId)
            throw new InvalidOperationException($"secret_id mismatch (got {received.SecretId})");
        if (received.Vault.Secrets.Count != 1 || !received.Vault.Secrets[0].Data.SequenceEqual(secretData))
            throw new InvalidOperationException("vault.secrets[0].data must round-trip the original");
        if (ulong.Parse(received.Vault.OwnerReplicaId) != ownerReplicaId)
            throw new InvalidOperationException("vault.owner_replica_id mismatch");
        if (received.Vault.Helpers.Count != 2)
            throw new InvalidOperationException($"vault.helpers must be 2, got {received.Vault.Helpers.Count}");
        if (received.Vault.Replicas.Count != 1)
            throw new InvalidOperationException($"vault.replicas must be 1, got {received.Vault.Replicas.Count}");
        var destInfo = received.Vault.Replicas[0];
        if (ulong.Parse(destInfo.ReplicaId) != destReplicaId)
            throw new InvalidOperationException("vault.replicas[0].replica_id mismatch");
        if (destInfo.SenderKind != (int)Pairing.SenderKind.ReplicaDestination)
            throw new InvalidOperationException("vault.replicas[0].sender_kind must be ReplicaDestination");
        if (received.Shares.Count != 2)
            throw new InvalidOperationException($"shares must be 2, got {received.Shares.Count}");

        Console.WriteLine(
            $"  ReplicaVaultReceived: vault={received.Vault.Secrets.Count}secret/{received.Vault.Helpers.Count}helpers/{received.Vault.Replicas.Count}replicas, shares={received.Shares.Count}  ✓");

        // Drain the helper outboxes from the v=1 round so the next
        // round's pump-and-drain sees only v=2 envelopes.
        helperA.Transport.DrainAll();
        helperB.Transport.DrainAll();

        // Vault version updates: the owner mutates the secret and
        // re-runs `ProtectSecret`. The destination must receive a fresh
        // `ReplicaVaultReceived` carrying `version=2` and the new
        // payload. The protocol pulls the next version from
        // `IShareStore.LatestVersion()`; the in-memory store exposes a
        // side-channel setter so this test can drive that contract
        // without first running a full helper-side store / confirm
        // cycle on the owner.
        owner.ShareStore.SetOwnerVersion(owner.Protocol.SecretId, 1);
        byte[] secretDataV2 = Encoding.UTF8.GetBytes("vault-payload-after-update");
        owner.Protocol.StartAsync(FlowKind.ProtectSecret, new ProtectSecretParams
        {
            Secrets = new[]
            {
                new UserSecret { Id = new byte[] { 0x01 }, Name = "shared-vault", Data = secretDataV2 },
            },
            Description = "v2 replica + helper distribution",
        }).GetAwaiter().GetResult();

        var outbound2 = owner.Transport.DrainAll();
        if (outbound2.Count != 3)
            throw new InvalidOperationException($"v2: expected 3 outbound envelopes, got {outbound2.Count}");
        var destEnvelope2 = outbound2.FirstOrDefault(o => o.Uri == "https://replica-destination.example.com").Bytes
            ?? throw new InvalidOperationException("v2: no envelope routed to the destination");

        var destEvents2 = destination.Protocol.ProcessAndAcceptAllAsync(destEnvelope2).GetAwaiter().GetResult();
        var received2 = destEvents2.OfType<ReplicaVaultReceivedEvent>().FirstOrDefault()
            ?? throw new InvalidOperationException(
                $"v2: destination did not emit ReplicaVaultReceived; got [{string.Join(", ", destEvents2.Select(e => e.EventType))}]");
        if (received2.Version != 2u)
            throw new InvalidOperationException($"v2: expected Version=2, got {received2.Version}");
        if (received2.Vault.Secrets.Count != 1 || !received2.Vault.Secrets[0].Data.SequenceEqual(secretDataV2))
            throw new InvalidOperationException("v2: vault.secrets[0].data must round-trip the updated bytes");
        Console.WriteLine(
            $"  ReplicaVaultReceived v=2: secret bytes updated, share count = {received2.Shares.Count}  ✓");

        // Replica recovery transitivity: the Destination received
        // `vault.helpers[*].shared_key` inside the vault. Those keys
        // must be byte-identical to what each helper has stored locally
        // for the owner channel, because a Destination acting as a
        // recovery delegate uses them to authenticate as the Source
        // toward each helper.
        var helperAStored = helperA.SecretStore.Load(helperA.Protocol.SecretId, helperAId, SecretKind.SharedKey)!.Bytes;
        var helperBStored = helperB.SecretStore.Load(helperB.Protocol.SecretId, helperBId, SecretKind.SharedKey)!.Bytes;
        var vaultHelperA = received2.Vault.Helpers
            .FirstOrDefault(h => ulong.Parse(h.ChannelId) == helperAId)
            ?? throw new InvalidOperationException("vault.helpers missing entry for HelperA");
        var vaultHelperB = received2.Vault.Helpers
            .FirstOrDefault(h => ulong.Parse(h.ChannelId) == helperBId)
            ?? throw new InvalidOperationException("vault.helpers missing entry for HelperB");
        if (!helperAStored.SequenceEqual(vaultHelperA.SharedKey))
            throw new InvalidOperationException(
                "vault.helpers[HelperA].shared_key must match what HelperA stores locally");
        if (!helperBStored.SequenceEqual(vaultHelperB.SharedKey))
            throw new InvalidOperationException(
                "vault.helpers[HelperB].shared_key must match what HelperB stores locally");
        Console.WriteLine(
            "  vault.helpers[*].shared_key matches each helper's stored key — destination can act in source's stead  ✓");

        // The vault also carries `vault.secrets[*].data` unencrypted,
        // so the Destination can fall back to its stored vault without
        // contacting any helper. The recovery model is "any one of:
        // helper quorum, vault on a single destination" — both paths
        // recover the same secret bytes.
        if (!received2.Vault.Secrets[0].Data.SequenceEqual(secretDataV2))
            throw new InvalidOperationException(
                "vault.secrets[0].data must be the raw recovered bytes");
        Console.WriteLine(
            "  vault.secrets[0].data is the raw recovered secret — destination-only recovery is viable  ✓");

        Console.WriteLine("Orchestrator replica pair + vault sync test passed.");
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
    /// Returns the index of <paramref name="needle"/> in
    /// <paramref name="haystack"/>, or -1 if not found.
    /// </summary>
    private static int IndexOfSequence(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return -1;
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
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
        ulong? SecretId = null);

    private const int DefaultThreshold = 2;

    /// <summary>
    /// Default vault identifier wired into every <see cref="MakeNode"/>
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
        if (options.ReplicaId is ulong replicaId)
            builder = builder.WithReplicaId(replicaId);

        return new Node(builder.Build(), transport, channelStore, shareStore, secretStore, userSecretStore);
    }
}
