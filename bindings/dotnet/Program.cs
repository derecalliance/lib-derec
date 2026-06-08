// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using DeRec.Library;
using DeRec.Library.Primitives;
using Proto = Org.Derecalliance.Derec.Protobuf;

internal static class Program
{
    private static void Main()
    {
        RunProtocolVersionTest();
        RunPairingFlowTest();
        RunPairingFlowHashedKeysTest();
        RunSharingFlowTest();
        RunVerificationFlowTest();
        RunRecoveryFlowTest();
        RunDiscoveryFlowTest();
        RunUnpairingFlowTest();
        RunEnvelopeAndReplyToTest();

        Console.WriteLine("All smoke tests passed.");
    }

    private static void RunProtocolVersionTest()
    {
        Console.WriteLine("=== Protocol version test ===");
        var version = ProtocolVersion.Current();
        Console.WriteLine($"protocol version = {version}");
        Console.WriteLine("Protocol version test passed.");
    }

    private static void RunPairingFlowTest()
    {
        Console.WriteLine("=== Pairing flow test (INLINE_KEYS) ===");

        ulong channelId = 1;

        // Contact carries the keys inline — no PrePair round-trip is needed.
        var contact = Pairing.Request.CreateContact(
            channelId,
            ContactMode.InlineKeys,
            new TransportProtocol("https://example.com/alice")
        );

        if (contact.SecretKeyMaterial.Length == 0)
            throw new InvalidOperationException("Pairing test failed: empty contact secret key material.");

        var pairRequest = Pairing.Request.Produce(
            Pairing.SenderKind.Helper,
            new TransportProtocol("https://example.com/helper"),
            contact.ContactMessage
        );

        if (pairRequest.SecretKeyMaterial.Length == 0)
            throw new InvalidOperationException("Pairing test failed: empty pair request secret key material.");

        // Contact-initiator side: extract then produce the response
        var extractedRequest = Pairing.Request.Extract(pairRequest.Envelope, contact.SecretKeyMaterial);
        if (extractedRequest.ChannelId != channelId)
            throw new InvalidOperationException("Pairing test failed: channel_id mismatch on extract.");

        var produced = Pairing.Response.Produce(
            channelId,
            extractedRequest.RequestProtoBytes,
            contact.SecretKeyMaterial
        );

        if (produced.SharedKey.Length == 0)
            throw new InvalidOperationException("Pairing test failed: empty shared key.");

        // Contact-responder side: extract then process
        var extractedResponse = Pairing.Response.Extract(produced.Envelope, pairRequest.SecretKeyMaterial);
        if (extractedResponse.ChannelId != channelId)
            throw new InvalidOperationException("Pairing test failed: channel_id mismatch on response extract.");

        var processed = Pairing.Response.Process(
            pairRequest.InitiatorContactMessage,
            extractedResponse.ResponseProtoBytes,
            pairRequest.SecretKeyMaterial
        );

        if (!produced.SharedKey.SequenceEqual(processed.SharedKey))
            throw new InvalidOperationException("Pairing test failed: shared keys do not match.");
        if (produced.ChannelId != processed.ChannelId)
            throw new InvalidOperationException($"Pairing test failed: rekeyed channel id mismatch (produce={produced.ChannelId} process={processed.ChannelId}).");
        if (produced.ChannelId == channelId)
            throw new InvalidOperationException("Pairing test failed: rekeyed channel id must differ from the pre-rekey id.");
        Console.WriteLine($"  channel id rekeyed: {channelId} → {produced.ChannelId}");

        Console.WriteLine("Pairing flow test (INLINE_KEYS) passed.");
    }

    private static void RunPairingFlowHashedKeysTest()
    {
        Console.WriteLine("=== Pairing flow test (HASHED_KEYS + PrePair) ===");

        ulong channelId = 2;

        // Alice creates a HASHED_KEYS contact. The transport MUST be ephemeral
        // because the PrePair messages cross the wire as plaintext.
        var aliceContact = Pairing.Request.CreateContact(
            channelId,
            ContactMode.HashedKeys,
            new TransportProtocol("https://example.com/alice/ephemeral")
        );

        if (aliceContact.ContactMessage.ContactMode != ContactMode.HashedKeys)
            throw new InvalidOperationException("HASHED_KEYS contact must advertise contact_mode = HashedKeys.");
        if (aliceContact.ContactMessage.MlkemEncapsulationKey is not null)
            throw new InvalidOperationException("HASHED_KEYS contact must NOT carry the ML-KEM key inline.");
        if (aliceContact.ContactMessage.EciesPublicKey is not null)
            throw new InvalidOperationException("HASHED_KEYS contact must NOT carry the ECIES key inline.");
        if (aliceContact.ContactMessage.ContactBindingHash is not { Length: 48 })
            throw new InvalidOperationException("HASHED_KEYS contact must carry a 48-byte SHA-384 binding hash.");
        Console.WriteLine("  contact carries 48-byte binding hash, no inline keys");


        // Bob (the scanner) sends a plaintext PrePair request asking for the keys.
        var prePairRequestEnvelope = Pairing.Request.ProducePrePair(
            new TransportProtocol("https://example.com/helper/ephemeral"),
            aliceContact.ContactMessage
        );

        // Alice decodes the inbound plaintext request.
        var extractedPrePairReq = Pairing.Request.ExtractPrePair(prePairRequestEnvelope.Envelope);
        if (extractedPrePairReq.ChannelId != channelId)
            throw new InvalidOperationException("PrePair request envelope must route to the contact's channel.");

        // Alice publishes the public keys back to Bob.
        var prePairResponseEnvelope = Pairing.Response.ProducePrePair(
            channelId,
            extractedPrePairReq.RequestProtoBytes,
            aliceContact.SecretKeyMaterial
        );

        // Bob decodes the inbound plaintext response.
        var extractedPrePairResp = Pairing.Response.ExtractPrePair(prePairResponseEnvelope.Envelope);
        if (extractedPrePairResp.ChannelId != channelId)
            throw new InvalidOperationException("PrePair response envelope must route to the contact's channel.");

        // Bob recomputes the SHA-384 binding hash and validates it against the
        // commitment from the original contact. Any tampering on the plaintext
        // PrePair leg surfaces here.
        var validated = Pairing.Response.ProcessPrePair(
            aliceContact.ContactMessage,
            extractedPrePairResp.ResponseProtoBytes
        );
        if (validated.MlkemEncapsulationKey.Length == 0)
            throw new InvalidOperationException("PrePair validation must return Alice's ML-KEM encapsulation key.");
        if (validated.EciesPublicKey.Length == 0)
            throw new InvalidOperationException("PrePair validation must return Alice's ECIES public key.");
        if (validated.Nonce != aliceContact.ContactMessage.Nonce)
            throw new InvalidOperationException("PrePair validation must echo the contact's nonce.");
        Console.WriteLine($"  PrePair validated (mlkem={validated.MlkemEncapsulationKey.Length}B, ecies={validated.EciesPublicKey.Length}B, nonce echoed)");


        // Bob synthesizes a "filled-in" contact by copying the validated keys
        // into the HASHED_KEYS contact. From here on the flow is identical to
        // the INLINE_KEYS path.
        var filledInContact = aliceContact.ContactMessage with
        {
            MlkemEncapsulationKey = validated.MlkemEncapsulationKey,
            EciesPublicKey = validated.EciesPublicKey,
        };

        var pairRequest = Pairing.Request.Produce(
            Pairing.SenderKind.Helper,
            new TransportProtocol("https://example.com/helper"),
            filledInContact
        );

        var extractedRequest = Pairing.Request.Extract(pairRequest.Envelope, aliceContact.SecretKeyMaterial);
        if (extractedRequest.ChannelId != channelId)
            throw new InvalidOperationException("HASHED_KEYS pairing: channel_id mismatch on extract.");

        var produced = Pairing.Response.Produce(
            channelId,
            extractedRequest.RequestProtoBytes,
            aliceContact.SecretKeyMaterial
        );
        if (produced.SharedKey.Length == 0)
            throw new InvalidOperationException("HASHED_KEYS pairing: empty shared key.");

        var extractedResponse = Pairing.Response.Extract(produced.Envelope, pairRequest.SecretKeyMaterial);
        var processed = Pairing.Response.Process(
            pairRequest.InitiatorContactMessage,
            extractedResponse.ResponseProtoBytes,
            pairRequest.SecretKeyMaterial
        );

        if (!produced.SharedKey.SequenceEqual(processed.SharedKey))
            throw new InvalidOperationException("HASHED_KEYS pairing: shared keys do not match.");
        if (produced.ChannelId != processed.ChannelId)
            throw new InvalidOperationException($"HASHED_KEYS pairing: rekeyed channel id mismatch (produce={produced.ChannelId} process={processed.ChannelId}).");
        if (produced.ChannelId == channelId)
            throw new InvalidOperationException("HASHED_KEYS pairing: rekeyed channel id must differ from the pre-rekey id.");

        Console.WriteLine($"  shared keys match ({produced.SharedKey.Length}B)");
        Console.WriteLine($"  channel id rekeyed: {channelId} → {produced.ChannelId}");
        Console.WriteLine("Pairing flow test (HASHED_KEYS + PrePair) passed.");
    }

    private static void RunSharingFlowTest()
    {
        Console.WriteLine("=== Sharing flow test ===");

        ulong secretId = 0xCAFEBABEUL;
        byte[] secretData = new byte[] { 5, 6, 7, 8, 255 };
        ulong[] channelIds = new ulong[] { 1, 2, 3 };
        ulong threshold = 2;
        uint version = 1;

        var splitResult = Sharing.Request.Split(secretId, secretData, channelIds, threshold, version);
        var shares = splitResult.DeserializeShares();

        if (shares.Count != channelIds.Length)
            throw new InvalidOperationException($"Sharing test failed: expected {channelIds.Length} shares but got {shares.Count}.");

        var sharedKeys = CreateChannelSharedKeys(channelIds);

        foreach (var entry in shares)
        {
            ulong channel = entry.Key;
            byte[] shareBytes = entry.Value;

            if (shareBytes.Length == 0)
                throw new InvalidOperationException($"Sharing test failed: empty share bytes for channel {channel}.");

            DeRecMessage requestEnvelope = Sharing.Request.Produce(
                channel, version, secretId, shareBytes,
                Array.Empty<uint>(), string.Empty, sharedKeys[channel]
            );

            // Helper side: extract then produce response
            var extractedRequest = Sharing.Request.Extract(requestEnvelope, sharedKeys[channel]);

            var storeResponse = Sharing.Response.Produce(
                channel,
                extractedRequest.RequestProtoBytes,
                sharedKeys[channel]
            );

            if (storeResponse.CommittedShareBytes.Length == 0)
                throw new InvalidOperationException($"Sharing test failed: empty committed_share_bytes for channel {channel}.");
            if (storeResponse.SecretId != secretId)
                throw new InvalidOperationException($"Sharing test failed: secret_id mismatch for channel {channel}.");
            if (storeResponse.Version != version)
                throw new InvalidOperationException($"Sharing test failed: version mismatch for channel {channel}.");

            var committedShare = Proto.CommittedDeRecShare.Parser.ParseFrom(storeResponse.CommittedShareBytes);
            var deRecShare = Proto.DeRecShare.Parser.ParseFrom(committedShare.DeRecShare.ToByteArray());
            if (deRecShare.Version != version)
                throw new InvalidOperationException("Sharing test failed: inner DeRecShare version mismatch.");

            // Owner side: extract then process
            var extractedResponse = Sharing.Response.Extract(storeResponse.Envelope, sharedKeys[channel]);
            Sharing.Response.Process(version, extractedResponse.ResponseProtoBytes);
        }

        Console.WriteLine("Sharing flow test passed.");
    }

    private static void RunVerificationFlowTest()
    {
        Console.WriteLine("=== Verification flow test ===");

        ulong secretId = 0xCAFEBABEUL;
        byte[] secretData = new byte[] { 5, 6, 7, 8, 255 };
        ulong[] channels = new ulong[] { 1, 2, 3 };
        ulong threshold = 2;
        uint version = 1;

        var sharedKeys = CreateChannelSharedKeys(channels);

        var shares = Sharing.Request.Split(secretId, secretData, channels, threshold, version)
            .DeserializeShares();

        ulong channel1 = 1;
        ulong channel2 = 2;
        byte[] sharedKey1 = sharedKeys[channel1];

        // Helper's stored share is the *extracted* inner StoreShareRequestMessage
        DeRecMessage storeEnv1 = Sharing.Request.Produce(
            channel1, version, secretId, shares[channel1], Array.Empty<uint>(), string.Empty, sharedKey1
        );
        DeRecMessage storeEnv2 = Sharing.Request.Produce(
            channel2, version, secretId, shares[channel2], Array.Empty<uint>(), string.Empty, sharedKey1
        );
        byte[] storedShare1 = Sharing.Request.Extract(storeEnv1, sharedKey1).RequestProtoBytes;
        byte[] storedShare2 = Sharing.Request.Extract(storeEnv2, sharedKey1).RequestProtoBytes;

        // Owner side: produce request
        DeRecMessage requestEnvelope = Verification.Request.Produce(channel1, secretId, version, sharedKey1);

        // Helper side: extract request, then produce response
        var req = Verification.Request.Extract(requestEnvelope, sharedKey1);
        if (req.ChannelId != channel1)
            throw new InvalidOperationException("Verification test failed: channel_id mismatch.");

        DeRecMessage responseEnvelope = Verification.Response.Produce(
            channel1, req.RequestProtoBytes, sharedKey1, storedShare1
        );

        // Owner side: extract response, then process against correct share (valid) and wrong share (invalid)
        var extractedResponse = Verification.Response.Extract(responseEnvelope, sharedKey1);

        bool valid = Verification.Response.Process(extractedResponse.ResponseProtoBytes, storedShare1);
        if (!valid)
            throw new InvalidOperationException("Verification test failed: expected valid for matching share.");

        bool invalid = Verification.Response.Process(extractedResponse.ResponseProtoBytes, storedShare2);
        if (invalid)
            throw new InvalidOperationException("Verification test failed: expected invalid for wrong share.");

        Console.WriteLine("Verification flow test passed.");
    }

    private static void RunRecoveryFlowTest()
    {
        Console.WriteLine("=== Recovery flow test ===");

        ulong secretId = 0xCAFEBABEUL;
        byte[] secretData = new byte[] { 5, 6, 7, 8, 255 };
        ulong[] channels = new ulong[] { 1, 2, 3 };
        ulong threshold = 2;
        uint version = 1;

        var sharedKeys = CreateChannelSharedKeys(channels);

        var shares = Sharing.Request.Split(secretId, secretData, channels, threshold, version)
            .DeserializeShares();

        ulong channel1 = 1;
        ulong channel2 = 2;
        byte[] sharedKey1 = sharedKeys[channel1];
        byte[] sharedKey2 = sharedKeys[channel2];

        // Helper-side persisted store-share inner request bytes
        byte[] storedShare1 = Sharing.Request.Extract(
            Sharing.Request.Produce(channel1, version, secretId, shares[channel1], Array.Empty<uint>(), string.Empty, sharedKey1),
            sharedKey1
        ).RequestProtoBytes;
        byte[] storedShare2 = Sharing.Request.Extract(
            Sharing.Request.Produce(channel2, version, secretId, shares[channel2], Array.Empty<uint>(), string.Empty, sharedKey2),
            sharedKey2
        ).RequestProtoBytes;

        // Helper 1
        DeRecMessage shareRequest1 = Recovery.Request.Produce(channel1, secretId, version, sharedKey1);
        byte[] extractedReq1 = Recovery.Request.Extract(shareRequest1, sharedKey1).RequestProtoBytes;
        DeRecMessage shareResponse1 = Recovery.Response.Produce(channel1, extractedReq1, storedShare1, sharedKey1);

        // Helper 2
        DeRecMessage shareRequest2 = Recovery.Request.Produce(channel2, secretId, version, sharedKey2);
        byte[] extractedReq2 = Recovery.Request.Extract(shareRequest2, sharedKey2).RequestProtoBytes;
        DeRecMessage shareResponse2 = Recovery.Response.Produce(channel2, extractedReq2, storedShare2, sharedKey2);

        // Owner side: extract both responses
        byte[] extractedResp1 = Recovery.Response.Extract(shareResponse1, sharedKey1).ResponseProtoBytes;
        byte[] extractedResp2 = Recovery.Response.Extract(shareResponse2, sharedKey2).ResponseProtoBytes;

        byte[] recovered = Recovery.Response.Recover(
            new[] { extractedResp1, extractedResp2 },
            secretId,
            version
        );

        if (!recovered.SequenceEqual(secretData))
            throw new InvalidOperationException("Recovery test failed: recovered secret does not match original.");

        Console.WriteLine("Recovery flow test passed.");
    }

    private static void RunDiscoveryFlowTest()
    {
        Console.WriteLine("=== Discovery flow test ===");

        ulong channelId = 42;
        byte[] sharedKey = Make32(0x11);

        // Owner side: produce request
        DeRecMessage requestEnvelope = Discovery.Request.Produce(channelId, sharedKey);

        // Helper side: extract request
        var extractedRequest = Discovery.Request.Extract(requestEnvelope, sharedKey);
        if (extractedRequest.ChannelId != channelId)
            throw new InvalidOperationException("Discovery test failed: channel_id mismatch on extract request.");

        // Helper side: produce response with a known secret list
        var secretList = new List<Discovery.SecretVersionEntry>
        {
            new Discovery.SecretVersionEntry
            {
                SecretId = 0xAABBCCDDUL,
                Versions = new List<Discovery.VersionEntry>
                {
                    new Discovery.VersionEntry { Version = 1, Description = "first" },
                    new Discovery.VersionEntry { Version = 2, Description = "second" },
                },
            },
            new Discovery.SecretVersionEntry
            {
                SecretId = 0x11223344UL,
                Versions = new List<Discovery.VersionEntry>
                {
                    new Discovery.VersionEntry { Version = 5, Description = "fifth" },
                },
            },
        };

        DeRecMessage responseEnvelope = Discovery.Response.Produce(channelId, secretList, sharedKey);

        // Owner side: extract response, then process
        var extractedResponse = Discovery.Response.Extract(responseEnvelope, sharedKey);
        if (extractedResponse.ChannelId != channelId)
            throw new InvalidOperationException("Discovery test failed: channel_id mismatch on extract response.");

        var parsed = Discovery.Response.Process(extractedResponse.ResponseProtoBytes);
        if (parsed.Count != 2)
            throw new InvalidOperationException($"Discovery test failed: expected 2 entries but got {parsed.Count}.");
        if (parsed[0].SecretId != 0xAABBCCDDUL || parsed[0].Versions.Count != 2)
            throw new InvalidOperationException("Discovery test failed: first entry mismatch.");
        if (parsed[0].Versions[0].Description != "first" || parsed[0].Versions[1].Description != "second")
            throw new InvalidOperationException("Discovery test failed: first entry descriptions mismatch.");
        if (parsed[1].SecretId != 0x11223344UL || parsed[1].Versions.Count != 1 || parsed[1].Versions[0].Version != 5)
            throw new InvalidOperationException("Discovery test failed: second entry mismatch.");

        Console.WriteLine("Discovery flow test passed.");
    }

    private static void RunUnpairingFlowTest()
    {
        Console.WriteLine("=== Unpairing flow test ===");

        ulong channelId = 99;
        byte[] sharedKey = Make32(0x22);
        const string Memo = "goodbye";

        // Initiator side: produce request
        DeRecMessage requestEnvelope = Unpairing.Request.Produce(channelId, Memo, sharedKey);

        // Responder side: extract request
        var extractedRequest = Unpairing.Request.Extract(requestEnvelope, sharedKey);
        if (extractedRequest.ChannelId != channelId)
            throw new InvalidOperationException("Unpairing test failed: channel_id mismatch on extract request.");
        if (extractedRequest.Memo != Memo)
            throw new InvalidOperationException($"Unpairing test failed: memo mismatch (got '{extractedRequest.Memo}').");

        // Responder side: produce ack response
        DeRecMessage responseEnvelope = Unpairing.Response.Produce(channelId, sharedKey);

        // Initiator side: extract response then process
        var extractedResponse = Unpairing.Response.Extract(responseEnvelope, sharedKey);
        if (extractedResponse.ChannelId != channelId)
            throw new InvalidOperationException("Unpairing test failed: channel_id mismatch on extract response.");

        Unpairing.Response.Process(extractedResponse.ResponseProtoBytes);

        Console.WriteLine("Unpairing flow test passed.");
    }

    private static Dictionary<ulong, byte[]> CreateChannelSharedKeys(ulong[] channelIds)
    {
        var keys = new Dictionary<ulong, byte[]>();
        for (int i = 0; i < channelIds.Length; i++)
        {
            keys[channelIds[i]] = Make32((byte)(i + 1));
        }
        return keys;
    }

    private static byte[] Make32(byte fill)
    {
        var key = new byte[32];
        Array.Fill(key, fill);
        return key;
    }

    /// <summary>
    /// Exercises the two cross-cutting envelope features added alongside the
    /// primitive surface:
    /// <list type="bullet">
    ///   <item><description>The optional <c>replyTo</c> parameter on
    ///   <c>Discovery.Request.Produce</c> (and the other four request types)
    ///   must accept a <see cref="TransportProtocol"/> without crashing, and
    ///   the resulting envelope must still extract cleanly.</description></item>
    ///   <item><description>The <c>Envelope.ApplyTraceId</c> /
    ///   <c>Envelope.ReadTraceId</c> helpers round-trip the trace_id field
    ///   on the outer envelope without touching the encrypted inner
    ///   payload — <c>Extract</c> still succeeds after re-stamping.</description></item>
    /// </list>
    /// </summary>
    private static void RunEnvelopeAndReplyToTest()
    {
        Console.WriteLine("=== Envelope + replyTo helpers test ===");

        ulong channelId = 99;
        byte[] sharedKey = Make32(0x99);
        var replyTo = new TransportProtocol("https://replica.example.com");

        // Primitive produce defaults to trace_id = 0 and reply_to = null.
        DeRecMessage envWithout = Discovery.Request.Produce(channelId, sharedKey);
        if (Envelope.ReadTraceId(envWithout) != 0)
            throw new InvalidOperationException(
                "Envelope test failed: primitive-default trace_id must be 0.");

        // Produce again, this time stamping reply_to into the inner body.
        // The encrypted inner now carries the TransportProtocol; verify the
        // call accepts replyTo without throwing and the resulting envelope
        // still extracts cleanly via the channel's shared key.
        DeRecMessage envWith = Discovery.Request.Produce(channelId, sharedKey, replyTo);

        // Round-trip a trace_id over the envelope with replyTo set.
        const ulong token = 0xDEADBEEF_F00DCAFEUL;
        DeRecMessage stamped = Envelope.ApplyTraceId(envWith, token);
        if (Envelope.ReadTraceId(stamped) != token)
            throw new InvalidOperationException(
                "Envelope test failed: trace_id did not round-trip through ApplyTraceId.");

        // The encrypted inner is untouched — Extract still succeeds after
        // re-stamping, proving the helper only rewrote the outer field.
        var extracted = Discovery.Request.Extract(stamped, sharedKey);
        if (extracted.ChannelId != channelId)
            throw new InvalidOperationException(
                "Envelope test failed: channel_id mismatch on extract after ApplyTraceId.");

        Console.WriteLine("Envelope + replyTo helpers test passed.");
    }
}
