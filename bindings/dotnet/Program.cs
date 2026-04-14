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
        RunSharingFlowTest();
        RunVerificationFlowTest();
        RunRecoveryFlowTest();

        Console.WriteLine("All smoke tests passed.");
    }

    private static void RunProtocolVersionTest()
    {
        Console.WriteLine("=== Protocol version test ===");

        var version = ProtocolVersion.Current();
        Console.WriteLine($"protocol version = {version}");
        Console.WriteLine($"major = {version.Major}");
        Console.WriteLine($"minor = {version.Minor}");

        Console.WriteLine("Protocol version test passed.");
    }

    private static void RunPairingFlowTest()
    {
        Console.WriteLine("=== Pairing flow test ===");

        ulong channelId = 1;

        var contact = Pairing.Request.CreateContact(
            channelId,
            new TransportProtocol("https://example.com/alice")
        );

        Console.WriteLine($"contact.ContactMessage.ChannelId = {contact.ContactMessage.ChannelId}");
        Console.WriteLine($"contact.SecretKeyMaterial bytes = {contact.SecretKeyMaterial.Length}");

        if (contact.SecretKeyMaterial.Length == 0)
            throw new InvalidOperationException("Pairing test failed: empty contact secret key material.");

        var pairRequest = Pairing.Request.Produce(
            Pairing.SenderKind.Helper,
            new TransportProtocol("https://example.com/helper"),
            contact.ContactMessage
        );

        Console.WriteLine($"pairRequest.Envelope bytes = {pairRequest.Envelope.Length}");
        Console.WriteLine($"pairRequest.InitiatorContactMessage.ChannelId = {pairRequest.InitiatorContactMessage.ChannelId}");
        Console.WriteLine($"pairRequest.SecretKeyMaterial bytes = {pairRequest.SecretKeyMaterial.Length}");

        if (pairRequest.SecretKeyMaterial.Length == 0)
            throw new InvalidOperationException("Pairing test failed: empty pair request secret key material.");

        var pairResponse = Pairing.Response.Produce(
            Pairing.SenderKind.OwnerNonRecovery,
            pairRequest.Envelope,
            contact.SecretKeyMaterial
        );

        Console.WriteLine($"pairResponse.Envelope bytes = {pairResponse.Envelope.Length}");
        Console.WriteLine($"pairResponse.SharedKey bytes = {pairResponse.SharedKey.Length}");
        Console.WriteLine($"pairResponse.ResponderTransportProtocol.Uri = {pairResponse.ResponderTransportProtocol.Uri}");

        if (pairResponse.SharedKey.Length == 0)
            throw new InvalidOperationException("Pairing test failed: empty pair response shared key.");

        var processed = Pairing.Response.Process(
            pairRequest.InitiatorContactMessage,
            pairResponse.Envelope,
            pairRequest.SecretKeyMaterial
        );

        Console.WriteLine($"processed.SharedKey bytes = {processed.SharedKey.Length}");

        if (processed.SharedKey.Length == 0)
            throw new InvalidOperationException("Pairing test failed: empty processed shared key.");

        if (!pairResponse.SharedKey.SequenceEqual(processed.SharedKey))
            throw new InvalidOperationException("Pairing test failed: shared keys do not match.");

        Console.WriteLine("Pairing flow test passed.");
    }

    private static void RunSharingFlowTest()
    {
        Console.WriteLine("=== Sharing flow test ===");

        byte[] secretId = new byte[] { 1, 2, 3, 4, 255 };
        byte[] secretData = new byte[] { 5, 6, 7, 8, 255 };
        ulong[] channelIds = new ulong[] { 1, 2, 3 };
        ulong threshold = 2;
        int version = 1;

        var splitResult = Sharing.Request.Split(secretId, secretData, channelIds, threshold, version);
        var shares = splitResult.DeserializeShares();

        Console.WriteLine($"shares count = {shares.Count}");

        if (shares.Count != channelIds.Length)
            throw new InvalidOperationException($"Sharing test failed: expected {channelIds.Length} shares but got {shares.Count}.");

        var sharedKeys = CreateChannelSharedKeys(channelIds);

        foreach (var entry in shares)
        {
            ulong channel = entry.Key;
            byte[] shareBytes = entry.Value;

            Console.WriteLine($"channel = {channel}, committed share bytes = {shareBytes.Length}");

            if (shareBytes.Length == 0)
                throw new InvalidOperationException($"Sharing test failed: empty share bytes for channel {channel}.");

            var storeRequest = Sharing.Request.Produce(
                channel, version, secretId, shareBytes,
                new int[0], string.Empty, sharedKeys[channel]
            );

            Console.WriteLine($"storeRequest.Envelope.ChannelId = {storeRequest.Envelope.ChannelId}");

            var storeResponse = Sharing.Response.Produce(channel, sharedKeys[channel], storeRequest.Envelope);

            Console.WriteLine($"storeResponse.Envelope.ChannelId = {storeResponse.Envelope.ChannelId}");
            Console.WriteLine($"storeResponse.CommittedShareBytes = {storeResponse.CommittedShareBytes.Length}");

            var committedShare = Proto.CommittedDeRecShare.Parser.ParseFrom(storeResponse.CommittedShareBytes);
            var deRecShare = Proto.DeRecShare.Parser.ParseFrom(committedShare.DeRecShare.ToByteArray());
            Console.WriteLine($"  de_rec_share.version = {deRecShare.Version}");
            Console.WriteLine($"  commitment bytes = {committedShare.Commitment.Length}");
            Console.WriteLine($"  merkle_path nodes = {committedShare.MerklePath.Count}");

            if (storeResponse.CommittedShareBytes.Length == 0)
                throw new InvalidOperationException($"Sharing test failed: empty committed_share_bytes for channel {channel}.");
            if (storeResponse.SecretId.Length == 0)
                throw new InvalidOperationException($"Sharing test failed: empty secret_id for channel {channel}.");
            if (storeResponse.Version != version)
                throw new InvalidOperationException($"Sharing test failed: version mismatch for channel {channel}.");

            Sharing.Response.Process(version, sharedKeys[channel], storeResponse.Envelope);
            Console.WriteLine($"sharing_response_process validated ok[{channel}]");
        }

        Console.WriteLine("Sharing flow test passed.");
    }

    private static void RunVerificationFlowTest()
    {
        Console.WriteLine("=== Verification flow test ===");

        byte[] secretId = new byte[] { 1, 2, 3, 4, 255 };
        byte[] secretData = new byte[] { 5, 6, 7, 8, 255 };
        ulong[] channels = new ulong[] { 1, 2, 3 };
        ulong threshold = 2;
        int version = 1;

        var sharedKeys = CreateChannelSharedKeys(channels);

        var shares = Sharing.Request.Split(secretId, secretData, channels, threshold, version)
            .DeserializeShares();

        ulong channel1 = 1;
        ulong channel2 = 2;
        byte[] sharedKey1 = sharedKeys[channel1];

        DeRecMessage storedEnvelope1 = Sharing.Request.Produce(
            channel1, version, secretId, shares[channel1], new int[0], string.Empty, sharedKey1
        ).Envelope;

        DeRecMessage storedEnvelope2 = Sharing.Request.Produce(
            channel2, version, secretId, shares[channel2], new int[0], string.Empty, sharedKey1
        ).Envelope;

        // Owner side: produce request
        DeRecMessage requestEnvelope = Verification.Request.Produce(channel1, secretId, version, sharedKey1);
        Console.WriteLine($"verification_request.ChannelId = {requestEnvelope.ChannelId}");

        // Helper side: extract request
        var req = Verification.Request.Extract(requestEnvelope, sharedKey1);
        Console.WriteLine($"req.ChannelId = {req.ChannelId}, req.Version = {req.Version}, req.Nonce = {req.Nonce}");

        if (req.ChannelId != channel1) throw new InvalidOperationException("Verification test failed: channel_id mismatch.");
        if (!req.SecretId.SequenceEqual(secretId)) throw new InvalidOperationException("Verification test failed: secret_id mismatch.");
        if (req.Version != version) throw new InvalidOperationException("Verification test failed: version mismatch.");
        if (req.Nonce == 0) throw new InvalidOperationException("Verification test failed: nonce must not be zero.");

        // Helper side: produce response
        DeRecMessage responseEnvelope = Verification.Response.Produce(
            channel1, req.SecretId, req.Version, req.Nonce, sharedKey1, storedEnvelope1
        );
        Console.WriteLine($"verification_response.ChannelId = {responseEnvelope.ChannelId}");

        // Owner side: correct share → true
        bool valid = Verification.Response.Process(responseEnvelope, sharedKey1, storedEnvelope1);
        Console.WriteLine($"verification valid (expected true) = {valid}");
        if (!valid) throw new InvalidOperationException("Verification test failed: expected valid response.");

        // Owner side: wrong share → false
        bool invalid = Verification.Response.Process(responseEnvelope, sharedKey1, storedEnvelope2);
        Console.WriteLine($"verification invalid (expected false) = {invalid}");
        if (invalid) throw new InvalidOperationException("Verification test failed: expected invalid response for wrong share.");

        Console.WriteLine("Verification flow test passed.");
    }

    private static void RunRecoveryFlowTest()
    {
        Console.WriteLine("=== Recovery flow test ===");

        byte[] secretId = new byte[] { 1, 2, 3, 4, 255 };
        byte[] secretData = new byte[] { 5, 6, 7, 8, 255 };
        ulong[] channels = new ulong[] { 1, 2, 3 };
        ulong threshold = 2;
        int version = 1;

        var sharedKeys = CreateChannelSharedKeys(channels);

        var shares = Sharing.Request.Split(secretId, secretData, channels, threshold, version)
            .DeserializeShares();

        ulong channel1 = 1;
        ulong channel2 = 2;
        byte[] sharedKey1 = sharedKeys[channel1];
        byte[] sharedKey2 = sharedKeys[channel2];

        DeRecMessage storedEnvelope1 = Sharing.Request.Produce(
            channel1, version, secretId, shares[channel1], new int[0], string.Empty, sharedKey1
        ).Envelope;

        DeRecMessage storedEnvelope2 = Sharing.Request.Produce(
            channel2, version, secretId, shares[channel2], new int[0], string.Empty, sharedKey2
        ).Envelope;

        DeRecMessage shareRequest1 = Recovery.Request.Produce(channel1, secretId, version, sharedKey1);
        Console.WriteLine($"shareRequest[1].ChannelId = {shareRequest1.ChannelId}");

        DeRecMessage shareResponse1 = Recovery.Response.Produce(
            channel1, secretId, shareRequest1, storedEnvelope1, sharedKey1
        );
        Console.WriteLine($"shareResponse[1].ChannelId = {shareResponse1.ChannelId}");

        DeRecMessage shareRequest2 = Recovery.Request.Produce(channel2, secretId, version, sharedKey2);
        DeRecMessage shareResponse2 = Recovery.Response.Produce(
            channel2, secretId, shareRequest2, storedEnvelope2, sharedKey2
        );

        byte[] recovered = Recovery.Response.Recover(
            new[]
            {
                new Recovery.Response.RecoveryInput { Envelope = shareResponse1, SharedKey = sharedKey1 },
                new Recovery.Response.RecoveryInput { Envelope = shareResponse2, SharedKey = sharedKey2 },
            },
            secretId,
            version
        );

        Console.WriteLine($"recovered bytes = {recovered.Length}");
        Console.WriteLine($"recovered matches original = {recovered.SequenceEqual(secretData)}");

        if (!recovered.SequenceEqual(secretData))
            throw new InvalidOperationException("Recovery test failed: recovered secret does not match original.");

        Console.WriteLine("Recovery flow test passed.");
    }

    private static Dictionary<ulong, byte[]> CreateChannelSharedKeys(ulong[] channelIds)
    {
        var keys = new Dictionary<ulong, byte[]>();
        for (int i = 0; i < channelIds.Length; i++)
        {
            var key = new byte[32];
            Array.Fill(key, (byte)(i + 1));
            keys[channelIds[i]] = key;
        }
        return keys;
    }
}
