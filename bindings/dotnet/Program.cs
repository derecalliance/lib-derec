using System;
using System.Collections.Generic;
using DeRec.Library;
using Org.Derecalliance.Derec.Protobuf;

internal static class Program
{
    private static void Main()
    {
        RunProtocolVersionTest();
        var pairRequestMessage = RunPairingFlowTest();
        RunSharingFlowTest();
        RunVerificationFlowTest();
        RunRecoveryFlowTest();

        RunDeRecMessageBuilderTest(pairRequestMessage);

        Console.WriteLine("All smoke tests passed.");
    }

    private static void RunProtocolVersionTest()
    {
        Console.WriteLine("=== Protocol version test ===");

        var version = ProtocolVersion.Current();

        Console.WriteLine($"protocol version = {version}");
        Console.WriteLine($"major = {version.Major}");
        Console.WriteLine($"minor = {version.Minor}");

        if (version.Major < 0 || version.Minor < 0)
        {
            throw new InvalidOperationException("Protocol version test failed.");
        }

        Console.WriteLine("Protocol version test passed.");
    }

    private static PairRequestMessage RunPairingFlowTest()
    {
        Console.WriteLine("=== Pairing flow test ===");

        var contact = Pairing.CreateContactMessage(1, "https://example.com/alice");

        Console.WriteLine($"contact.transport_uri = {contact.ContactMessage.TransportUri}");
        Console.WriteLine($"contact.public_key_id = {contact.ContactMessage.PublicKeyId}");
        Console.WriteLine($"contact.nonce = {contact.ContactMessage.Nonce}");
        Console.WriteLine($"contact.transport_protocol = {contact.ContactMessage.TransportProtocol}");
        Console.WriteLine($"contact.secret_key_material bytes = {contact.SecretKeyMaterial.Length}");

        if (contact.ContactMessage.TransportUri != "https://example.com/alice")
        {
            throw new InvalidOperationException("Pairing test failed: unexpected transport URI.");
        }

        if (contact.SecretKeyMaterial.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty contact secret key material.");
        }

        var pairRequest = Pairing.ProducePairingRequestMessage(
            1,
            Pairing.SenderKind.Helper,
            contact.ContactMessage
        );

        Console.WriteLine($"pair_request.secret_key_material bytes = {pairRequest.SecretKeyMaterial.Length}");
        Console.WriteLine($"pair_request_message = {pairRequest.PairRequestMessage}");

        if (pairRequest.SecretKeyMaterial.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty pair request secret key material.");
        }

        var pairResponse = Pairing.ProducePairingResponseMessage(
            Pairing.SenderKind.SharerNonRecovery,
            pairRequest.PairRequestMessage,
            contact.SecretKeyMaterial
        );

        Console.WriteLine($"pair_response.shared_key bytes = {pairResponse.SharedKey.Length}");
        Console.WriteLine($"pair_response_message = {pairResponse.PairResponseMessage}");

        if (pairResponse.SharedKey.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty pair response shared key.");
        }

        var processed = Pairing.ProcessPairingResponseMessage(
            contact.ContactMessage,
            pairResponse.PairResponseMessage,
            pairRequest.SecretKeyMaterial
        );

        Console.WriteLine($"processed.shared_key bytes = {processed.SharedKey.Length}");

        if (processed.SharedKey.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty processed shared key.");
        }

        bool sharedKeysEqual =
            Convert.ToHexString(pairResponse.SharedKey) ==
            Convert.ToHexString(processed.SharedKey);

        Console.WriteLine($"shared keys equal = {sharedKeysEqual}");

        if (!sharedKeysEqual)
        {
            throw new InvalidOperationException("Pairing test failed: shared keys do not match.");
        }

        Console.WriteLine("Pairing flow test passed.");

        return pairRequest.PairRequestMessage;
    }

    private static void RunSharingFlowTest()
    {
        Console.WriteLine("=== Sharing flow test ===");

        byte[] secretId = new byte[] { 1, 2, 3, 4, 255 };
        byte[] secretData = new byte[] { 5, 6, 7, 8, 255 };
        ulong[] channels = new ulong[] { 1, 2, 3 };
        ulong threshold = 2;
        int version = 1;

        var result = Sharing.ProtectSecret(
            secretId,
            secretData,
            channels,
            threshold,
            version,
            keepList: new[] { 1, 2, 3 },
            description: "v1 initial distribution"
        );

        Console.WriteLine($"shares count = {result.Shares.Count}");

        if (result.Shares.Count != channels.Length)
        {
            throw new InvalidOperationException(
                $"Sharing test failed: expected {channels.Length} shares but got {result.Shares.Count}."
            );
        }

        foreach (ulong channel in channels)
        {
            if (!result.Shares.ContainsKey(channel))
            {
                throw new InvalidOperationException(
                    $"Sharing test failed: missing share for channel {channel}."
                );
            }
        }

        foreach (var entry in result.Shares)
        {
            Console.WriteLine($"channel = {entry.Key}");
            Console.WriteLine($"store_share_request = {entry.Value}");
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

        var sharing = Sharing.ProtectSecret(
                secretId,
                secretData,
                channels,
                threshold,
                version,
                keepList: new[] { 1, 2, 3 },
                description: "v1 initial distribution"
                );

        if (!sharing.Shares.TryGetValue(1, out var shareMessage))
        {
            throw new InvalidOperationException("Verification test failed: missing share for channel 1.");
        }

        byte[] shareContent = shareMessage.Share.ToByteArray();

        var request = Verification.GenerateVerificationRequest(secretId, version);
        Console.WriteLine($"verification_request = {request}");

        var response = Verification.GenerateVerificationResponse(
                secretId,
                1,
                shareContent,
                request
                );
        Console.WriteLine($"verification_response = {response}");

        bool valid = Verification.VerifyShareResponse(
                secretId,
                1,
                shareContent,
                response
                );

        Console.WriteLine($"verification valid = {valid}");

        if (!valid)
        {
            throw new InvalidOperationException("Verification test failed: expected valid response.");
        }

        if (!sharing.Shares.TryGetValue(2, out var wrongShareMessage))
        {
            throw new InvalidOperationException("Verification test failed: missing share for channel 2.");
        }

        byte[] wrongShareContent = wrongShareMessage.Share.ToByteArray();

        bool invalid = Verification.VerifyShareResponse(
                secretId,
                1,
                wrongShareContent,
                response
                );

        Console.WriteLine($"verification invalid case = {invalid}");

        if (invalid)
        {
            throw new InvalidOperationException("Verification test failed: expected invalid response for wrong share.");
        }

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

        var sharing = Sharing.ProtectSecret(
                secretId,
                secretData,
                channels,
                threshold,
                version,
                keepList: new[] { 1, 2, 3 },
                description: "v1 initial distribution"
                );

        var shareRequest = Recovery.GenerateShareRequest(1, secretId, version);
        Console.WriteLine($"share_request = {shareRequest}");

        List<GetShareResponseMessage> responses = new();

        foreach (ulong channel in channels)
        {
            if (!sharing.Shares.TryGetValue(channel, out var storeShareRequest))
            {
                throw new InvalidOperationException(
                        $"Recovery test failed: missing share for channel {channel}."
                        );
            }

            var shareResponse = Recovery.GenerateShareResponse(
                    channel,
                    secretId,
                    shareRequest,
                    storeShareRequest
                    );

            Console.WriteLine($"share_response[{channel}] = {shareResponse}");
            responses.Add(shareResponse);
        }

        byte[] recovered = Recovery.RecoverFromShareResponses(
                responses,
                secretId,
                version
                );

        Console.WriteLine($"recovered bytes = {recovered.Length}");
        Console.WriteLine($"recovered matches original = {Convert.ToHexString(recovered) == Convert.ToHexString(secretData)}");

        if (Convert.ToHexString(recovered) != Convert.ToHexString(secretData))
        {
            throw new InvalidOperationException("Recovery test failed: recovered secret does not match original.");
        }

        Console.WriteLine("Recovery flow test passed.");
    }

    private static void RunDeRecMessageBuilderTest(PairRequestMessage pairRequest)
    {
        Console.WriteLine("=== DeRecMessage builder/codec test ===");

        byte[] sender = Enumerable.Repeat((byte)0x11, 48).ToArray();
        byte[] receiver = Enumerable.Repeat((byte)0x22, 48).ToArray();
        byte[] secretId = new byte[] { 1, 2, 3, 4 };
        DateTimeOffset timestamp = DateTimeOffset.UtcNow;

        DeRecMessage derecMessage = new DeRecMessageBuilder()
            .Sender(sender)
            .Receiver(receiver)
            .SecretId(secretId)
            .Timestamp(timestamp)
            .Message(pairRequest)
            .Build();

        if (derecMessage.ProtocolVersionMajor < 0 || derecMessage.ProtocolVersionMinor < 0)
        {
            throw new InvalidOperationException("DeRecMessage builder test failed: invalid protocol version.");
        }

        if (derecMessage.Sender.Length != 48)
        {
            throw new InvalidOperationException("DeRecMessage builder test failed: invalid sender length.");
        }

        if (derecMessage.Receiver.Length != 48)
        {
            throw new InvalidOperationException("DeRecMessage builder test failed: invalid receiver length.");
        }

        if (derecMessage.SecretId.Length != 4)
        {
            throw new InvalidOperationException("DeRecMessage builder test failed: invalid secretId length.");
        }

        if (derecMessage.Timestamp is null)
        {
            throw new InvalidOperationException("DeRecMessage builder test failed: missing timestamp.");
        }

        if (derecMessage.MessageBodies?.SharerMessageBodies is null)
        {
            throw new InvalidOperationException("DeRecMessage builder test failed: expected owner/sharer message bodies.");
        }

        if (derecMessage.MessageBodies.SharerMessageBodies.SharerMessageBody.Count != 1)
        {
            throw new InvalidOperationException("DeRecMessage builder test failed: expected exactly one message body.");
        }

        Console.WriteLine("DeRecMessage built successfully.");

        // Serialize / deserialize
        byte[] serialized = DeRecMessageCodec.Serialize(derecMessage);
        Console.WriteLine($"Serialized size = {serialized.Length}");

        DeRecMessage deserialized = DeRecMessageCodec.Deserialize(serialized);

        if (!derecMessage.Equals(deserialized))
        {
            throw new InvalidOperationException("DeRecMessage codec test failed: deserialize(serialize(x)) != x.");
        }

        Console.WriteLine("Serialize/deserialize roundtrip OK.");

        // Dummy crypto backends
        var signer = new DummySigner(sender);
        var verifier = new DummyVerifier(sender);
        var encrypter = new DummyEncrypter(42, receiver);
        var decrypter = new DummyDecrypter(42, receiver);

        byte[] wireBytes = DeRecMessageCodec.EncodeToBytes(
                derecMessage,
                signer,
                encrypter
                );

        Console.WriteLine($"Wire size = {wireBytes.Length}");

        DeRecMessage decoded = DeRecMessageCodec.DecodeFromBytes(
                wireBytes,
                decrypter,
                verifier
                );

        if (!derecMessage.Equals(decoded))
        {
            throw new InvalidOperationException("DeRecMessage codec test failed: decode(encode(x)) != x.");
        }

        Console.WriteLine("Encode/decode roundtrip OK.");
        Console.WriteLine("DeRecMessage builder/codec test passed.");
    }

    private sealed class DummySigner : IDeRecMessageSigner
    {
        private readonly byte[] _senderKeyHash;

        public DummySigner(byte[] senderKeyHash)
        {
            _senderKeyHash = senderKeyHash;
        }

        public byte[] SenderKeyHash() => _senderKeyHash;

        public byte[] Sign(byte[] payload)
        {
            byte[] prefix = new byte[] { 9, 9, 9 };
            byte[] output = new byte[prefix.Length + payload.Length];
            Buffer.BlockCopy(prefix, 0, output, 0, prefix.Length);
            Buffer.BlockCopy(payload, 0, output, prefix.Length, payload.Length);
            return output;
        }
    }

    private sealed class DummyVerifier : IDeRecMessageVerifier
    {
        private readonly byte[] _senderKeyHash;

        public DummyVerifier(byte[] senderKeyHash)
        {
            _senderKeyHash = senderKeyHash;
        }

        public VerifiedPayload Verify(byte[] signedPayload)
        {
            if (signedPayload.Length < 3)
            {
                throw new InvalidOperationException("DummyVerifier failed: signed payload too short.");
            }

            byte[] payload = signedPayload[3..];

            return new VerifiedPayload
            {
                Payload = payload,
                SignerKeyHash = _senderKeyHash
            };
        }
    }

    private sealed class DummyEncrypter : IDeRecMessageEncrypter
    {
        private readonly int _recipientKeyId;
        private readonly byte[] _recipientKeyHash;

        public DummyEncrypter(int recipientKeyId, byte[] recipientKeyHash)
        {
            _recipientKeyId = recipientKeyId;
            _recipientKeyHash = recipientKeyHash;
        }

        public int RecipientKeyId() => _recipientKeyId;

        public byte[] RecipientKeyHash() => _recipientKeyHash;

        public byte[] Encrypt(byte[] payload)
        {
            byte[] copy = (byte[])payload.Clone();
            Array.Reverse(copy);
            return copy;
        }
    }

    private sealed class DummyDecrypter : IDeRecMessageDecrypter
    {
        private readonly int _recipientKeyId;
        private readonly byte[] _recipientKeyHash;

        public DummyDecrypter(int recipientKeyId, byte[] recipientKeyHash)
        {
            _recipientKeyId = recipientKeyId;
            _recipientKeyHash = recipientKeyHash;
        }

        public int RecipientKeyId() => _recipientKeyId;

        public byte[] RecipientKeyHash() => _recipientKeyHash;

        public byte[] Decrypt(byte[] payload)
        {
            byte[] copy = (byte[])payload.Clone();
            Array.Reverse(copy);
            return copy;
        }
    }
}
