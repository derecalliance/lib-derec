using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using DeRec.Library;

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

        var contact = Pairing.CreateContactMessage(channelId, new TransportProtocol("https://example.com/alice"));

        Console.WriteLine($"contact.wire_bytes = {contact.WireBytes.Length}");
        Console.WriteLine($"contact.secret_key_material bytes = {contact.SecretKeyMaterial.Length}");

        if (contact.WireBytes.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty contact wire bytes.");
        }

        if (contact.SecretKeyMaterial.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty contact secret key material.");
        }

        var pairRequest = Pairing.ProducePairingRequestMessage(
            Pairing.SenderKind.Helper,
            new TransportProtocol("https://example.com/helper"),
            contact.WireBytes
        );

        Console.WriteLine($"pair_request.wire_bytes = {pairRequest.WireBytes.Length}");
        Console.WriteLine($"pair_request.initiator_contact_message.channel_id = {pairRequest.InitiatorContactMessage.ChannelId}");
        Console.WriteLine($"pair_request.initiator_contact_message.transport_protocol.uri = {pairRequest.InitiatorContactMessage.TransportProtocol.Uri}");
        Console.WriteLine($"pair_request.initiator_contact_message.nonce = {pairRequest.InitiatorContactMessage.Nonce}");
        Console.WriteLine($"pair_request.secret_key_material bytes = {pairRequest.SecretKeyMaterial.Length}");

        if (pairRequest.WireBytes.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty pair request wire bytes.");
        }


        if (pairRequest.SecretKeyMaterial.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty pair request secret key material.");
        }

        var pairResponse = Pairing.ProducePairingResponseMessage(
            Pairing.SenderKind.OwnerNonRecovery,
            pairRequest.WireBytes,
            contact.SecretKeyMaterial
        );

        Console.WriteLine($"pair_response.wire_bytes = {pairResponse.WireBytes.Length}");
        Console.WriteLine($"pair_response.shared_key bytes = {pairResponse.SharedKey.Length}");
        Console.WriteLine($"pair_response.responder_transport_protocol.uri = {pairResponse.ResponderTransportProtocol.Uri}");
        Console.WriteLine($"pair_response.responder_transport_protocol.protocol = {pairResponse.ResponderTransportProtocol.Protocol}");

        if (pairResponse.WireBytes.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty pair response wire bytes.");
        }

        if (pairResponse.SharedKey.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty pair response shared key.");
        }

        var processed = Pairing.ProcessPairingResponseMessage(
            pairRequest.InitiatorContactMessage,
            pairResponse.WireBytes,
            pairRequest.SecretKeyMaterial
        );

        Console.WriteLine($"processed.shared_key bytes = {processed.SharedKey.Length}");

        if (processed.SharedKey.Length == 0)
        {
            throw new InvalidOperationException("Pairing test failed: empty processed shared key.");
        }

        bool sharedKeysEqual = pairResponse.SharedKey.SequenceEqual(processed.SharedKey);

        Console.WriteLine($"shared keys equal = {sharedKeysEqual}");

        if (!sharedKeysEqual)
        {
            throw new InvalidOperationException("Pairing test failed: shared keys do not match.");
        }

        Console.WriteLine("Pairing flow test passed.");
    }

    private static void RunSharingFlowTest()
    {
        Console.WriteLine("=== Sharing flow test ===");

        byte[] secretId = new byte[] { 1, 2, 3, 4, 255 };
        byte[] secretData = new byte[] { 5, 6, 7, 8, 255 };
        ulong[] channels = new ulong[] { 1, 2, 3 };
        ulong threshold = 2;
        int version = 1;

        var sharedKeys = CreateChannelSharedKeys(channels);

        var result = Sharing.ProtectSecret(
            secretId,
            secretData,
            sharedKeys,
            threshold,
            version,
            keepList: new[] { 1, 2, 3 },
            description: "v1 initial distribution"
        );

        Console.WriteLine($"share_message_wire_bytes_array total bytes = {result.ShareMessageWireBytesArray.Length}");

        var shares = DeserializeShareMessageWireBytesArray(result.ShareMessageWireBytesArray);

        Console.WriteLine($"shares count = {shares.Count}");

        if (shares.Count != channels.Length)
        {
            throw new InvalidOperationException(
                $"Sharing test failed: expected {channels.Length} shares but got {shares.Count}."
            );
        }

        foreach (ulong channel in channels)
        {
            if (!shares.ContainsKey(channel))
            {
                throw new InvalidOperationException(
                    $"Sharing test failed: missing share for channel {channel}."
                );
            }
        }

        foreach (var entry in shares)
        {
            Console.WriteLine($"channel = {entry.Key}");
            Console.WriteLine($"share wire bytes = {entry.Value.Length}");

            if (entry.Value.Length == 0)
            {
                throw new InvalidOperationException(
                    $"Sharing test failed: empty share bytes for channel {entry.Key}."
                );
            }
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

        var sharing = Sharing.ProtectSecret(
            secretId,
            secretData,
            sharedKeys,
            threshold,
            version,
            keepList: new[] { 1, 2, 3 },
            description: "v1 initial distribution"
        );

        var shares = DeserializeShareMessageWireBytesArray(sharing.ShareMessageWireBytesArray);

        if (!shares.TryGetValue(1, out var storedShareRequestWireBytes1))
        {
            throw new InvalidOperationException("Verification test failed: missing share for channel 1.");
        }

        if (!sharedKeys.TryGetValue(1, out var sharedKey1))
        {
            throw new InvalidOperationException("Verification test failed: missing shared key for channel 1.");
        }

        var request = Verification.GenerateVerificationRequest(secretId, 1, version, sharedKey1);
        Console.WriteLine($"verification_request wire bytes = {request.Length}");

        var response = Verification.GenerateVerificationResponse(
            secretId,
            1,
            sharedKey1,
            storedShareRequestWireBytes1,
            request
        );
        Console.WriteLine($"verification_response wire bytes = {response.Length}");

        bool valid = Verification.VerifyShareResponse(
            secretId,
            1,
            sharedKey1,
            storedShareRequestWireBytes1,
            response
        );

        Console.WriteLine($"verification valid = {valid}");

        if (!valid)
        {
            throw new InvalidOperationException("Verification test failed: expected valid response.");
        }

        if (!shares.TryGetValue(2, out var storedShareRequestWireBytes2))
        {
            throw new InvalidOperationException("Verification test failed: missing share for channel 2.");
        }

        bool invalid = Verification.VerifyShareResponse(
            secretId,
            1,
            sharedKey1,
            storedShareRequestWireBytes2,
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

        var sharedKeys = CreateChannelSharedKeys(channels);

        var sharing = Sharing.ProtectSecret(
            secretId,
            secretData,
            sharedKeys,
            threshold,
            version,
            keepList: new[] { 1, 2, 3 },
            description: "v1 initial distribution"
        );

        var shares = DeserializeShareMessageWireBytesArray(sharing.ShareMessageWireBytesArray);

        List<Recovery.RecoveryResponseInput> responses = new();

        foreach (ulong channel in channels)
        {
            if (!shares.TryGetValue(channel, out var storedShareRequestWireBytes))
            {
                throw new InvalidOperationException(
                    $"Recovery test failed: missing share for channel {channel}."
                );
            }

            if (!sharedKeys.TryGetValue(channel, out var sharedKey))
            {
                throw new InvalidOperationException(
                    $"Recovery test failed: missing shared key for channel {channel}."
                );
            }

            byte[] shareRequest = Recovery.GenerateShareRequest(channel, secretId, version, sharedKey);
            Console.WriteLine($"share_request[{channel}] wire bytes = {shareRequest.Length}");

            byte[] shareResponse = Recovery.GenerateShareResponse(
                channel,
                secretId,
                shareRequest,
                storedShareRequestWireBytes,
                sharedKey
            );

            Console.WriteLine($"share_response[{channel}] wire bytes = {shareResponse.Length}");

            responses.Add(new Recovery.RecoveryResponseInput
            {
                Bytes = shareResponse,
                SharedKey = sharedKey
            });
        }

        byte[] recovered = Recovery.RecoverFromShareResponses(
            responses,
            secretId,
            version
        );

        Console.WriteLine($"recovered bytes = {recovered.Length}");
        Console.WriteLine($"recovered matches original = {recovered.SequenceEqual(secretData)}");

        if (!recovered.SequenceEqual(secretData))
        {
            throw new InvalidOperationException("Recovery test failed: recovered secret does not match original.");
        }

        Console.WriteLine("Recovery flow test passed.");
    }

    private static Dictionary<ulong, byte[]> CreateChannelSharedKeys(IEnumerable<ulong> channels)
    {
        var result = new Dictionary<ulong, byte[]>();
        byte fill = 1;

        foreach (ulong channel in channels)
        {
            result[channel] = Enumerable.Repeat(fill, 32).ToArray();
            fill++;
        }

        return result;
    }

    private static Dictionary<ulong, byte[]> DeserializeShareMessageWireBytesArray(byte[] bytes)
    {
        var result = new Dictionary<ulong, byte[]>();
        int offset = 0;

        uint count = ReadU32(bytes, ref offset);
        Console.WriteLine($"declared share entry count = {count}");

        for (uint i = 0; i < count; i++)
        {
            ulong channelId = ReadU64(bytes, ref offset);
            uint messageLen = ReadU32(bytes, ref offset);

            Console.WriteLine($"parsed entry[{i}] channelId = {channelId}, messageLen = {messageLen}");

            if (offset + messageLen > bytes.Length)
            {
                throw new InvalidOperationException(
                    $"Unexpected end of share_message_wire_bytes_array while reading entry {i}."
                );
            }

            byte[] messageBytes = new byte[messageLen];
            Buffer.BlockCopy(bytes, offset, messageBytes, 0, (int)messageLen);
            offset += (int)messageLen;

            if (result.ContainsKey(channelId))
            {
                throw new InvalidOperationException(
                    $"Duplicate channelId parsed from share_message_wire_bytes_array: {channelId}. " +
                    "This usually means the .NET deserializer no longer matches the Rust FFI format."
                );
            }

            result[channelId] = messageBytes;
        }

        if (offset != bytes.Length)
        {
            throw new InvalidOperationException(
                $"Unexpected trailing bytes in share_message_wire_bytes_array. offset={offset}, total={bytes.Length}"
            );
        }

        return result;
    }

    private static uint ReadU32(byte[] bytes, ref int offset)
    {
        if (offset + 4 > bytes.Length)
        {
            throw new InvalidOperationException("Unexpected end of buffer while reading u32.");
        }

        uint value = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
        offset += 4;
        return value;
    }

    private static ulong ReadU64(byte[] bytes, ref int offset)
    {
        if (offset + 8 > bytes.Length)
        {
            throw new InvalidOperationException("Unexpected end of buffer while reading u64.");
        }

        ulong value = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset, 8));
        offset += 8;
        return value;
    }
}
