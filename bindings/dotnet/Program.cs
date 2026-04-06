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
        ulong[] channelIds = new ulong[] { 1, 2, 3 };
        ulong threshold = 2;
        int version = 1;

        var result = Sharing.ProtectSecret(secretId, secretData, channelIds, threshold, version);

        Console.WriteLine($"shares_wire_bytes total bytes = {result.SharesWireBytes.Length}");

        var shares = DeserializeSharesWireBytes(result.SharesWireBytes);

        Console.WriteLine($"shares count = {shares.Count}");

        if (shares.Count != channelIds.Length)
        {
            throw new InvalidOperationException(
                $"Sharing test failed: expected {channelIds.Length} shares but got {shares.Count}."
            );
        }

        foreach (ulong channel in channelIds)
        {
            if (!shares.ContainsKey(channel))
            {
                throw new InvalidOperationException(
                    $"Sharing test failed: missing share for channel {channel}."
                );
            }
        }

        var sharedKeys = CreateChannelSharedKeys(channelIds);

        foreach (var entry in shares)
        {
            Console.WriteLine($"channel = {entry.Key}");
            Console.WriteLine($"committed share bytes = {entry.Value.Length}");

            if (entry.Value.Length == 0)
            {
                throw new InvalidOperationException(
                    $"Sharing test failed: empty share bytes for channel {entry.Key}."
                );
            }

            var storeResult = Sharing.ProduceStoreShareRequestMessage(
                entry.Key,
                version,
                entry.Value,
                Array.Empty<int>(),
                string.Empty,
                sharedKeys[entry.Key]
            );

            Console.WriteLine($"store_share_request wire bytes = {storeResult.WireBytes.Length}");

            if (storeResult.WireBytes.Length == 0)
            {
                throw new InvalidOperationException(
                    $"Sharing test failed: empty store share request wire bytes for channel {entry.Key}."
                );
            }

            var processResult = Sharing.ProduceStoreShareResponseMessage(
                entry.Key,
                sharedKeys[entry.Key],
                storeResult.WireBytes
            );

            Console.WriteLine($"store_share_response wire bytes = {processResult.WireBytes.Length}");
            Console.WriteLine($"committed_share_bytes = {processResult.CommittedShareBytes.Length}");

            if (processResult.WireBytes.Length == 0)
            {
                throw new InvalidOperationException(
                    $"Sharing test failed: empty response wire bytes for channel {entry.Key}."
                );
            }

            if (processResult.CommittedShareBytes.Length == 0)
            {
                throw new InvalidOperationException(
                    $"Sharing test failed: empty committed_share_bytes for channel {entry.Key}."
                );
            }

            Sharing.ProcessStoreShareResponseMessage(
                version,
                sharedKeys[entry.Key],
                processResult.WireBytes
            );

            Console.WriteLine("store_share_response validated ok");
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

        var sharing = Sharing.ProtectSecret(secretId, secretData, channels, threshold, version);
        var shares = DeserializeSharesWireBytes(sharing.SharesWireBytes);

        if (shares.Count != channels.Length)
        {
            throw new InvalidOperationException(
                $"Verification test failed: expected {channels.Length} shares but got {shares.Count}."
            );
        }

        ulong channel1 = 1;
        ulong channel2 = 2;

        byte[] sharedKey1 = sharedKeys[channel1];

        byte[] storedWire1 = Sharing.ProduceStoreShareRequestMessage(
            channel1, version, shares[channel1], Array.Empty<int>(), string.Empty, sharedKey1
        ).WireBytes;

        // Intentionally use sharedKey1 for channel2's envelope to test invalid verification.
        byte[] storedWire2 = Sharing.ProduceStoreShareRequestMessage(
            channel2, version, shares[channel2], Array.Empty<int>(), string.Empty, sharedKey1
        ).WireBytes;

        byte[] requestWireBytes = Verification.GenerateVerificationRequest(
            secretId, channel1, version, sharedKey1
        );

        Console.WriteLine($"verification_request wire bytes = {requestWireBytes.Length}");

        byte[] responseWireBytes = Verification.GenerateVerificationResponse(
            secretId, channel1, sharedKey1, storedWire1, requestWireBytes
        );

        Console.WriteLine($"verification_response wire bytes = {responseWireBytes.Length}");

        bool valid = Verification.VerifyShareResponse(
            secretId, channel1, sharedKey1, storedWire1, responseWireBytes
        );

        Console.WriteLine($"verification valid = {valid}");

        if (!valid)
        {
            throw new InvalidOperationException("Verification test failed: expected valid response.");
        }

        bool invalid = Verification.VerifyShareResponse(
            secretId, channel1, sharedKey1, storedWire2, responseWireBytes
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

        var sharing = Sharing.ProtectSecret(secretId, secretData, channels, threshold, version);
        var shares = DeserializeSharesWireBytes(sharing.SharesWireBytes);

        if (shares.Count != channels.Length)
        {
            throw new InvalidOperationException(
                $"Recovery test failed: expected {channels.Length} shares but got {shares.Count}."
            );
        }

        ulong channel1 = 1;
        ulong channel2 = 2;

        byte[] sharedKey1 = sharedKeys[channel1];
        byte[] sharedKey2 = sharedKeys[channel2];

        byte[] storedWire1 = Sharing.ProduceStoreShareRequestMessage(
            channel1, version, shares[channel1], Array.Empty<int>(), string.Empty, sharedKey1
        ).WireBytes;

        byte[] storedWire2 = Sharing.ProduceStoreShareRequestMessage(
            channel2, version, shares[channel2], Array.Empty<int>(), string.Empty, sharedKey2
        ).WireBytes;

        byte[] shareRequest1 = Recovery.GenerateShareRequest(channel1, secretId, version, sharedKey1);
        Console.WriteLine($"share_request[1] wire bytes = {shareRequest1.Length}");

        byte[] shareResponse1 = Recovery.GenerateShareResponse(
            channel1, secretId, shareRequest1, storedWire1, sharedKey1
        );
        Console.WriteLine($"share_response[1] wire bytes = {shareResponse1.Length}");

        byte[] shareRequest2 = Recovery.GenerateShareRequest(channel2, secretId, version, sharedKey2);
        Console.WriteLine($"share_request[2] wire bytes = {shareRequest2.Length}");

        byte[] shareResponse2 = Recovery.GenerateShareResponse(
            channel2, secretId, shareRequest2, storedWire2, sharedKey2
        );
        Console.WriteLine($"share_response[2] wire bytes = {shareResponse2.Length}");

        byte[] recovered = Recovery.RecoverFromShareResponses(
            new[]
            {
                new Recovery.RecoveryResponseInput { Bytes = shareResponse1, SharedKey = sharedKey1 },
                new Recovery.RecoveryResponseInput { Bytes = shareResponse2, SharedKey = sharedKey2 },
            },
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

    private static Dictionary<ulong, byte[]> DeserializeSharesWireBytes(byte[] bytes)
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
                    $"Unexpected end of shares_wire_bytes while reading entry {i}."
                );
            }

            byte[] messageBytes = new byte[messageLen];
            Buffer.BlockCopy(bytes, offset, messageBytes, 0, (int)messageLen);
            offset += (int)messageLen;

            if (result.ContainsKey(channelId))
            {
                throw new InvalidOperationException(
                    $"Duplicate channelId parsed from shares_wire_bytes: {channelId}. " +
                    "This usually means the .NET deserializer no longer matches the Rust FFI format."
                );
            }

            result[channelId] = messageBytes;
        }

        if (offset != bytes.Length)
        {
            throw new InvalidOperationException(
                $"Unexpected trailing bytes in shares_wire_bytes. offset={offset}, total={bytes.Length}"
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
