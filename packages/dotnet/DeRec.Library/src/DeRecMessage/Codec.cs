using System;
using Google.Protobuf;
using Org.Derecalliance.Derec.Protobuf;

namespace DeRec.Library;

public interface IDeRecMessageSigner
{
    byte[] SenderKeyHash();
    byte[] Sign(byte[] payload);
}

public interface IDeRecMessageVerifier
{
    VerifiedPayload Verify(byte[] signedPayload);
}

public interface IDeRecMessageEncrypter
{
    int RecipientKeyId();
    byte[] RecipientKeyHash();
    byte[] Encrypt(byte[] signedPayload);
}

public interface IDeRecMessageDecrypter
{
    int RecipientKeyId();
    byte[] RecipientKeyHash();
    byte[] Decrypt(byte[] encryptedPayload);
}

public static class DeRecMessageCodec
{
    public static byte[] Serialize(DeRecMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        return message.ToByteArray();
    }

    public static DeRecMessage Deserialize(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        try
        {
            return DeRecMessage.Parser.ParseFrom(bytes);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"protobuf decode failed: {ex.Message}", ex);
        }
    }

    public static WireMessage Encode(
        DeRecMessage message,
        IDeRecMessageSigner signer,
        IDeRecMessageEncrypter encrypter
    )
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(encrypter);

        byte[] senderKeyHash = signer.SenderKeyHash();
        byte[] recipientKeyHash = encrypter.RecipientKeyHash();

        if (!message.Sender.ToByteArray().AsSpan().SequenceEqual(senderKeyHash))
        {
            throw new InvalidOperationException(
                "sender hash mismatch between envelope and signer key"
            );
        }

        if (!message.Receiver.ToByteArray().AsSpan().SequenceEqual(recipientKeyHash))
        {
            throw new InvalidOperationException(
                "receiver hash mismatch between envelope and recipient key"
            );
        }

        byte[] protobufBytes = Serialize(message);
        byte[] signedPayload = signer.Sign(protobufBytes);
        byte[] encryptedPayload = encrypter.Encrypt(signedPayload);

        return new WireMessage
        {
            RecipientKeyId = encrypter.RecipientKeyId(),
            Payload = encryptedPayload
        };
    }

    public static byte[] EncodeToBytes(
        DeRecMessage message,
        IDeRecMessageSigner signer,
        IDeRecMessageEncrypter encrypter
    )
    {
        return Encode(message, signer, encrypter).ToBytes();
    }

    public static DeRecMessage Decode(
        WireMessage wireMessage,
        IDeRecMessageDecrypter decrypter,
        IDeRecMessageVerifier verifier
    )
    {
        ArgumentNullException.ThrowIfNull(wireMessage);
        ArgumentNullException.ThrowIfNull(decrypter);
        ArgumentNullException.ThrowIfNull(verifier);

        if (wireMessage.RecipientKeyId != decrypter.RecipientKeyId())
        {
            throw new InvalidOperationException(
                $"recipient key id mismatch: wire={wireMessage.RecipientKeyId}, expected={decrypter.RecipientKeyId()}"
            );
        }

        byte[] signedPayload = decrypter.Decrypt(wireMessage.Payload);
        VerifiedPayload verified = verifier.Verify(signedPayload);

        DeRecMessage message = Deserialize(verified.Payload);

        if (!message.Sender.ToByteArray().AsSpan().SequenceEqual(verified.SignerKeyHash))
        {
            throw new InvalidOperationException(
                "sender hash mismatch between envelope and verified signature"
            );
        }

        if (!message.Receiver.ToByteArray().AsSpan().SequenceEqual(decrypter.RecipientKeyHash()))
        {
            throw new InvalidOperationException(
                "receiver hash mismatch between envelope and recipient key"
            );
        }

        return message;
    }

    public static DeRecMessage DecodeFromBytes(
        byte[] bytes,
        IDeRecMessageDecrypter decrypter,
        IDeRecMessageVerifier verifier
    )
    {
        ArgumentNullException.ThrowIfNull(bytes);

        WireMessage wireMessage = WireMessage.FromBytes(bytes);
        return Decode(wireMessage, decrypter, verifier);
    }
}
