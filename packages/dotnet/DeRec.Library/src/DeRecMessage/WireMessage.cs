namespace DeRec.Library;

public sealed class WireMessage
{
    public required int RecipientKeyId { get; init; }
    public required byte[] Payload { get; init; }

    public byte[] ToBytes()
    {
        byte[] output = new byte[4 + Payload.Length];

        byte[] keyBytes = BitConverter.GetBytes(RecipientKeyId);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(keyBytes);
        }

        Buffer.BlockCopy(keyBytes, 0, output, 0, 4);
        Buffer.BlockCopy(Payload, 0, output, 4, Payload.Length);

        return output;
    }

    public static WireMessage FromBytes(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);

        if (bytes.Length < 4)
        {
            throw new InvalidOperationException(
                $"Wire message too short: expected at least 4 bytes, got {bytes.Length}."
            );
        }

        byte[] keyBytes = new byte[4];
        Buffer.BlockCopy(bytes, 0, keyBytes, 0, 4);

        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(keyBytes);
        }

        int recipientKeyId = BitConverter.ToInt32(keyBytes, 0);

        byte[] payload = new byte[bytes.Length - 4];
        Buffer.BlockCopy(bytes, 4, payload, 0, payload.Length);

        return new WireMessage
        {
            RecipientKeyId = recipientKeyId,
            Payload = payload
        };
    }
}
