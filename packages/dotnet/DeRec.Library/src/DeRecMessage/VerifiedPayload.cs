namespace DeRec.Library;

public sealed class VerifiedPayload
{
    public required byte[] Payload { get; init; }
    public required byte[] SignerKeyHash { get; init; }
}
