namespace DeRec.Library;

public static class Pairing
{
    public enum SenderKind
    {
        OwnerNonRecovery = 0,
        OwnerRecovery = 1,
        Helper = 2,
    }

    public sealed class CreateContactMessageResult
    {
        public required byte[] WireBytes { get; init; }
        public required byte[] SecretKeyMaterial { get; init; }
    }

    public sealed class ProducePairingRequestMessageResult
    {
        public required byte[] WireBytes { get; init; }
        public required ContactMessage InitiatorContactMessage { get; init; }
        public required byte[] SecretKeyMaterial { get; init; }
    }

    public sealed class ProducePairingResponseMessageResult
    {
        public required byte[] WireBytes { get; init; }
        public required TransportProtocol ResponderTransportProtocol { get; init; }
        public required byte[] SharedKey { get; init; }
    }

    public sealed class ProcessPairingResponseMessageResult
    {
        public required byte[] SharedKey { get; init; }
    }

    public static CreateContactMessageResult CreateContactMessage(ulong channelId, TransportProtocol transportProtocol)
    {
        byte[] transportProtocolBytes = transportProtocol.ToProtoBytes();

        Native.Pairing.CreateContactMessageResult nativeResult =
            Native.Pairing.create_contact_message(
                channelId,
                transportProtocolBytes,
                (UIntPtr)transportProtocolBytes.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] wireBytes = Utils.CopyBuffer(nativeResult.ContactWireBytes);
            byte[] secretKeyMaterial = Utils.CopyBuffer(nativeResult.SecretKeyMaterial);

            return new CreateContactMessageResult
            {
                WireBytes = wireBytes,
                SecretKeyMaterial = secretKeyMaterial,
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.ContactWireBytes);
            Utils.FreeBuffer(nativeResult.SecretKeyMaterial);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static ProducePairingRequestMessageResult ProducePairingRequestMessage(
        SenderKind kind,
        TransportProtocol transportProtocol,
        byte[] contactMessageBytes
    )
    {
        byte[] transportProtocolBytes = transportProtocol.ToProtoBytes();

        Native.Pairing.ProducePairingRequestMessageResult nativeResult =
            Native.Pairing.produce_pairing_request_message(
                (int)kind,
                transportProtocolBytes,
                (UIntPtr)transportProtocolBytes.Length,
                contactMessageBytes,
                (UIntPtr)contactMessageBytes.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] wireBytes = Utils.CopyBuffer(nativeResult.RequestWireBytes);
            byte[] initiatorContactMessageWireBytes = Utils.CopyBuffer(nativeResult.InitiatorContactMessageWireBytes);
            byte[] secretKeyMaterial = Utils.CopyBuffer(nativeResult.SecretKeyMaterial);

            return new ProducePairingRequestMessageResult
            {
                WireBytes = wireBytes,
                InitiatorContactMessage = ContactMessage.FromProtoBytes(initiatorContactMessageWireBytes),
                SecretKeyMaterial = secretKeyMaterial,
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.RequestWireBytes);
            Utils.FreeBuffer(nativeResult.InitiatorContactMessageWireBytes);
            Utils.FreeBuffer(nativeResult.SecretKeyMaterial);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static ProducePairingResponseMessageResult ProducePairingResponseMessage(
        SenderKind kind,
        byte[] pairRequestWireBytes,
        byte[] pairingSecretKeyMaterial
    )
    {
        Native.Pairing.ProducePairingResponseMessageResult nativeResult =
            Native.Pairing.produce_pairing_response_message(
                (int)kind,
                pairRequestWireBytes,
                (UIntPtr)pairRequestWireBytes.Length,
                pairingSecretKeyMaterial,
                (UIntPtr)pairingSecretKeyMaterial.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] wireBytes = Utils.CopyBuffer(nativeResult.ResponseWireBytes);
            byte[] responderTransportProtocolBytes = Utils.CopyBuffer(nativeResult.ResponderTransportProtocol);
            byte[] sharedKey = Utils.CopyBuffer(nativeResult.SharedKey);

            return new ProducePairingResponseMessageResult
            {
                WireBytes = wireBytes,
                ResponderTransportProtocol = TransportProtocol.FromProtoBytes(responderTransportProtocolBytes),
                SharedKey = sharedKey,
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.ResponseWireBytes);
            Utils.FreeBuffer(nativeResult.ResponderTransportProtocol);
            Utils.FreeBuffer(nativeResult.SharedKey);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static ProcessPairingResponseMessageResult ProcessPairingResponseMessage(
        ContactMessage contactMessage,
        byte[] pairResponseWireBytes,
        byte[] pairingSecretKeyMaterial
    )
    {
        byte[] contactMessageBytes = contactMessage.ToProtoBytes();

        Native.Pairing.ProcessPairingResponseMessageResult nativeResult =
            Native.Pairing.process_pairing_response_message(
                contactMessageBytes,
                (UIntPtr)contactMessageBytes.Length,
                pairResponseWireBytes,
                (UIntPtr)pairResponseWireBytes.Length,
                pairingSecretKeyMaterial,
                (UIntPtr)pairingSecretKeyMaterial.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] sharedKey = Utils.CopyBuffer(nativeResult.SharedKey);

            return new ProcessPairingResponseMessageResult
            {
                SharedKey = sharedKey,
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.SharedKey);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }
}
