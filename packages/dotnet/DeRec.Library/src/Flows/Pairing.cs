using System;
using System.Text;

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
        public required byte[] SecretKeyMaterial { get; init; }
    }

    public sealed class ProducePairingResponseMessageResult
    {
        public required byte[] WireBytes { get; init; }
        public required byte[] TransportProtocolWireBytes { get; init; }
        public required byte[] SharedKey { get; init; }
    }

    public sealed class ProcessPairingResponseMessageResult
    {
        public required byte[] SharedKey { get; init; }
    }

    public static CreateContactMessageResult CreateContactMessage(ulong channelId, string transportUri)
    {
        byte[] transportUriBytes = Encoding.UTF8.GetBytes(transportUri);

        Native.Pairing.CreateContactMessageResult nativeResult =
            Native.Pairing.create_contact_message(
                channelId,
                transportUriBytes,
                (UIntPtr)transportUriBytes.Length
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
        string transportUri,
        byte[] contactMessageBytes
    )
    {
        byte[] transportUriBytes = Encoding.UTF8.GetBytes(transportUri);

        Native.Pairing.ProducePairingRequestMessageResult nativeResult =
            Native.Pairing.produce_pairing_request_message(
                (int)kind,
                transportUriBytes,
                (UIntPtr)transportUriBytes.Length,
                contactMessageBytes,
                (UIntPtr)contactMessageBytes.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] wireBytes = Utils.CopyBuffer(nativeResult.RequestWireBytes);
            byte[] secretKeyMaterial = Utils.CopyBuffer(nativeResult.SecretKeyMaterial);

            return new ProducePairingRequestMessageResult
            {
                WireBytes = wireBytes,
                SecretKeyMaterial = secretKeyMaterial,
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.RequestWireBytes);
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
            byte[] transportProtocolWireBytes = Utils.CopyBuffer(nativeResult.TransportProtocol);
            byte[] sharedKey = Utils.CopyBuffer(nativeResult.SharedKey);

            return new ProducePairingResponseMessageResult
            {
                WireBytes = wireBytes,
                TransportProtocolWireBytes = transportProtocolWireBytes,
                SharedKey = sharedKey,
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.ResponseWireBytes);
            Utils.FreeBuffer(nativeResult.TransportProtocol);
            Utils.FreeBuffer(nativeResult.SharedKey);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static ProcessPairingResponseMessageResult ProcessPairingResponseMessage(
        byte[] contactMessageBytes,
        byte[] pairResponseWireBytes,
        byte[] pairingSecretKeyMaterial
    )
    {
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
