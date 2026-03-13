using System;
using System.Runtime.InteropServices;
using System.Text;
using Org.Derecalliance.Derec.Protobuf;
using Google.Protobuf;

namespace DeRec.Library;

public static class Pairing
{
    public enum SenderKind
    {
        SharerNonRecovery = 0,
        SharerRecovery = 1,
        Helper = 2,
    }

    public sealed class ContactMessageResult
    {
        public required ContactMessage ContactMessage { get; init; }
        public required byte[] SecretKeyMaterial { get; init; }
    }

    public sealed class PairRequestMessageResult
    {
        public required PairRequestMessage PairRequestMessage { get; init; }
        public required byte[] SecretKeyMaterial { get; init; }
    }

    public sealed class PairResponseMessageResult
    {
        public required PairResponseMessage PairResponseMessage { get; init; }
        public required byte[] SharedKey { get; init; }
    }

    public sealed class ProcessPairingResponseResult
    {
        public required byte[] SharedKey { get; init; }
    }

    public static ContactMessageResult CreateContactMessage(ulong channelId, string transportUri)
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
            if (nativeResult.Status.Code != 0)
            {
                string message = nativeResult.Status.Message != IntPtr.Zero
                    ? Marshal.PtrToStringAnsi(nativeResult.Status.Message) ?? "unknown error"
                    : "unknown error";

                throw new InvalidOperationException(message);
            }

            byte[] contactMessageBytes = Utils.CopyBuffer(nativeResult.ContactMessage);
            byte[] secretKeyMaterial = Utils.CopyBuffer(nativeResult.SecretKeyMaterial);

            ContactMessage contactMessage = ContactMessage.Parser.ParseFrom(contactMessageBytes);

            return new ContactMessageResult
            {
                ContactMessage = contactMessage,
                SecretKeyMaterial = secretKeyMaterial,
            };
        }
        finally
        {
            if (nativeResult.ContactMessage.Ptr != IntPtr.Zero)
            {
                Native.Utils.derec_free_buffer(
                    nativeResult.ContactMessage.Ptr,
                    nativeResult.ContactMessage.Len
                );
            }

            if (nativeResult.SecretKeyMaterial.Ptr != IntPtr.Zero)
            {
                Native.Utils.derec_free_buffer(
                    nativeResult.SecretKeyMaterial.Ptr,
                    nativeResult.SecretKeyMaterial.Len
                );
            }

            if (nativeResult.Status.Message != IntPtr.Zero)
            {
                Native.Utils.derec_free_string(nativeResult.Status.Message);
            }
        }
    }

    public static PairRequestMessageResult ProducePairingRequestMessage(
        ulong channelId,
        SenderKind peerStatus,
        ContactMessage contactMessage
    )
    {
        byte[] contactMessageBytes = contactMessage.ToByteArray();

        Native.Pairing.ProducePairingRequestMessageResult nativeResult =
            Native.Pairing.produce_pairing_request_message(
                channelId,
                (int)peerStatus,
                contactMessageBytes,
                (UIntPtr)contactMessageBytes.Length
            );

        try
        {
            if (nativeResult.Status.Code != 0)
            {
                string message = nativeResult.Status.Message != IntPtr.Zero
                    ? Marshal.PtrToStringAnsi(nativeResult.Status.Message) ?? "unknown error"
                    : "unknown error";

                throw new InvalidOperationException(message);
            }

            byte[] pairRequestMessageBytes = Utils.CopyBuffer(nativeResult.PairRequestMessage);
            byte[] secretKeyMaterial = Utils.CopyBuffer(nativeResult.SecretKeyMaterial);

            PairRequestMessage pairRequestMessage =
                PairRequestMessage.Parser.ParseFrom(pairRequestMessageBytes);

            return new PairRequestMessageResult
            {
                PairRequestMessage = pairRequestMessage,
                SecretKeyMaterial = secretKeyMaterial,
            };
        }
        finally
        {
            if (nativeResult.PairRequestMessage.Ptr != IntPtr.Zero)
            {
                Native.Utils.derec_free_buffer(
                    nativeResult.PairRequestMessage.Ptr,
                    nativeResult.PairRequestMessage.Len
                );
            }

            if (nativeResult.SecretKeyMaterial.Ptr != IntPtr.Zero)
            {
                Native.Utils.derec_free_buffer(
                    nativeResult.SecretKeyMaterial.Ptr,
                    nativeResult.SecretKeyMaterial.Len
                );
            }

            if (nativeResult.Status.Message != IntPtr.Zero)
            {
                Native.Utils.derec_free_string(nativeResult.Status.Message);
            }
        }
    }

    public static PairResponseMessageResult ProducePairingResponseMessage(
        SenderKind peerStatus,
        PairRequestMessage pairRequestMessage,
        byte[] secretKeyMaterial
    )
    {
        byte[] pairRequestMessageBytes = pairRequestMessage.ToByteArray();

        Native.Pairing.ProducePairingResponseMessageResult nativeResult =
            Native.Pairing.produce_pairing_response_message(
                (int)peerStatus,
                pairRequestMessageBytes,
                (UIntPtr)pairRequestMessageBytes.Length,
                secretKeyMaterial,
                (UIntPtr)secretKeyMaterial.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] pairResponseMessageBytes = Utils.CopyBuffer(nativeResult.PairResponseMessage);
            byte[] sharedKey = Utils.CopyBuffer(nativeResult.SharedKey);

            PairResponseMessage pairResponseMessage =
                PairResponseMessage.Parser.ParseFrom(pairResponseMessageBytes);

            return new PairResponseMessageResult
            {
                PairResponseMessage = pairResponseMessage,
                SharedKey = sharedKey,
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.PairResponseMessage);
            Utils.FreeBuffer(nativeResult.SharedKey);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    public static ProcessPairingResponseResult ProcessPairingResponseMessage(
        ContactMessage contactMessage,
        PairResponseMessage pairResponseMessage,
        byte[] secretKeyMaterial
    )
    {
        byte[] contactMessageBytes = contactMessage.ToByteArray();
        byte[] pairResponseMessageBytes = pairResponseMessage.ToByteArray();

        Native.Pairing.ProcessPairingResponseMessageResult nativeResult =
            Native.Pairing.process_pairing_response_message(
                contactMessageBytes,
                (UIntPtr)contactMessageBytes.Length,
                pairResponseMessageBytes,
                (UIntPtr)pairResponseMessageBytes.Length,
                secretKeyMaterial,
                (UIntPtr)secretKeyMaterial.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] sharedKey = Utils.CopyBuffer(nativeResult.SharedKey);

            return new ProcessPairingResponseResult
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
