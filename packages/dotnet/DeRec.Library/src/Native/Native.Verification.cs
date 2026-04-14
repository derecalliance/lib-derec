using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

internal static class Verification
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceVerifyShareRequestMessageResult
    {
        public Status Status;
        public Buffer RequestWireBytes;
        public int MessageType;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ExtractVerifyShareRequestResult
    {
        public Status Status;
        public ulong ChannelId;
        public Buffer SecretId;
        public int Version;
        public ulong Nonce;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProduceVerifyShareResponseMessageResult
    {
        public Status Status;
        public Buffer ResponseWireBytes;
        public int MessageType;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct VerifyShareResponseResult
    {
        public Status Status;

        [MarshalAs(UnmanagedType.I1)]
        public bool IsValid;
    }

    /// <summary>
    /// Builds an encrypted verification request envelope. The envelope's
    /// <c>message_type</c> is set to <c>VERIFY_SHARE_REQUEST</c>.
    /// </summary>
    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceVerifyShareRequestMessageResult produce_verify_share_request_message(
        ulong channelId,
        byte[] secretId,
        UIntPtr secretIdLen,
        int version,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    /// <summary>
    /// Decodes and decrypts a verification request envelope in a single call.
    /// Returns <c>channel_id</c>, <c>secret_id</c>, <c>version</c>, and <c>nonce</c>.
    /// </summary>
    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ExtractVerifyShareRequestResult extract_verify_share_request(
        byte[] requestWireBytes,
        UIntPtr requestWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen
    );

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern ProduceVerifyShareResponseMessageResult produce_verify_share_response_message(
        ulong channelId,
        byte[] secretId,
        UIntPtr secretIdLen,
        int version,
        ulong nonce,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[] shareContent,
        UIntPtr shareContentLen
    );

    /// <summary>
    /// Decodes and decrypts the response envelope, then validates the SHA-384 proof.
    /// </summary>
    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern VerifyShareResponseResult process_verify_share_response_message(
        byte[] responseWireBytes,
        UIntPtr responseWireBytesLen,
        byte[] sharedKey,
        UIntPtr sharedKeyLen,
        byte[] shareContent,
        UIntPtr shareContentLen
    );
}
