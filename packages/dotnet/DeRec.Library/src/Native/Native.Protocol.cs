// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Native;

/// <summary>
/// P/Invoke surface for the stateful <c>DeRecProtocol</c> orchestrator FFI.
/// Callbacks for the four store/transport traits are passed in as
/// function pointers in the layout structs below — each delegate MUST
/// have <see cref="UnmanagedFunctionPointerAttribute"/> with
/// <see cref="CallingConvention.Cdecl"/>.
/// </summary>
/// <remarks>
/// All <c>byte[] buf, UIntPtr bufLen</c> parameter pairs in this class
/// follow the global FFI marshaling contract on <see cref="Utils"/> —
/// pass <c>(UIntPtr)buf.Length</c>; never a wire-derived value. Every
/// returned <see cref="Buffer"/> field must be released via
/// <see cref="DeRec.Library.Utils.FreeBuffer"/> (see
/// <see cref="Buffer"/> for the ownership contract).
/// </remarks>
internal static class Protocol
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreLoadDelegate(
        IntPtr userData, ulong secretId, ulong channelId,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreSaveDelegate(
        IntPtr userData, ulong secretId, ulong channelId,
        IntPtr bytes, UIntPtr len);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreRemoveDelegate(
        IntPtr userData, ulong secretId, ulong channelId,
        out uint outExisted);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreListDelegate(
        IntPtr userData, ulong secretId,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreLinkDelegate(
        IntPtr userData, ulong secretId, ulong a, ulong b);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreLinkedDelegate(
        IntPtr userData, ulong secretId, ulong channelId,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void FreeBufferDelegate(
        IntPtr userData, IntPtr ptr, UIntPtr len);

    [StructLayout(LayoutKind.Sequential)]
    internal struct ChannelStoreCallbacks
    {
        public IntPtr UserData;
        public IntPtr Load;
        public IntPtr Save;
        public IntPtr Remove;
        public IntPtr ListChannels;
        public IntPtr LinkChannel;
        public IntPtr LinkedChannels;
        public IntPtr FreeBuffer;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int SecretStoreLoadDelegate(
        IntPtr userData, ulong secretId, ulong channelId, uint kind,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int SecretStoreSaveDelegate(
        IntPtr userData, ulong secretId, ulong channelId, uint kind,
        IntPtr bytes, UIntPtr len);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int SecretStoreRemoveDelegate(
        IntPtr userData, ulong secretId, ulong channelId, uint kind);

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecretStoreCallbacks
    {
        public IntPtr UserData;
        public IntPtr Load;
        public IntPtr Save;
        public IntPtr Remove;
        public IntPtr FreeBuffer;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreLoadDelegate(
        IntPtr userData, ulong secretId, ulong channelId,
        IntPtr versionsJsonPtr, UIntPtr versionsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreLoadManyDelegate(
        IntPtr userData, ulong secretId,
        IntPtr channelIdsJsonPtr, UIntPtr channelIdsJsonLen,
        IntPtr versionsJsonPtr, UIntPtr versionsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreLoadAllDelegate(
        IntPtr userData, ulong secretId,
        IntPtr channelIdsJsonPtr, UIntPtr channelIdsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreLatestVersionDelegate(
        IntPtr userData, ulong secretId,
        out uint outHasVersion, out uint outVersion);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreSaveDelegate(
        IntPtr userData, ulong secretId, ulong channelId,
        IntPtr shareJsonPtr, UIntPtr shareJsonLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreRemoveChannelDelegate(
        IntPtr userData, ulong secretId, ulong channelId);

    [StructLayout(LayoutKind.Sequential)]
    internal struct ShareStoreCallbacks
    {
        public IntPtr UserData;
        public IntPtr Load;
        public IntPtr LoadMany;
        public IntPtr LoadAll;
        public IntPtr LatestVersion;
        public IntPtr Save;
        public IntPtr RemoveChannel;
        public IntPtr FreeBuffer;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int UserSecretStoreLoadLatestDelegate(
        IntPtr userData, ulong secretId,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int UserSecretStoreSaveLatestDelegate(
        IntPtr userData, ulong secretId,
        IntPtr valueJsonPtr, UIntPtr valueJsonLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int UserSecretStoreRemoveDelegate(
        IntPtr userData, ulong secretId);

    [StructLayout(LayoutKind.Sequential)]
    internal struct UserSecretStoreCallbacks
    {
        public IntPtr UserData;
        public IntPtr LoadLatest;
        public IntPtr SaveLatest;
        public IntPtr Remove;
        public IntPtr FreeBuffer;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int TransportSendDelegate(
        IntPtr userData, IntPtr uriPtr, UIntPtr uriLen, int protocol,
        IntPtr bytes, UIntPtr len);

    [StructLayout(LayoutKind.Sequential)]
    internal struct TransportCallbacks
    {
        public IntPtr UserData;
        public IntPtr Send;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DeRecProtocolNewResult
    {
        public DeRecError Error;
        public IntPtr Handle;
    }

    /// <summary>
    /// Per-flow auto-accept policy. Mirrors the Rust
    /// <c>DeRecAutoAcceptPolicy</c> repr(C) struct one-to-one. Each
    /// field is a <c>uint</c> (0 = off, non-zero = on) to match the
    /// rest of the FFI's bool-as-<c>uint</c> convention.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct DeRecAutoAcceptPolicy
    {
        public uint Pairing;
        public uint PrePair;
        public uint StoreShare;
        public uint VerifyShare;
        public uint Discovery;
        public uint GetShare;
        public uint Unpair;
        public uint UpdateChannelInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DeRecProtocolFingerprintResult
    {
        public DeRecError Error;
        public IntPtr Fingerprint;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecProtocolNewResult derec_protocol_new(
        ulong secretId,
        ref ChannelStoreCallbacks channelStoreCb,
        ref SecretStoreCallbacks secretStoreCb,
        ref ShareStoreCallbacks shareStoreCb,
        ref UserSecretStoreCallbacks userSecretStoreCb,
        ref TransportCallbacks transportCb,
        byte[] ownTransportUri, UIntPtr ownTransportUriLen,
        int ownTransportProtocol,
        uint threshold,
        uint keepVersionsCount,
        byte[]? communicationInfo, UIntPtr communicationInfoLen,
        uint timeoutInSecs,
        uint autoRespondOnFailure,
        int unpairAck,
        uint autoReplyTo,
        DeRecAutoAcceptPolicy autoAccept,
        uint hasReplicaId,
        ulong replicaId);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void derec_protocol_free(IntPtr handle);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecProtocolFingerprintResult derec_protocol_get_fingerprint(
        IntPtr handle, ulong channelId);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecError derec_protocol_verify_fingerprint(
        IntPtr handle, ulong channelId, byte[] fingerprintUtf8, out uint outMatched);

    [StructLayout(LayoutKind.Sequential)]
    internal struct DeRecProtocolCreateContactResult
    {
        public DeRecError Error;
        public Buffer ContactWireBytes;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecProtocolCreateContactResult derec_protocol_create_contact(
        IntPtr handle, uint hasChannelId, ulong channelId, int contactMode);

    [StructLayout(LayoutKind.Sequential)]
    internal struct DeRecProtocolStartResult
    {
        public DeRecError Error;
        public uint HasChannelId;
        public ulong ChannelId;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecProtocolStartResult derec_protocol_start(
        IntPtr handle, uint flowKind, byte[]? paramsJson, UIntPtr paramsJsonLen);

    [StructLayout(LayoutKind.Sequential)]
    internal struct DeRecProtocolEventsResult
    {
        public DeRecError Error;
        public Buffer EventsJson;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecProtocolEventsResult derec_protocol_process(
        IntPtr handle, byte[] message, UIntPtr messageLen);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecProtocolEventsResult derec_protocol_accept(
        IntPtr handle, byte[] action, UIntPtr actionLen);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecError derec_protocol_reject(
        IntPtr handle, byte[] action, UIntPtr actionLen,
        int status, byte[]? memo, UIntPtr memoLen);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecError derec_protocol_set_communication_info(
        IntPtr handle, byte[] infoJson, UIntPtr infoJsonLen);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecError derec_protocol_set_own_transport(
        IntPtr handle, byte[] uri, UIntPtr uriLen, int protocol);

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecError derec_protocol_restore(
        IntPtr handle, byte[] paramsJson, UIntPtr paramsJsonLen);
}
