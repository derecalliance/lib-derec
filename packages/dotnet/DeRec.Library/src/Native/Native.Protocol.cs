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
internal static class Protocol
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreLoadDelegate(
        IntPtr userData, ulong channelId, out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreSaveDelegate(
        IntPtr userData, ulong channelId, IntPtr bytes, UIntPtr len);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreRemoveDelegate(
        IntPtr userData, ulong channelId, out uint outExisted);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreListDelegate(
        IntPtr userData, out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreLinkDelegate(
        IntPtr userData, ulong a, ulong b);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ChannelStoreLinkedDelegate(
        IntPtr userData, ulong channelId, out IntPtr outPtr, out UIntPtr outLen);

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
        IntPtr userData, ulong channelId, uint kind, out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int SecretStoreSaveDelegate(
        IntPtr userData, ulong channelId, uint kind, IntPtr bytes, UIntPtr len);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int SecretStoreRemoveDelegate(
        IntPtr userData, ulong channelId, uint kind);

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
        IntPtr userData, ulong channelId, ulong secretId,
        IntPtr versionsJsonPtr, UIntPtr versionsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreLoadManyDelegate(
        IntPtr userData,
        IntPtr channelIdsJsonPtr, UIntPtr channelIdsJsonLen,
        ulong secretId,
        IntPtr versionsJsonPtr, UIntPtr versionsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreLoadAllDelegate(
        IntPtr userData,
        IntPtr channelIdsJsonPtr, UIntPtr channelIdsJsonLen,
        out IntPtr outPtr, out UIntPtr outLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreLatestVersionDelegate(
        IntPtr userData, out uint outHasVersion, out uint outVersion);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreSaveDelegate(
        IntPtr userData, ulong channelId, IntPtr shareJsonPtr, UIntPtr shareJsonLen);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate int ShareStoreRemoveChannelDelegate(
        IntPtr userData, ulong channelId);

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

    [StructLayout(LayoutKind.Sequential)]
    internal struct DeRecProtocolFingerprintResult
    {
        public DeRecError Error;
        public IntPtr Fingerprint;
    }

    [DllImport("derec_library", CallingConvention = CallingConvention.Cdecl)]
    internal static extern DeRecProtocolNewResult derec_protocol_new(
        ref ChannelStoreCallbacks channelStoreCb,
        ref SecretStoreCallbacks secretStoreCb,
        ref ShareStoreCallbacks shareStoreCb,
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
}
