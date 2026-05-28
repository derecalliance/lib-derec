// SPDX-License-Identifier: Apache-2.0

using System;
using System.Runtime.InteropServices;

namespace DeRec.Library.Primitives;

public static partial class Unpairing
{
    public static class Request
    {
        public sealed class ExtractResult
        {
            public required ulong ChannelId { get; init; }
            public required string Memo { get; init; }
        }

        public static DeRecMessage Produce(ulong channelId, string memo, byte[] sharedKey)
        {
            byte[] memoBytes = System.Text.Encoding.UTF8.GetBytes(memo ?? string.Empty);

            Native.Unpairing.ProduceUnpairRequestMessageResult nativeResult =
                Native.Unpairing.produce_unpair_request_message(
                    channelId,
                    memoBytes,
                    (UIntPtr)memoBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.RequestWireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.RequestWireBytes);
            }
        }

        public static ExtractResult Extract(DeRecMessage request, byte[] sharedKey)
        {
            byte[] requestBytes = request.ToProtoBytes();

            Native.Unpairing.ExtractUnpairRequestResult nativeResult =
                Native.Unpairing.extract_unpair_request(
                    requestBytes,
                    (UIntPtr)requestBytes.Length,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Error);
                string memo = nativeResult.Memo != IntPtr.Zero
                    ? Marshal.PtrToStringAnsi(nativeResult.Memo) ?? string.Empty
                    : string.Empty;
                return new ExtractResult
                {
                    ChannelId = nativeResult.ChannelId,
                    Memo = memo,
                };
            }
            finally
            {
                if (nativeResult.Memo != IntPtr.Zero)
                {
                    Native.Utils.derec_free_string(nativeResult.Memo);
                }
            }
        }
    }
}
