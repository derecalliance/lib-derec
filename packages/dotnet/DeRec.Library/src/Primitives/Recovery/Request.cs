// SPDX-License-Identifier: Apache-2.0

namespace DeRec.Library.Primitives;

public static partial class Recovery
{
    public static class Request
    {
        /// <summary>
        /// Produces a recovery share request envelope (Owner side).
        /// </summary>
        public static DeRecMessage Produce(
            ulong channelId,
            byte[] secretId,
            int version,
            byte[] sharedKey
        )
        {
            Native.Recovery.ProduceGetShareRequestMessageResult nativeResult =
                Native.Recovery.produce_get_share_request_message(
                    channelId,
                    secretId,
                    (UIntPtr)secretId.Length,
                    version,
                    sharedKey,
                    (UIntPtr)sharedKey.Length
                );

            try
            {
                Utils.ThrowIfError(nativeResult.Status);

                return DeRecMessage.FromProtoBytes(Utils.CopyBuffer(nativeResult.WireBytes));
            }
            finally
            {
                Utils.FreeBuffer(nativeResult.WireBytes);
                Utils.FreeStatusMessage(nativeResult.Status);
            }
        }
    }
}
