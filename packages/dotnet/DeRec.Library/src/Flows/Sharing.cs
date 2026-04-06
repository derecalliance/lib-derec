using System;
using System.Collections.Generic;

namespace DeRec.Library;

public static class Sharing
{
    /// <summary>
    /// Result of <see cref="ProtectSecret"/>.
    ///
    /// Contains one serialized <c>CommittedDeRecShare</c> per helper channel in the
    /// binary FFI container format (count + per-entry channel ID + length-prefixed bytes).
    ///
    /// Pass each entry to <c>ProduceStoreShareRequestMessage</c> together with the
    /// helper's shared key to produce the encrypted delivery envelope.
    /// </summary>
    public sealed class ProtectSecretResult
    {
        public required byte[] SharesWireBytes { get; init; }
    }

    /// <summary>
    /// Result of <see cref="ProduceStoreShareRequestMessage"/>.
    ///
    /// Contains a serialized <c>DeRecMessage</c> envelope whose inner payload is an
    /// encrypted <c>StoreShareRequestMessage</c>.
    ///
    /// Send <see cref="WireBytes"/> to the helper over the channel transport.
    /// The helper stores these bytes and uses them to respond to verification
    /// and recovery requests.
    /// </summary>
    public sealed class ProduceStoreShareRequestMessageResult
    {
        public required byte[] WireBytes { get; init; }
    }

    /// <summary>
    /// Result of <see cref="ProduceStoreShareResponseMessage"/>.
    ///
    /// Contains both the encrypted response to send back to the Owner and the
    /// committed share bytes for local storage.
    /// </summary>
    public sealed class ProduceStoreShareResponseMessageResult
    {
        /// <summary>
        /// Serialized <c>DeRecMessage</c> envelope carrying an encrypted
        /// <c>StoreShareResponseMessage</c>. Send these bytes back to the Owner.
        /// </summary>
        public required byte[] WireBytes { get; init; }

        /// <summary>
        /// Serialized <c>CommittedDeRecShare</c> protobuf bytes extracted from the request.
        /// The Helper must persist this value for future verification and recovery requests.
        /// </summary>
        public required byte[] CommittedShareBytes { get; init; }
    }

    /// <summary>
    /// Generates verifiable secret shares and returns one serialized
    /// <c>CommittedDeRecShare</c> per helper channel.
    /// </summary>
    /// <param name="secretId">Identifier of the secret being protected.</param>
    /// <param name="secretData">Raw secret bytes to split using VSS.</param>
    /// <param name="channelIds">Helper channel identifiers. Duplicate entries are deduplicated.</param>
    /// <param name="threshold">Minimum number of shares required for reconstruction.</param>
    /// <param name="version">Logical version of this secret distribution.</param>
    /// <returns>
    /// A <see cref="ProtectSecretResult"/> whose <c>SharesWireBytes</c> contain a
    /// serialized map from channel ID to <c>CommittedDeRecShare</c> bytes.
    /// </returns>
    public static ProtectSecretResult ProtectSecret(
        byte[] secretId,
        byte[] secretData,
        ulong[] channelIds,
        ulong threshold,
        int version
    )
    {
        if (channelIds is null)
        {
            throw new ArgumentNullException(nameof(channelIds));
        }

        Native.Sharing.ProtectSecretResult nativeResult =
            Native.Sharing.protect_secret(
                secretId,
                (UIntPtr)secretId.Length,
                secretData,
                (UIntPtr)secretData.Length,
                channelIds,
                (UIntPtr)channelIds.Length,
                (UIntPtr)threshold,
                version
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            byte[] sharesWireBytes = Utils.CopyBuffer(nativeResult.SharesWireBytes);

            return new ProtectSecretResult
            {
                SharesWireBytes = sharesWireBytes,
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.SharesWireBytes);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    /// <summary>
    /// Wraps a committed helper share into an encrypted delivery envelope.
    ///
    /// Call this once for each share entry returned by <see cref="ProtectSecret"/>,
    /// providing the corresponding helper's shared key (established during pairing).
    /// Send the resulting <see cref="ProduceStoreShareRequestMessageResult.WireBytes"/>
    /// to the helper over the channel transport.
    /// </summary>
    /// <param name="channelId">Channel ID of the target helper.</param>
    /// <param name="version">Share-distribution version number.</param>
    /// <param name="committedShare">
    /// Serialized <c>CommittedDeRecShare</c> protobuf bytes for this channel,
    /// taken from the deserialized map produced by <see cref="ProtectSecret"/>.
    /// </param>
    /// <param name="keepList">
    /// Version numbers the helper should retain. Pass an empty array to use the
    /// helper's default retention policy.
    /// </param>
    /// <param name="description">Human-readable description of this share distribution.</param>
    /// <param name="sharedKey">32-byte symmetric key shared with this helper.</param>
    /// <returns>
    /// A <see cref="ProduceStoreShareRequestMessageResult"/> whose
    /// <c>WireBytes</c> are a serialized <c>DeRecMessage</c> envelope.
    /// </returns>
    public static ProduceStoreShareRequestMessageResult ProduceStoreShareRequestMessage(
        ulong channelId,
        int version,
        byte[] committedShare,
        int[] keepList,
        string description,
        byte[] sharedKey
    )
    {
        if (committedShare is null)
        {
            throw new ArgumentNullException(nameof(committedShare));
        }

        if (keepList is null)
        {
            throw new ArgumentNullException(nameof(keepList));
        }

        if (sharedKey is null)
        {
            throw new ArgumentNullException(nameof(sharedKey));
        }

        if (sharedKey.Length != 32)
        {
            throw new ArgumentException("sharedKey must be exactly 32 bytes.", nameof(sharedKey));
        }

        byte[] descriptionBytes = System.Text.Encoding.UTF8.GetBytes(description ?? string.Empty);

        Native.Sharing.ProduceStoreShareRequestMessageResult nativeResult =
            Native.Sharing.produce_store_share_request_message(
                channelId,
                version,
                committedShare,
                (UIntPtr)committedShare.Length,
                keepList,
                (UIntPtr)keepList.Length,
                descriptionBytes,
                (UIntPtr)descriptionBytes.Length,
                sharedKey,
                (UIntPtr)sharedKey.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            return new ProduceStoreShareRequestMessageResult
            {
                WireBytes = Utils.CopyBuffer(nativeResult.WireBytes),
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.WireBytes);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    /// <summary>
    /// Processes an incoming sharing request on behalf of a Helper.
    ///
    /// Decrypts and validates the <c>StoreShareRequestMessage</c> carried inside the
    /// provided <c>DeRecMessage</c> envelope, extracts the committed share, and returns
    /// an encrypted <c>StoreShareResponseMessage</c> plus the committed share bytes for
    /// local storage.
    /// </summary>
    /// <param name="channelId">Channel ID of the Owner channel this request arrived on.</param>
    /// <param name="sharedKey">32-byte symmetric key shared with the Owner.</param>
    /// <param name="requestBytes">
    /// Serialized <c>DeRecMessage</c> envelope bytes received from the Owner,
    /// as produced by <see cref="ProduceStoreShareRequestMessage"/>.
    /// </param>
    /// <returns>
    /// A <see cref="ProduceStoreShareResponseMessageResult"/> containing the response wire
    /// bytes and the serialized committed share bytes for local storage.
    /// </returns>
    public static ProduceStoreShareResponseMessageResult ProduceStoreShareResponseMessage(
        ulong channelId,
        byte[] sharedKey,
        byte[] requestBytes
    )
    {
        if (sharedKey is null)
        {
            throw new ArgumentNullException(nameof(sharedKey));
        }

        if (sharedKey.Length != 32)
        {
            throw new ArgumentException("sharedKey must be exactly 32 bytes.", nameof(sharedKey));
        }

        if (requestBytes is null)
        {
            throw new ArgumentNullException(nameof(requestBytes));
        }

        Native.Sharing.ProduceStoreShareResponseMessageResult nativeResult =
            Native.Sharing.produce_store_share_response_message(
                channelId,
                sharedKey,
                (UIntPtr)sharedKey.Length,
                requestBytes,
                (UIntPtr)requestBytes.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);

            return new ProduceStoreShareResponseMessageResult
            {
                WireBytes = Utils.CopyBuffer(nativeResult.WireBytes),
                CommittedShareBytes = Utils.CopyBuffer(nativeResult.CommittedShareBytes),
            };
        }
        finally
        {
            Utils.FreeBuffer(nativeResult.WireBytes);
            Utils.FreeBuffer(nativeResult.CommittedShareBytes);
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }

    /// <summary>
    /// Validates a sharing response received from a Helper.
    ///
    /// Decrypts and validates the <c>StoreShareResponseMessage</c> carried inside the
    /// provided <c>DeRecMessage</c> envelope. Checks the timestamp invariant, that the
    /// echoed version matches the supplied <paramref name="version"/>, and that the
    /// <c>result</c> field is present.
    /// </summary>
    /// <param name="version">Version number that was sent in the original request.</param>
    /// <param name="sharedKey">32-byte symmetric key shared with the Helper.</param>
    /// <param name="responseBytes">
    /// Serialized <c>DeRecMessage</c> envelope bytes received from the Helper,
    /// as produced by <see cref="ProduceStoreShareResponseMessage"/>.
    /// </param>
    /// <exception cref="DeRecException">
    /// Thrown if decryption, decoding, or invariant checks fail, or if the Helper's
    /// response status is not <c>Ok</c>. The exception message includes the Helper's
    /// status code and memo when the rejection originates from the Helper.
    /// </exception>
    public static void ProcessStoreShareResponseMessage(
        int version,
        byte[] sharedKey,
        byte[] responseBytes
    )
    {
        if (sharedKey is null)
        {
            throw new ArgumentNullException(nameof(sharedKey));
        }

        if (sharedKey.Length != 32)
        {
            throw new ArgumentException("sharedKey must be exactly 32 bytes.", nameof(sharedKey));
        }

        if (responseBytes is null)
        {
            throw new ArgumentNullException(nameof(responseBytes));
        }

        Native.Sharing.ProcessStoreShareResponseMessageResult nativeResult =
            Native.Sharing.process_store_share_response_message(
                version,
                sharedKey,
                (UIntPtr)sharedKey.Length,
                responseBytes,
                (UIntPtr)responseBytes.Length
            );

        try
        {
            Utils.ThrowIfError(nativeResult.Status);
        }
        finally
        {
            Utils.FreeStatusMessage(nativeResult.Status);
        }
    }
}
