// SPDX-License-Identifier: Apache-2.0

namespace DeRec.Library;

/// <summary>
/// Identifies the protocol phase or layer that produced an error. Mirrors the
/// <c>DEREC_CATEGORY_*</c> constants from the C FFI. The same value means the
/// same thing across all language bindings.
/// </summary>
public static class DeRecCategory
{
    public const int Ok = 0;
    public const int Ffi = 1;
    public const int Pairing = 2;
    public const int Sharing = 3;
    public const int Recovery = 4;
    public const int Verification = 5;
    public const int Discovery = 6;
    public const int Unpairing = 7;
    public const int DeRecMessage = 8;
    public const int SecretStore = 9;
    public const int ChannelStore = 10;
    public const int ShareStore = 11;
    public const int InvalidInput = 12;
    public const int Protobuf = 13;
    public const int Invariant = 14;
}

/// <summary>
/// Identifies the specific reason an operation failed. Mirrors the
/// <c>DEREC_CODE_*</c> constants from the C FFI. Codes are global — the same
/// value means the same thing regardless of <see cref="DeRecCategory"/>.
/// </summary>
public static class DeRecCode
{
    public const int Ok = 0;
    public const int NonOkStatus = 1;
    public const int VersionMismatch = 2;
    public const int Invariant = 3;
    public const int InvalidInput = 4;
    public const int ProtobufDecode = 5;
    public const int ProtobufEncode = 6;
    public const int ProtocolViolation = 7;
    public const int StoreError = 8;
    public const int BuilderError = 9;
    /// <summary>
    /// Returned by the secret store's <c>LoadMany</c> with <c>MissingPolicy.Fail</c>
    /// when one or more channels had no <c>SharedKey</c> entry. The formatted
    /// <see cref="DeRecException.Message"/> carries the missing channel ids
    /// (e.g. <c>"secret store: missing SharedKey entries for channel(s): [42, 7]"</c>).
    /// <see cref="DeRecException.Category"/> is
    /// <see cref="DeRecCategory.SecretStore"/>.
    /// </summary>
    public const int MissingSharedKey = 10;

    /// <summary>
    /// The protocol was built without a local replica id but a replica-mode
    /// flow was attempted. Returned by every entry point that requires local
    /// replica identity.
    /// <see cref="DeRecException.Category"/> is
    /// <see cref="DeRecCategory.InvalidInput"/>.
    /// </summary>
    public const int ReplicaIdNotConfigured = 12;

    public const int Encryption = 20;
    public const int Keygen = 21;
    public const int FinishPairingInitiator = 22;
    public const int FinishPairingResponder = 23;

    public const int EmptyTransportUri = 40;
    public const int InvalidContactMessage = 41;
    public const int InvalidPairRequestMessage = 42;
    public const int InvalidPairResponseMessage = 43;
    /// <summary>
    /// Returned by <c>Pairing.Response.ProcessPrePair</c> when the public keys
    /// published by the contact creator don't hash to the
    /// <see cref="ContactMessage.ContactBindingHash"/> carried by the original
    /// <see cref="ContactMessage"/>. Cryptographically distinguishable from a
    /// normal rejection — surfaces as a typed error so applications can flag
    /// it specifically (the contact the user scanned does not match the keys
    /// they would pair with).
    /// <see cref="DeRecException.Category"/> is
    /// <see cref="DeRecCategory.Pairing"/>.
    /// </summary>
    public const int PrePairHashMismatch = 44;

    /// <summary>
    /// A replica-mode pairing arrived without the reserved
    /// <c>derec.replica_id</c> key in <c>CommunicationInfo</c>. Replica
    /// pairings cannot proceed without a peer-side identity to record on
    /// the channel; the orchestrator refuses the pairing rather than
    /// completing it with a missing field.
    /// <see cref="DeRecException.Category"/> is
    /// <see cref="DeRecCategory.Pairing"/>.
    /// </summary>
    public const int MissingReplicaId = 45;

    /// <summary>
    /// A non-replica pairing carried the reserved <c>derec.replica_id</c>
    /// key in <c>CommunicationInfo</c>. The reserved key is only valid for
    /// replica-mode pairings; its presence on an Owner/Helper pairing
    /// indicates either a misconfigured peer or a downgrade attempt.
    /// <see cref="DeRecException.Category"/> is
    /// <see cref="DeRecCategory.Pairing"/>.
    /// </summary>
    public const int UnexpectedReplicaId = 46;

    public const int EmptyChannels = 60;
    public const int DuplicateChannelId = 61;
    public const int InvalidThreshold = 62;
    public const int EmptySecretData = 63;
    public const int VssShareFailed = 64;

    public const int EmptyResponses = 80;
    public const int EmptyCommittedDeRecShare = 81;
    public const int DecodeCommittedDeRecShare = 82;
    public const int DecodeDeRecShare = 83;
    public const int SecretIdMismatch = 84;
    public const int ReconstructionFailed = 85;

    public const int FfiNullPtr = 100;
    public const int FfiBadLength = 101;
    public const int FfiBadUtf8 = 102;
    public const int FfiBadProto = 103;
    public const int FfiInvalidEnum = 104;
    public const int FfiBadSharedKey = 105;
    public const int FfiNulInString = 106;
}
