// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

using Google.Protobuf;

namespace DeRec.Library;

/// <summary>
/// Decoded representation of a DeRec <c>ContactMessage</c>, exchanged out-of-band
/// before pairing begins.
/// </summary>
/// <param name="ChannelId">
/// Channel identifier the initiator expects to use for the new pairing session.
/// </param>
/// <param name="ContactMode">
/// Selects how the public encryption material is delivered. See
/// <see cref="ContactMode"/>.
/// </param>
/// <param name="Nonce">
/// Random nonce that binds the pairing request to this contact exchange.
/// </param>
/// <param name="MlkemEncapsulationKey">
/// Serialized ML-KEM-768 encapsulation key. Present only when
/// <see cref="ContactMode"/> is <see cref="ContactMode.InlineKeys"/>.
/// </param>
/// <param name="EciesPublicKey">
/// Serialized ECIES public key. Present only when
/// <see cref="ContactMode"/> is <see cref="ContactMode.InlineKeys"/>.
/// </param>
/// <param name="ContactBindingHash">
/// SHA-384 commitment to the public encryption material. Present only when
/// <see cref="ContactMode"/> is <see cref="ContactMode.HashedKeys"/>. Validated
/// by the scanner after it receives the keys via <c>PrePair</c>.
/// </param>
public sealed record ContactMessage(
    ulong ChannelId,
    ContactMode ContactMode,
    ulong Nonce,
    byte[]? MlkemEncapsulationKey,
    byte[]? EciesPublicKey,
    byte[]? ContactBindingHash
)
{
    /// <summary>
    /// Every transport endpoint the creator of this contact can be reached on,
    /// in its own preference order.
    /// </summary>
    /// <remarks>
    /// Preserved across a decode/encode round trip, so a contact this SDK
    /// parses and hands back to <c>Pairing.Request.Produce</c> still
    /// advertises every endpoint the creator offered.
    /// </remarks>
    public IReadOnlyList<TransportProtocol> SupportedTransports { get; init; } =
        Array.Empty<TransportProtocol>();

    /// <summary>
    /// The endpoints this contact advertises, in the creator's own order.
    /// </summary>
    /// <remarks>
    /// Reports what was advertised, not what is acceptable; nothing here is
    /// validated.
    /// </remarks>
    public IReadOnlyList<TransportProtocol> AdvertisedEndpoints() => SupportedTransports;

    /// <summary>
    /// When the creator produced this contact, or <c>null</c> if unset.
    /// </summary>
    public Timestamp? Timestamp { get; init; }

    /// <summary>
    /// Serializes this <see cref="ContactMessage"/> to protobuf wire bytes.
    /// </summary>
    /// <exception cref="DeRecException">
    /// The contact violates its <see cref="ContactMode"/> invariant.
    /// </exception>
    public byte[] ToProtoBytes()
    {
        var proto = new Org.Derecalliance.Derec.Protobuf.ContactMessage
        {
            ChannelId = ChannelId,
            ContactMode = (Org.Derecalliance.Derec.Protobuf.ContactMode)(int)ContactMode,
            Nonce = Nonce,
        };
        foreach (TransportProtocol offer in SupportedTransports)
        {
            proto.SupportedTransports.Add(new Org.Derecalliance.Derec.Protobuf.TransportProtocol
            {
                Uri = offer.Uri,
                Protocol = (Org.Derecalliance.Derec.Protobuf.Protocol)(int)offer.Protocol,
            });
        }
        if (MlkemEncapsulationKey is { Length: > 0 } mlkem)
        {
            proto.MlkemEncapsulationKey = Google.Protobuf.ByteString.CopyFrom(mlkem);
        }
        if (EciesPublicKey is { Length: > 0 } ecies)
        {
            proto.EciesPublicKey = Google.Protobuf.ByteString.CopyFrom(ecies);
        }
        if (ContactBindingHash is { Length: > 0 } hash)
        {
            proto.ContactBindingHash = Google.Protobuf.ByteString.CopyFrom(hash);
        }
        if (Timestamp is { } ts)
        {
            proto.Timestamp = new Google.Protobuf.WellKnownTypes.Timestamp
            {
                Seconds = ts.Seconds,
                Nanos = ts.Nanos,
            };
        }
        byte[] bytes = proto.ToByteArray();
        Validate(bytes);
        return bytes;
    }

    /// <summary>
    /// Decodes a <see cref="ContactMessage"/> from protobuf wire bytes, such
    /// as those received out of band from a QR code.
    /// </summary>
    /// <exception cref="DeRecException">
    /// The bytes are not a valid contact: undecodable, unknown
    /// <see cref="ContactMode"/>, fields inconsistent with the mode, or a
    /// binding hash of the wrong length.
    /// </exception>
    public static ContactMessage FromProtoBytes(byte[] bytes)
    {
        Validate(bytes);

        var proto = Org.Derecalliance.Derec.Protobuf.ContactMessage.Parser.ParseFrom(bytes);

        // proto3 `optional bytes` fields are reported via `HasFoo` once set;
        // if the field was never set the property still returns `ByteString.Empty`,
        // so we map that case to `null` to match the wire semantics.
        byte[]? mlkem = proto.HasMlkemEncapsulationKey
            ? proto.MlkemEncapsulationKey.ToByteArray()
            : null;
        byte[]? ecies = proto.HasEciesPublicKey
            ? proto.EciesPublicKey.ToByteArray()
            : null;
        byte[]? hash = proto.HasContactBindingHash
            ? proto.ContactBindingHash.ToByteArray()
            : null;

        return new ContactMessage(
            ChannelId: proto.ChannelId,
            ContactMode: (ContactMode)(int)proto.ContactMode,
            Nonce: proto.Nonce,
            MlkemEncapsulationKey: mlkem,
            EciesPublicKey: ecies,
            ContactBindingHash: hash
        )
        {
            SupportedTransports = proto.SupportedTransports
                .Select(t => new TransportProtocol(t.Uri, (Protocol)(int)t.Protocol))
                .ToList(),
            Timestamp = proto.Timestamp is { } ts ? new Timestamp(ts.Seconds, ts.Nanos) : null,
        };
    }

    private static void Validate(byte[] bytes)
    {
        Native.DeRecError error =
            Native.Pairing.validate_contact_message(bytes, (UIntPtr)bytes.Length);
        Utils.ThrowIfError(error);
    }
}
