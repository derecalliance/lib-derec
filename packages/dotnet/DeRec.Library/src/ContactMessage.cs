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
/// <param name="TransportProtocol">
/// Transport endpoint and protocol to use when sending protocol messages to the initiator.
///
/// <para>
/// <b>Reading this directly is incorrect.</b> Its meaning narrowed from "the
/// endpoint" to "one entry of a list, and possibly absent": a creator that has
/// moved past this field populates only <see cref="SupportedTransports"/>, and
/// this property is then an empty-URI placeholder. Call
/// <see cref="AdvertisedEndpoints"/>, which resolves both spellings. Removed at
/// 0.0.5.
/// </para>
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
    TransportProtocol TransportProtocol,
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
    /// Empty means "only <see cref="TransportProtocol"/> is offered", which is
    /// how every implementation predating this field advertises. Preserved
    /// across a decode/encode round trip, so a contact this SDK parses and
    /// hands back to <c>Pairing.Request.Produce</c> still advertises every
    /// endpoint the creator offered.
    /// </remarks>
    public IReadOnlyList<TransportProtocol> SupportedTransports { get; init; } =
        Array.Empty<TransportProtocol>();

    /// <summary>
    /// The endpoints this contact advertises, in the creator's own order.
    /// </summary>
    /// <remarks>
    /// Yields <see cref="SupportedTransports"/> when it is non-empty, and
    /// otherwise the singular <see cref="TransportProtocol"/> — which is how
    /// every implementation predating the offer list advertises, and the reason
    /// this is a method rather than a property read. Reports what was
    /// advertised, not what is acceptable; nothing here is validated.
    /// </remarks>
    public IReadOnlyList<TransportProtocol> AdvertisedEndpoints() =>
        SupportedTransports.Count > 0
            ? SupportedTransports
            : string.IsNullOrEmpty(TransportProtocol.Uri)
                ? Array.Empty<TransportProtocol>()
                : new[] { TransportProtocol };

    /// <summary>
    /// Serializes this <see cref="ContactMessage"/> to protobuf wire bytes.
    /// </summary>
    /// <remarks>
    /// Structurally validates the contact's <c>(ContactMode, inline keys,
    /// binding hash)</c> tuple before emitting bytes — a locally constructed
    /// instance that violates the per-mode invariant raises
    /// <see cref="DeRecException"/> instead of producing a wire blob that
    /// downstream consumers would reject anyway.
    /// </remarks>
    // Touches the deprecated singular `transportProtocol`: this is the
    // compatibility path that keeps peers predating `supportedTransports`
    // working, so the warning is expected here rather than a defect.
#pragma warning disable CS0612
    internal byte[] ToProtoBytes()
    {
        var proto = new Org.Derecalliance.Derec.Protobuf.ContactMessage
        {
            ChannelId = ChannelId,
            ContactMode = (Org.Derecalliance.Derec.Protobuf.ContactMode)(int)ContactMode,
            TransportProtocol = new Org.Derecalliance.Derec.Protobuf.TransportProtocol
            {
                Uri = TransportProtocol.Uri,
                Protocol = (Org.Derecalliance.Derec.Protobuf.Protocol)(int)TransportProtocol.Protocol,
            },
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
        byte[] bytes = proto.ToByteArray();
        Validate(bytes);
        return bytes;
    }

    /// <summary>
    /// Deserializes a <see cref="ContactMessage"/> from protobuf wire bytes
    /// and structurally validates the result against the per-mode invariant
    /// documented on the wire format. Throws <see cref="DeRecException"/>
    /// if the contact is malformed (unknown <see cref="ContactMode"/>,
    /// mode/field mismatch, wrong binding-hash length).
    /// </summary>
    // Touches the deprecated singular `transportProtocol`: this is the
    // compatibility path that keeps peers predating `supportedTransports`
    // working, so the warning is expected here rather than a defect.
#pragma warning disable CS0612
    internal static ContactMessage FromProtoBytes(byte[] bytes)
    {
        Validate(bytes);

        var proto = Org.Derecalliance.Derec.Protobuf.ContactMessage.Parser.ParseFrom(bytes);

        var tp = proto.TransportProtocol is { } protoTp
            ? new TransportProtocol(protoTp.Uri, (Protocol)(int)protoTp.Protocol)
            : new TransportProtocol(string.Empty);

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
            TransportProtocol: tp,
            Nonce: proto.Nonce,
            MlkemEncapsulationKey: mlkem,
            EciesPublicKey: ecies,
            ContactBindingHash: hash
        )
        {
            SupportedTransports = proto.SupportedTransports
                .Select(t => new TransportProtocol(t.Uri, (Protocol)(int)t.Protocol))
                .ToList(),
        };
    }

    private static void Validate(byte[] bytes)
    {
        Native.DeRecError error =
            Native.Pairing.validate_contact_message(bytes, (UIntPtr)bytes.Length);
        Utils.ThrowIfError(error);
    }
}
#pragma warning restore CS0612
