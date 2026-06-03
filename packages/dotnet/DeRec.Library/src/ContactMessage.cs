// SPDX-License-Identifier: Apache-2.0

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
    /// <summary>Serializes this <see cref="ContactMessage"/> to protobuf wire bytes.</summary>
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
        return proto.ToByteArray();
    }

    /// <summary>Deserializes a <see cref="ContactMessage"/> from protobuf wire bytes.</summary>
    internal static ContactMessage FromProtoBytes(byte[] bytes)
    {
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
        );
    }
}
