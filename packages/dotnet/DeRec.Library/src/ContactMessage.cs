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
/// <param name="TransportProtocol">
/// Transport endpoint and protocol to use when sending protocol messages to the initiator.
/// </param>
/// <param name="Nonce">
/// Random nonce that binds the pairing request to this contact exchange.
/// </param>
/// <param name="MlkemEncapsulationKey">
/// Serialized ML-KEM-768 encapsulation key. Required to complete the pairing flow.
/// </param>
/// <param name="EciesPublicKey">
/// Serialized ECIES public key. Required to complete the pairing flow.
/// </param>
public sealed record ContactMessage(
    ulong ChannelId,
    TransportProtocol TransportProtocol,
    ulong Nonce,
    byte[] MlkemEncapsulationKey,
    byte[] EciesPublicKey
)
{
    /// <summary>Serializes this <see cref="ContactMessage"/> to protobuf wire bytes.</summary>
    internal byte[] ToProtoBytes()
    {
        var proto = new Org.Derecalliance.Derec.Protobuf.ContactMessage
        {
            ChannelId = ChannelId,
            TransportProtocol = new Org.Derecalliance.Derec.Protobuf.TransportProtocol
            {
                Uri = TransportProtocol.Uri,
                Protocol = (Org.Derecalliance.Derec.Protobuf.Protocol)(int)TransportProtocol.Protocol,
            },
            Nonce = Nonce,
            MlkemEncapsulationKey = Google.Protobuf.ByteString.CopyFrom(MlkemEncapsulationKey),
            EciesPublicKey = Google.Protobuf.ByteString.CopyFrom(EciesPublicKey),
        };
        return proto.ToByteArray();
    }

    /// <summary>Deserializes a <see cref="ContactMessage"/> from protobuf wire bytes.</summary>
    internal static ContactMessage FromProtoBytes(byte[] bytes)
    {
        var proto = Org.Derecalliance.Derec.Protobuf.ContactMessage.Parser.ParseFrom(bytes);

        var tp = proto.TransportProtocol is { } protoTp
            ? new TransportProtocol(protoTp.Uri, (Protocol)(int)protoTp.Protocol)
            : new TransportProtocol(string.Empty);

        return new ContactMessage(
            ChannelId: proto.ChannelId,
            TransportProtocol: tp,
            Nonce: proto.Nonce,
            MlkemEncapsulationKey: proto.MlkemEncapsulationKey.ToByteArray(),
            EciesPublicKey: proto.EciesPublicKey.ToByteArray()
        );
    }
}
