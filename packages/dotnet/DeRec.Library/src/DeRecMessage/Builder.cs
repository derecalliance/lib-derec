using System;
using System.Collections.Generic;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Org.Derecalliance.Derec.Protobuf;

namespace DeRec.Library;

public sealed class DeRecMessageBuilder
{
    private enum EnvelopeSide
    {
        Owner,
        Helper,
    }

    private byte[]? _sender;
    private byte[]? _receiver;
    private byte[]? _secretId;
    private Google.Protobuf.WellKnownTypes.Timestamp? _timestamp =
        Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(DateTimeOffset.UtcNow);
    private EnvelopeSide? _side;

    private readonly List<DeRecMessage.Types.SharerMessageBody> _ownerBodies = new();
    private readonly List<DeRecMessage.Types.HelperMessageBody> _helperBodies = new();

    public DeRecMessageBuilder Sender(byte[] sender)
    {
        ArgumentNullException.ThrowIfNull(sender);
        _sender = (byte[])sender.Clone();
        return this;
    }

    public DeRecMessageBuilder Receiver(byte[] receiver)
    {
        ArgumentNullException.ThrowIfNull(receiver);
        _receiver = (byte[])receiver.Clone();
        return this;
    }

    public DeRecMessageBuilder SecretId(byte[] secretId)
    {
        ArgumentNullException.ThrowIfNull(secretId);

        if (secretId.Length is < 1 or > 16)
        {
            throw new ArgumentException(
                $"secretId must be between 1 and 16 bytes, got {secretId.Length}.",
                nameof(secretId)
            );
        }

        _secretId = (byte[])secretId.Clone();
        return this;
    }

    public DeRecMessageBuilder Timestamp(Timestamp timestamp)
    {
        ArgumentNullException.ThrowIfNull(timestamp);
        _timestamp = timestamp.Clone();
        return this;
    }

    public DeRecMessageBuilder Timestamp(DateTimeOffset timestamp)
    {
        _timestamp = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(
            timestamp.ToUniversalTime()
        );
        return this;
    }

    public DeRecMessageBuilder Message(IMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        switch (message)
        {
            case PairRequestMessage m:
                EnsureSide(EnvelopeSide.Owner);
                _ownerBodies.Add(new DeRecMessage.Types.SharerMessageBody
                {
                    PairRequestMessage = m
                });
                break;

            case UnpairRequestMessage m:
                EnsureSide(EnvelopeSide.Owner);
                _ownerBodies.Add(new DeRecMessage.Types.SharerMessageBody
                {
                    UnpairRequestMessage = m
                });
                break;

            case StoreShareRequestMessage m:
                EnsureSide(EnvelopeSide.Owner);
                _ownerBodies.Add(new DeRecMessage.Types.SharerMessageBody
                {
                    StoreShareRequestMessage = m
                });
                break;

            case VerifyShareRequestMessage m:
                EnsureSide(EnvelopeSide.Owner);
                _ownerBodies.Add(new DeRecMessage.Types.SharerMessageBody
                {
                    VerifyShareRequestMessage = m
                });
                break;

            case GetSecretIdsVersionsRequestMessage m:
                EnsureSide(EnvelopeSide.Owner);
                _ownerBodies.Add(new DeRecMessage.Types.SharerMessageBody
                {
                    GetSecretIdsVersionsRequestMessage = m
                });
                break;

            case GetShareRequestMessage m:
                EnsureSide(EnvelopeSide.Owner);
                _ownerBodies.Add(new DeRecMessage.Types.SharerMessageBody
                {
                    GetShareRequestMessage = m
                });
                break;

            case PairResponseMessage m:
                EnsureSide(EnvelopeSide.Helper);
                _helperBodies.Add(new DeRecMessage.Types.HelperMessageBody
                {
                    PairResponseMessage = m
                });
                break;

            case UnpairResponseMessage m:
                EnsureSide(EnvelopeSide.Helper);
                _helperBodies.Add(new DeRecMessage.Types.HelperMessageBody
                {
                    UnpairResponseMessage = m
                });
                break;

            case StoreShareResponseMessage m:
                EnsureSide(EnvelopeSide.Helper);
                _helperBodies.Add(new DeRecMessage.Types.HelperMessageBody
                {
                    StoreShareResponseMessage = m
                });
                break;

            case VerifyShareResponseMessage m:
                EnsureSide(EnvelopeSide.Helper);
                _helperBodies.Add(new DeRecMessage.Types.HelperMessageBody
                {
                    VerifyShareResponseMessage = m
                });
                break;

            case GetSecretIdsVersionsResponseMessage m:
                EnsureSide(EnvelopeSide.Helper);
                _helperBodies.Add(new DeRecMessage.Types.HelperMessageBody
                {
                    GetSecretIdsVersionsResponseMessage = m
                });
                break;

            case GetShareResponseMessage m:
                EnsureSide(EnvelopeSide.Helper);
                _helperBodies.Add(new DeRecMessage.Types.HelperMessageBody
                {
                    GetShareResponseMessage = m
                });
                break;

            case ErrorResponseMessage m:
                EnsureSide(EnvelopeSide.Helper);
                _helperBodies.Add(new DeRecMessage.Types.HelperMessageBody
                {
                    ErrorResponseMessage = m
                });
                break;

            default:
                throw new ArgumentException(
                    $"Unsupported DeRec message type: {message.GetType().FullName}.",
                    nameof(message)
                );
        }

        return this;
    }

    public DeRecMessage Build()
    {
        if (_sender is null)
        {
            throw new InvalidOperationException("missing sender");
        }

        if (_receiver is null)
        {
            throw new InvalidOperationException("missing receiver");
        }

        if (_secretId is null)
        {
            throw new InvalidOperationException("missing secretId");
        }

        if (_timestamp is null)
        {
            throw new InvalidOperationException("missing timestamp");
        }

        if (_side is null)
        {
            throw new InvalidOperationException("missing message bodies");
        }

        ProtocolVersion protocolVersion = ProtocolVersion.Current();

        DeRecMessage.Types.MessageBodies messageBodies = _side switch
        {
            EnvelopeSide.Owner => new DeRecMessage.Types.MessageBodies
            {
                SharerMessageBodies = new DeRecMessage.Types.SharerMessageBodies()
            },
            EnvelopeSide.Helper => new DeRecMessage.Types.MessageBodies
            {
                HelperMessageBodies = new DeRecMessage.Types.HelperMessageBodies()
            },
            _ => throw new InvalidOperationException("invalid envelope side")
        };

        if (_side == EnvelopeSide.Owner)
        {
            messageBodies.SharerMessageBodies.SharerMessageBody.Add(_ownerBodies);
        }
        else
        {
            messageBodies.HelperMessageBodies.HelperMessageBody.Add(_helperBodies);
        }

        return new DeRecMessage
        {
            ProtocolVersionMajor = protocolVersion.Major,
            ProtocolVersionMinor = protocolVersion.Minor,
            Sender = ByteString.CopyFrom(_sender),
            Receiver = ByteString.CopyFrom(_receiver),
            SecretId = ByteString.CopyFrom(_secretId),
            Timestamp = _timestamp.Clone(),
            MessageBodies = messageBodies
        };
    }

    private void EnsureSide(EnvelopeSide side)
    {
        if (_side is null)
        {
            _side = side;
            return;
        }

        if (_side != side)
        {
            throw new InvalidOperationException(
                "cannot mix owner and helper message bodies in one DeRecMessage"
            );
        }
    }
}
