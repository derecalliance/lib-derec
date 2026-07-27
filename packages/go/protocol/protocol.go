// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/internal/native"
)

// UnpairAck controls whether the unpair initiator waits for the peer's
// acknowledgement before dropping local channel state. Mirrors
// derec_library::protocol::UnpairAck; values match the Rust enum and the
// unpair_ack field documented on derec_protocol_new_packed.
type UnpairAck int32

const (
	// UnpairAckRequired waits for the peer's UnpairResponse before
	// dropping local state. Default.
	UnpairAckRequired UnpairAck = 0
	// UnpairAckNotRequired drops local state immediately on initiating
	// unpair, without waiting for an acknowledgement.
	UnpairAckNotRequired UnpairAck = 1
)

// AutoAcceptPolicy is a per-flow auto-accept toggle set, mirroring the
// Rust AutoAcceptPolicy field for field. When a flow's field is true, the
// orchestrator internally accepts the matching inbound request instead of
// surfacing it for the application to accept explicitly. Zero value is
// "every flow off" (today's behavior: every request surfaces for the
// application to decide).
type AutoAcceptPolicy struct {
	Pairing           bool
	PrePair           bool
	StoreShare        bool
	VerifyShare       bool
	Discovery         bool
	GetShare          bool
	Unpair            bool
	UpdateChannelInfo bool
}

// Config configures a DeRecProtocol instance. Mirrors the Rust
// DeRecProtocolBuilder / dotnet DeRecProtocolBuilder field for field; a
// zero-valued field falls back to the same default those builders use,
// documented per field below.
type Config struct {
	// SecretID identifies the single secret this protocol instance
	// manages.
	SecretID uint64

	// OwnTransportURI is this node's advertised transport endpoint. An
	// empty URI defers configuration to a later SetOwnTransport call;
	// any pairing flow requires it to be set first.
	OwnTransportURI string
	// OwnTransportProtocol selects the transport scheme for
	// OwnTransportURI; 0 = HTTPS (see derecpb.Protocol_HTTPS), currently
	// the only defined value.
	OwnTransportProtocol int32

	// Threshold is the minimum number of shares required to reconstruct
	// the secret. Default: 3.
	Threshold uint32
	// KeepVersionsCount is the number of recent share versions each
	// helper retains. Default: 3.
	KeepVersionsCount uint32
	// CommunicationInfo carries key/value pairs included in
	// pairing-request and pairing-response CommunicationInfo. Default:
	// empty.
	CommunicationInfo map[string]string
	// Timeout is the protocol-wide staleness boundary, truncated to
	// seconds and clamped to at least 1 second. Default: 5 minutes.
	Timeout time.Duration
	// AutoRespondOnFailure controls whether the protocol auto-replies on
	// failed inbound processing. Default: false.
	AutoRespondOnFailure bool
	// UnpairAck controls whether the unpair initiator waits for the
	// peer's acknowledgement. Default: UnpairAckRequired.
	UnpairAck UnpairAck
	// AutoReplyTo controls whether outbound requests carry an ephemeral
	// replyTo pointing at OwnTransportURI. Default: false.
	AutoReplyTo bool
	// AutoAccept is the per-flow auto-accept policy. Default: every flow
	// off.
	AutoAccept AutoAcceptPolicy
	// ReplicaID configures this node's local replica_id, required for
	// any replica-mode pairing. Default: unset.
	ReplicaID *uint64
}

// DeRecProtocol is the orchestrator instance bound to a set of
// application-supplied store/transport implementations. Not safe for
// concurrent use — callers must not invoke methods on the same instance
// from more than one goroutine at a time, matching every other DeRec SDK.
type DeRecProtocol struct {
	instance *native.ProtocolInstance

	// Strong references keeping the store/transport implementations
	// reachable for as long as Rust may still invoke a callback into
	// them, mirroring the dotnet wrapper's GC-root fields. Never read —
	// their only purpose is to outlive instance.
	channelStore    ChannelStore
	secretStore     SecretStore
	shareStore      ShareStore
	userSecretStore UserSecretStore
	stateStore      StateStore
	transport       Transport

	closed bool
}

// New constructs a DeRecProtocol bound to the given store/transport
// implementations and config. It assembles the C callback tables backing
// each store (internal/native's buildCallbacks) and then calls
// derec_protocol_new_packed — the first genuine C-ABI round trip a
// protocol instance makes. On error the store registration is released before
// returning; callers only need to call Close on success.
func New(
	channelStore ChannelStore,
	shareStore ShareStore,
	secretStore SecretStore,
	userSecretStore UserSecretStore,
	stateStore StateStore,
	transport Transport,
	config Config,
) (*DeRecProtocol, error) {
	if channelStore == nil {
		return nil, errors.New("protocol: New: channelStore is required")
	}
	if shareStore == nil {
		return nil, errors.New("protocol: New: shareStore is required")
	}
	if secretStore == nil {
		return nil, errors.New("protocol: New: secretStore is required")
	}
	if userSecretStore == nil {
		return nil, errors.New("protocol: New: userSecretStore is required")
	}
	if stateStore == nil {
		return nil, errors.New("protocol: New: stateStore is required")
	}
	if transport == nil {
		return nil, errors.New("protocol: New: transport is required")
	}

	threshold := config.Threshold
	if threshold == 0 {
		threshold = 3
	}
	keepVersionsCount := config.KeepVersionsCount
	if keepVersionsCount == 0 {
		keepVersionsCount = 3
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	timeoutInSecs := uint32(timeout.Truncate(time.Second).Seconds())
	if timeoutInSecs == 0 {
		timeoutInSecs = 1
	}

	commInfo, err := encodeCommunicationInfo(config.CommunicationInfo)
	if err != nil {
		return nil, err
	}

	nativeCfg := native.ProtocolConfig{
		SecretID:             config.SecretID,
		OwnTransportURI:      config.OwnTransportURI,
		OwnTransportProtocol: config.OwnTransportProtocol,
		Threshold:            threshold,
		KeepVersionsCount:    keepVersionsCount,
		CommunicationInfo:    commInfo,
		TimeoutInSecs:        timeoutInSecs,
		AutoRespondOnFailure: config.AutoRespondOnFailure,
		UnpairAck:            int32(config.UnpairAck),
		AutoReplyTo:          config.AutoReplyTo,
		AutoAccept: native.AutoAcceptPolicy{
			Pairing:           config.AutoAccept.Pairing,
			PrePair:           config.AutoAccept.PrePair,
			StoreShare:        config.AutoAccept.StoreShare,
			VerifyShare:       config.AutoAccept.VerifyShare,
			Discovery:         config.AutoAccept.Discovery,
			GetShare:          config.AutoAccept.GetShare,
			Unpair:            config.AutoAccept.Unpair,
			UpdateChannelInfo: config.AutoAccept.UpdateChannelInfo,
		},
		ReplicaID: config.ReplicaID,
	}

	instance, err := native.NewProtocolInstance(
		channelStore, secretStore, shareStore, userSecretStore, stateStore, transport,
		nativeCfg,
	)
	if err != nil {
		return nil, err
	}

	return &DeRecProtocol{
		instance:        instance,
		channelStore:    channelStore,
		secretStore:     secretStore,
		shareStore:      shareStore,
		userSecretStore: userSecretStore,
		stateStore:      stateStore,
		transport:       transport,
	}, nil
}

// Close frees the underlying protocol handle and releases the store
// registration. Idempotent — safe to call more than once.
func (p *DeRecProtocol) Close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	p.instance.Free()
	return nil
}

// GetFingerprint derives the human-readable fingerprint for channelID's
// shared key, for out-of-band comparison during pairing confirmation.
// Fails if the channel has no shared key (not yet paired).
func (p *DeRecProtocol) GetFingerprint(channelID uint64) (string, error) {
	if p.closed {
		return "", errors.New("protocol: GetFingerprint: protocol is closed")
	}
	return p.instance.GetFingerprint(channelID)
}

// VerifyFingerprint compares fingerprint against channelID's
// locally-derived one. On match, the channel transitions from Pending to
// Paired and this returns true. Every non-nil error, and every legitimate
// mismatch, returns false — callers must check err to distinguish "did
// not match" from "could not be verified".
func (p *DeRecProtocol) VerifyFingerprint(channelID uint64, fingerprint string) (bool, error) {
	if p.closed {
		return false, errors.New("protocol: VerifyFingerprint: protocol is closed")
	}
	return p.instance.VerifyFingerprint(channelID, fingerprint)
}

// SetOwnTransport replaces this node's local transport endpoint. Only
// mutates local state — propagating the change to paired peers requires a
// follow-up UpdateChannelInfo flow. See Config.OwnTransportProtocol for
// the protocol argument's meaning.
func (p *DeRecProtocol) SetOwnTransport(uri string, protocol int32) error {
	if p.closed {
		return errors.New("protocol: SetOwnTransport: protocol is closed")
	}
	return p.instance.SetOwnTransport(uri, protocol)
}

// SetCommunicationInfo replaces this node's local communication_info map.
// Does not contact peers — follow up with an UpdateChannelInfo flow to
// propagate the change.
func (p *DeRecProtocol) SetCommunicationInfo(info map[string]string) error {
	if p.closed {
		return errors.New("protocol: SetCommunicationInfo: protocol is closed")
	}
	return p.instance.SetCommunicationInfo(info)
}

// Process hands an inbound wire-encoded DeRecMessage envelope to the
// protocol core and returns the resulting events, decoded from the JSON
// array derec_protocol_process emits — see events.go for the per-event
// shape. Safe to call with a message the local channel_id has never seen
// (the core surfaces that as an error, not a panic); an expired or
// pending-fingerprint-verification message that produces no actionable
// effect decodes to a single NoOp event rather than an empty slice.
func (p *DeRecProtocol) Process(message []byte) ([]Event, error) {
	if p.closed {
		return nil, errors.New("protocol: Process: protocol is closed")
	}
	eventsJSON, err := p.instance.Process(message)
	if err != nil {
		return nil, err
	}
	return decodeEvents(eventsJSON)
}

// encodeCommunicationInfo proto-encodes info as a derecpb.CommunicationInfo,
// the wire shape derec_protocol_new_packed expects for its
// communication_info argument. A nil/empty map encodes to nil bytes,
// matching the FFI's "no entries" convention (communication_info_len == 0).
func encodeCommunicationInfo(info map[string]string) ([]byte, error) {
	if len(info) == 0 {
		return nil, nil
	}
	msg := &derecpb.CommunicationInfo{
		CommunicationInfoEntries: make([]*derecpb.CommunicationInfoKeyValue, 0, len(info)),
	}
	for k, v := range info {
		msg.CommunicationInfoEntries = append(msg.CommunicationInfoEntries, &derecpb.CommunicationInfoKeyValue{
			Key:   k,
			Value: &derecpb.CommunicationInfoKeyValue_StringValue{StringValue: v},
		})
	}
	return proto.Marshal(msg)
}
