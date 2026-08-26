// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/internal/native"
)

// UnpairAck controls whether the unpair initiator waits for the peer's
// acknowledgement before dropping local channel state. Mirrors
// derec_library::protocol::UnpairAck; values match the Rust enum and the
// unpair_ack field documented on derec_protocol_new.
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
//
// Per-flow caveats, read before enabling in production:
//
//   - Pairing covers standard and replica pairing. Replica pairing
//     remains Pending until both sides verify fingerprints, so
//     auto-accept is safe there; standard pairing becomes Paired at once.
//   - PrePair turns the initiator into a request-amplification oracle —
//     anyone knowing a HashedKeys contact's nonce can elicit a
//     key-publish. Keep off unless you control both ends of the transport.
//   - StoreShare is the helper's only admission-control point for inbound
//     shares. The protocol enforces no size, quota or rate limit of its
//     own, and maxShareSize is checked for range overlap at pairing time
//     only, never against an actual share. While false, ActionRequired
//     carries the decoded request, so the application can inspect the
//     share and Reject with StatusEnum_SIZE_LIMIT_EXCEEDED. Setting it
//     true removes that opportunity entirely: every share from every
//     paired Owner is stored unconditionally, at whatever size it
//     arrives. Keep off in any deployment with per-user storage limits.
//   - Unpair is destructive — accepting deletes the local channel record
//     before any UI confirmation.
//   - UpdateChannelInfo silently overwrites the channel record with the
//     peer's announced transport / communication info.
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
	// Timeouts configures how long the protocol waits on each thing that
	// can keep it waiting. nil, or a zero field inside it, leaves the
	// library's own default in force. See Timeouts.
	Timeouts *Timeouts
	// UnsafeHTTP accepts plaintext http:// transport endpoints. Development
	// only. Default: false, the production posture.
	//
	// With it false, plaintext is accepted only for an endpoint this device
	// configured for itself that names loopback (localhost, 127.0.0.1, ::1),
	// so a local dev server needs no configuration. With it true, plaintext
	// is accepted for any host on any path, including endpoints a peer
	// supplies — which is what makes the LAN case work (a phone against a
	// laptop), and why the name is blunt.
	//
	// This is a guardrail, not transport security: the SDK opens no sockets,
	// so nothing here stops an application sending plaintext. It governs
	// which endpoints the protocol will record, propagate and reply to.
	UnsafeHTTP bool
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

// Timeouts configures how long the protocol waits on each thing that can keep
// it waiting. A zero field means "use the library default"; the defaults live
// in the Rust library, not here.
//
// These were one knob until it became clear they answer different questions.
// InboundMessage is a security boundary — it bounds how stale a message may be
// and still be accepted, so it must tolerate transport latency and clock skew.
// The other three are liveness budgets: how long to keep hoping a peer will
// answer. Collapsing them meant tightening the replay window every time
// someone wanted rounds to settle faster.
type Timeouts struct {
	// InboundMessage is the staleness boundary for inbound envelopes: any
	// message older than this is discarded on receipt, whatever the flow.
	// This is the replay-defence window, and lowering it starts refusing
	// legitimately old messages from slow transports or skewed clocks.
	// Default: 300s.
	InboundMessage time.Duration
	// SharingRound bounds how long a publishing round waits on a peer that
	// has not answered. It is what limits how long SharingComplete can be
	// delayed by one unreachable peer. Default: 60s.
	SharingRound time.Duration
	// UnpairAck bounds the wait for an unpair acknowledgement before local
	// channel state is dropped anyway. Default: 60s.
	UnpairAck time.Duration
	// ExpiredChannels governs removal of channels still awaiting out-of-band
	// fingerprint confirmation — every replica pairing, and every NoKeys
	// pairing. Unlike the others it can be disabled, leaving the sweep to
	// the application. The budget is a human one: someone comparing a
	// fingerprint, possibly over the phone. nil leaves the default
	// (enabled, 300s) in force.
	ExpiredChannels *RemoveExpiredChannelsPolicy
}

// RemoveExpiredChannelsPolicy configures the automatic expired-channel
// sweep. Both fields are always forwarded to the library, including when
// Enabled is false — the library decides that a disabled policy ignores
// its timeout.
type RemoveExpiredChannelsPolicy struct {
	Enabled       bool
	TimeoutInSecs uint64
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
// derec_protocol_new — the first genuine C-ABI round trip a
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

	// Timeouts are forwarded verbatim; an unset field is omitted so the
	// library applies its own default rather than this wrapper choosing one.
	var nativeTimeouts *native.TimeoutsConfig
	if config.Timeouts != nil {
		secs := func(d time.Duration) *uint64 {
			if d == 0 {
				return nil
			}
			v := uint64(d.Truncate(time.Second).Seconds())
			return &v
		}
		nativeTimeouts = &native.TimeoutsConfig{
			InboundMessageSecs: secs(config.Timeouts.InboundMessage),
			SharingRoundSecs:   secs(config.Timeouts.SharingRound),
			UnpairAckSecs:      secs(config.Timeouts.UnpairAck),
		}
		if p := config.Timeouts.ExpiredChannels; p != nil {
			nativeTimeouts.ExpiredChannels = &native.RemoveExpiredChannelsPolicy{
				Enabled:       p.Enabled,
				TimeoutInSecs: p.TimeoutInSecs,
			}
		}
	}

	commInfo, err := encodeCommunicationInfo(config.CommunicationInfo)
	if err != nil {
		return nil, err
	}

	nativeCfg := native.ProtocolConfig{
		SecretID:             config.SecretID,
		OwnTransportURI:      config.OwnTransportURI,
		OwnTransportProtocol: config.OwnTransportProtocol,
		Threshold:            config.Threshold,
		KeepVersionsCount:    config.KeepVersionsCount,
		CommunicationInfo:    commInfo,
		Timeouts:             nativeTimeouts,
		UnsafeHTTP:           config.UnsafeHTTP,
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

// RemoveExpiredChannels removes Pending channels older than
// olderThanSecs, along with their pairing keys, returning the ids
// removed.
//
// Independent of Config.RemoveExpiredChannels — this sweeps at the
// threshold given even when that policy is disabled. The age comparison
// is strict, so a channel created within the current second survives
// even olderThanSecs == 0.
func (p *DeRecProtocol) RemoveExpiredChannels(olderThanSecs uint64) ([]uint64, error) {
	if p.closed {
		return nil, errors.New("protocol: RemoveExpiredChannels: protocol is closed")
	}
	raw, err := p.instance.RemoveExpiredChannels(olderThanSecs)
	if err != nil {
		return nil, err
	}
	var decimal []string
	if err := json.Unmarshal(raw, &decimal); err != nil {
		return nil, fmt.Errorf("protocol: RemoveExpiredChannels: decode ids: %w", err)
	}
	ids := make([]uint64, 0, len(decimal))
	for _, s := range decimal {
		id, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("protocol: RemoveExpiredChannels: parse id %q: %w", s, err)
		}
		ids = append(ids, id)
	}
	return ids, nil
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

// Tick advances time-driven state without an inbound message, returning the
// resulting events.
//
// Timeouts are otherwise only evaluated by Process, so a publish whose
// helpers all go quiet has nothing left to close it: the round stays open
// and no SharingComplete is ever emitted. Call this from a scheduler — a
// time.Ticker, a cron job, a queue heartbeat — at an interval shorter than
// the configured timeout.
//
// Safe to call at any time; with nothing in flight it returns no events. It
// mutates the same round state an inbound response does, so it must be
// serialized against Process for the same secret_id.
func (p *DeRecProtocol) Tick() ([]Event, error) {
	if p.closed {
		return nil, errors.New("protocol: Tick: protocol is closed")
	}
	eventsJSON, err := p.instance.Tick()
	if err != nil {
		return nil, err
	}
	return decodeEvents(eventsJSON)
}

// encodeCommunicationInfo proto-encodes info as a derecpb.CommunicationInfo,
// the wire shape derec_protocol_new expects for its
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
