// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/derecalliance/lib-derec/packages/go/derec"
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
//   - StoreShare is the helper's admission-control point for inbound
//     shares beyond what the library already checks: this device's own
//     configured minShareSize/maxShareSize is enforced against every
//     inbound share's actual length regardless of this flag, before
//     ActionRequired is ever considered — an out-of-range share is
//     refused with StatusEnum_SIZE_LIMIT_EXCEEDED either way, and this
//     flag has no say in it. While false, ActionRequired carries the
//     decoded request, which is where a tighter or per-user size limit,
//     storage quota, or any other app-specific decline belongs — call
//     Reject for that. Setting it true removes that opportunity: every
//     in-range share from every paired Owner is stored unconditionally,
//     unless the share store refuses it. Keep off in any deployment with
//     per-user storage limits tighter than this device's own configured
//     range.
//   - Unpair is destructive — accepting deletes the local channel record
//     before any UI confirmation.
//   - UpdateChannelInfo silently overwrites the channel record with the
//     peer's announced transport / communication info.
//
// In the canonical config JSON every flow is written, and a flow absent from
// a read is false, the library's default for it.
type AutoAcceptPolicy struct {
	Pairing           bool `json:"pairing"`
	PrePair           bool `json:"pre_pair"`
	StoreShare        bool `json:"store_share"`
	VerifyShare       bool `json:"verify_share"`
	Discovery         bool `json:"discovery"`
	GetShare          bool `json:"get_share"`
	Unpair            bool `json:"unpair"`
	UpdateChannelInfo bool `json:"update_channel_info"`
}

// Config configures a DeRecProtocol instance: the secret it manages plus every
// data setting, carried by the embedded DeRecProtocolConfig. Mirrors the Rust
// DeRecProtocolBuilder / dotnet DeRecProtocolBuilder field for field. The
// settings are promoted, so cfg.Threshold reads and writes
// cfg.DeRecProtocolConfig.Threshold; a composite literal names the embedded
// struct: Config{SecretID: id, DeRecProtocolConfig: DeRecProtocolConfig{...}}.
//
// Config itself is not a config-file shape: json.Marshal(cfg) writes SecretID
// beside the settings, and reading that back is refused, SecretID being an
// unknown key. Marshal and unmarshal cfg.DeRecProtocolConfig.
type Config struct {
	// SecretID identifies the single secret this protocol instance
	// manages. It is per instance, so it is not part of the
	// DeRecProtocolConfig a config file carries.
	SecretID uint64

	DeRecProtocolConfig
}

// ParameterRange declares the bounds this node advertises during pair
// negotiation, mirroring the ParameterRange proto field for field. Each bound
// is optional and defaults to 0, which the proto reads as "no constraint on
// this dimension". In the canonical config JSON every bound is written, and a
// bound may be read from a number or a decimal string.
type ParameterRange struct {
	MinShareSize                       int64 `json:"min_share_size"`
	MaxShareSize                       int64 `json:"max_share_size"`
	MinTimeBetweenVerifications        int64 `json:"min_time_between_verifications"`
	MaxTimeBetweenVerifications        int64 `json:"max_time_between_verifications"`
	MinTimeBetweenShareUpdates         int64 `json:"min_time_between_share_updates"`
	MaxTimeBetweenShareUpdates         int64 `json:"max_time_between_share_updates"`
	MinUnresponsiveDeletionTimeout     int64 `json:"min_unresponsive_deletion_timeout"`
	MaxUnresponsiveDeletionTimeout     int64 `json:"max_unresponsive_deletion_timeout"`
	MinUnresponsiveDeactivationTimeout int64 `json:"min_unresponsive_deactivation_timeout"`
	MaxUnresponsiveDeactivationTimeout int64 `json:"max_unresponsive_deactivation_timeout"`
}

// Timeouts configures how long the protocol waits on each thing that can keep
// it waiting. Every value is in whole seconds, the unit the library takes, so
// what is set here reaches it unchanged. A nil field means "use the library
// default"; the defaults live in the Rust library, not here. Every non-nil
// value, including 0, is forwarded as given and the library decides what it
// means.
//
// InboundMessageSecs is a security boundary — it bounds how stale a message
// may be and still be accepted, so it must tolerate transport latency and
// clock skew. The other three are liveness budgets: how long to keep hoping a
// peer will answer.
type Timeouts struct {
	// InboundMessageSecs is the staleness boundary for inbound envelopes:
	// any message older than this is discarded on receipt, whatever the
	// flow. This is the replay-defence window, and lowering it starts
	// refusing legitimately old messages from slow transports or skewed
	// clocks. Default: 300.
	InboundMessageSecs *uint64 `json:"inbound_message_secs,omitempty"`
	// SharingRoundSecs bounds how long a publishing round waits on a peer
	// that has not answered. It is what limits how long SharingComplete can
	// be delayed by one unreachable peer. Default: 60.
	SharingRoundSecs *uint64 `json:"sharing_round_secs,omitempty"`
	// UnpairAckSecs bounds the wait for an unpair acknowledgement before
	// local channel state is dropped anyway. Default: 60.
	UnpairAckSecs *uint64 `json:"unpair_ack_secs,omitempty"`
	// ExpiredChannels governs removal of channels still awaiting out-of-band
	// fingerprint confirmation — every replica pairing, and every NoKeys
	// pairing. Unlike the others it can be disabled, leaving the sweep to
	// the application. The budget is a human one: someone comparing a
	// fingerprint, possibly over the phone. nil leaves the default
	// (enabled, 300 seconds) in force.
	ExpiredChannels *RemoveExpiredChannelsPolicy `json:"expired_channels,omitempty"`
}

// RemoveExpiredChannelsPolicy configures the automatic expired-channel
// sweep. Both fields are always forwarded to the library, including when
// Enabled is false — the library decides that a disabled policy ignores
// its timeout.
type RemoveExpiredChannelsPolicy struct {
	Enabled       bool   `json:"enabled"`
	TimeoutInSecs uint64 `json:"timeout_in_secs"`
}

// Stores bundles the five store implementations New requires, mirroring the
// Rust DeRecStores / dotnet DeRecStores field for field.
type Stores struct {
	Channel    ChannelStore
	Share      ShareStore
	Secret     SecretStore
	UserSecret UserSecretStore
	State      StateStore
}

// DeRecProtocol is the orchestrator instance bound to a set of
// application-supplied store/transport implementations. Not safe for
// concurrent use — callers must not invoke methods on the same instance
// from more than one goroutine at a time, matching every other DeRec SDK.
type DeRecProtocol struct {
	instance *native.ProtocolInstance

	// secretID is kept so the constructed protocol can answer which secret
	// it manages, matching the other SDKs (dotnet `SecretId`, TypeScript
	// `secretId`). Without it a caller has to hold on to the Config value
	// it passed in.
	secretID uint64

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

// New constructs a DeRecProtocol bound to the given stores, transport
// implementation and config. It assembles the C callback tables backing
// each store (internal/native's buildCallbacks) and then calls
// derec_protocol_new — the first genuine C-ABI round trip a
// protocol instance makes. On error the store registration is released before
// returning; callers only need to call Close on success.
func New(
	stores Stores,
	transport Transport,
	config Config,
) (*DeRecProtocol, error) {
	channelStore := stores.Channel
	shareStore := stores.Share
	secretStore := stores.Secret
	userSecretStore := stores.UserSecret
	stateStore := stores.State

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

	configJSON, err := json.Marshal(config.DeRecProtocolConfig)
	if err != nil {
		return nil, fmt.Errorf("protocol: New: marshal config: %w", err)
	}
	instance, err := native.NewProtocolInstance(
		channelStore, secretStore, shareStore, userSecretStore, stateStore, transport,
		config.SecretID, configJSON,
	)
	if err != nil {
		return nil, err
	}

	return &DeRecProtocol{
		instance:        instance,
		secretID:        config.SecretID,
		channelStore:    channelStore,
		secretStore:     secretStore,
		shareStore:      shareStore,
		userSecretStore: userSecretStore,
		stateStore:      stateStore,
		transport:       transport,
	}, nil
}

// SecretID is the single secret this protocol instance manages, as supplied
// in Config.SecretID.
//
// Mirrors dotnet's SecretId property and the TypeScript `secretId` accessor,
// so a caller need not retain the Config it built with.
func (p *DeRecProtocol) SecretID() uint64 {
	return p.secretID
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
//
// On a replica destination, confirming is also the decision to adopt the
// group's vault: the source's publish is then installed as it arrives, with
// no further prompt. Ask the user before calling this; to decline, never
// confirm.
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
// Independent of Config.Timeouts.ExpiredChannels — this sweeps at the
// age given even when that policy is disabled. The age comparison
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

// SetOwnTransports replaces every endpoint this node advertises, in
// preference order. A node serves at most one endpoint per protocol,
// so this list is a preference order over distinct protocols and two
// entries of the same protocol are rejected.
// Only mutates local state; propagating the change to paired peers
// requires a follow-up UpdateChannelInfo flow. See Config.OwnTransports
// for each entry's Protocol meaning.
func (p *DeRecProtocol) SetOwnTransports(transports []TransportProtocolParam) error {
	if p.closed {
		return errors.New("protocol: SetOwnTransports: protocol is closed")
	}
	nativeTransports := make([]native.OwnTransport, 0, len(transports))
	for _, t := range transports {
		nativeTransports = append(nativeTransports, native.OwnTransport{URI: t.URI, Protocol: t.Protocol})
	}
	return p.instance.SetOwnTransports(nativeTransports)
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
//
// A message the core rejects returns a *ProcessError carrying the failing
// channel and the events produced before the failure.
func (p *DeRecProtocol) Process(message []byte) ([]Event, error) {
	if p.closed {
		return nil, errors.New("protocol: Process: protocol is closed")
	}
	eventsJSON, channelID, err := p.instance.Process(message)
	events, decodeErr := decodeEvents(eventsJSON)
	if err != nil {
		derecErr, ok := err.(*derec.Error)
		if !ok {
			return nil, err
		}
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, &ProcessError{ChannelID: channelID, Events: events, Err: derecErr}
	}
	return events, decodeErr
}

// ProcessError is the error Process returns when the protocol core rejects
// a message. It mirrors derec_library::protocol::ProcessError.
//
// ChannelID names the channel the failing message arrived on; nil when the
// bytes were not a decodable envelope. Events holds what the call produced
// before failing, such as sharing-round and unpair timeouts: they are not
// reported again, so handle them as a successful call's events. Err is the
// underlying *derec.Error, also reachable through errors.As.
type ProcessError struct {
	ChannelID *uint64
	Events    []Event
	Err       *derec.Error
}

// Error implements the error interface with the underlying error's message.
func (e *ProcessError) Error() string {
	return e.Err.Error()
}

// Unwrap returns the underlying *derec.Error.
func (e *ProcessError) Unwrap() error {
	return e.Err
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
