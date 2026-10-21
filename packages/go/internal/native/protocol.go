// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	"github.com/ebitengine/purego"
)

// DeRecProtocolNewResult mirrors #[repr(C)] struct DeRecProtocolNewResult
// in library/src/interop/ffi/protocol/handle/mod.rs: the standard DeRecError
// envelope plus the opaque protocol handle (null on error).
type DeRecProtocolNewResult struct {
	Error  DeRecError
	Handle uintptr
}

// DeRecProtocolFingerprintResult mirrors #[repr(C)] struct
// DeRecProtocolFingerprintResult in
// library/src/interop/ffi/protocol/handle/pairing.rs: the standard DeRecError
// envelope plus an owned C string (null on error), released via
// stringFromCString.
type DeRecProtocolFingerprintResult struct {
	Error       DeRecError
	Fingerprint *byte
}

// DeRecProtocolEventsResult mirrors #[repr(C)] struct
// DeRecProtocolEventsResult in library/src/interop/ffi/protocol/handle/flow.rs: the
// standard DeRecError envelope plus a UTF-8 JSON array of events, released
// via bytesFromBuffer.
type DeRecProtocolEventsResult struct {
	Error      DeRecError
	EventsJSON DeRecBuffer
}

// DeRecProtocolProcessResult mirrors #[repr(C)] struct
// DeRecProtocolProcessResult in library/src/interop/ffi/protocol/handle/flow.rs:
// the standard DeRecError envelope, a UTF-8 JSON array of events filled on
// success and on failure, and the channel a failing message came from when
// HasChannelID is set.
type DeRecProtocolProcessResult struct {
	Error        DeRecError
	EventsJSON   DeRecBuffer
	HasChannelID bool
	ChannelID    uint64
}

// DeRecProtocolRestoreResult mirrors #[repr(C)] struct
// DeRecProtocolRestoreResult in library/src/interop/ffi/protocol/handle/flow.rs:
// the standard DeRecError envelope, a UTF-8 JSON array of events, and a
// UTF-8 JSON array of decimal-string conflicting channel ids (non-empty
// only on CodeRestoreConflict). Both buffers are released via
// bytesFromBuffer.
type DeRecProtocolRestoreResult struct {
	Error                     DeRecError
	EventsJSON                DeRecBuffer
	ConflictingChannelIDsJSON DeRecBuffer
}

// DeRecProtocolCreateContactResult mirrors #[repr(C)] struct
// DeRecProtocolCreateContactResult in
// library/src/interop/ffi/protocol/handle/pairing.rs: the standard DeRecError
// envelope plus the prost-encoded ContactMessage bytes, released via
// bytesFromBuffer.
type DeRecProtocolCreateContactResult struct {
	Error            DeRecError
	ContactWireBytes DeRecBuffer
}

// DeRecRemovedChannelsResult mirrors #[repr(C)] struct
// DeRecRemovedChannelsResult in
// library/src/interop/ffi/protocol/handle/config.rs: the standard DeRecError
// envelope plus a UTF-8 JSON array of removed channel ids as decimal
// strings, released via bytesFromBuffer.
type DeRecRemovedChannelsResult struct {
	Error    DeRecError
	Channels DeRecBuffer
}

var (
	protocolNewOnce sync.Once
	protocolNewFn   func(
		configJSONPtr *byte, configJSONLen uintptr,
		communicationInfoPtr *byte, communicationInfoLen uintptr,
		channelCB *ChannelStoreCallbacks,
		secretCB *SecretStoreCallbacks,
		shareCB *ShareStoreCallbacks,
		userSecretCB *UserSecretStoreCallbacks,
		stateCB *StateStoreCallbacks,
		transportCB *TransportCallbacks,
	) DeRecProtocolNewResult

	protocolFreeOnce sync.Once
	protocolFreeFn   func(handle uintptr)

	protocolGetFingerprintOnce sync.Once
	protocolGetFingerprintFn   func(handle uintptr, channelID uint64) DeRecProtocolFingerprintResult

	protocolVerifyFingerprintOnce sync.Once
	protocolVerifyFingerprintFn   func(
		handle uintptr, channelID uint64,
		fingerprintPtr *byte, outMatched *uint32,
	) DeRecError

	protocolRemoveExpiredChannelsOnce sync.Once
	protocolRemoveExpiredChannelsFn   func(
		handle uintptr, olderThanSecs uint64,
	) DeRecRemovedChannelsResult

	protocolSetOwnTransportsOnce sync.Once
	protocolSetOwnTransportsFn   func(
		handle uintptr,
		jsonPtr *byte, jsonLen uintptr,
	) DeRecError

	protocolSetCommunicationInfoOnce sync.Once
	protocolSetCommunicationInfoFn   func(
		handle uintptr,
		infoJSONPtr *byte, infoJSONLen uintptr,
	) DeRecError

	protocolProcessOnce sync.Once
	protocolProcessFn   func(
		handle uintptr,
		messagePtr *byte, messageLen uintptr,
	) DeRecProtocolProcessResult

	protocolTickOnce sync.Once
	protocolTickFn   func(handle uintptr) DeRecProtocolEventsResult

	protocolStartOnce sync.Once
	protocolStartFn   func(
		handle uintptr, flowKind uint32,
		paramsJSONPtr *byte, paramsJSONLen uintptr,
	) DeRecProtocolEventsResult

	protocolAcceptOnce sync.Once
	protocolAcceptFn   func(
		handle uintptr,
		actionPtr *byte, actionLen uintptr,
	) DeRecProtocolEventsResult

	protocolRejectOnce sync.Once
	protocolRejectFn   func(
		handle uintptr,
		actionPtr *byte, actionLen uintptr,
		status int32,
		memoPtr *byte, memoLen uintptr,
	) DeRecError

	protocolRestoreOnce sync.Once
	protocolRestoreFn   func(
		handle uintptr,
		paramsJSONPtr *byte, paramsJSONLen uintptr,
	) DeRecProtocolRestoreResult

	protocolCreateContactOnce sync.Once
	protocolCreateContactFn   func(
		handle uintptr,
		hasChannelID uint32, channelID uint64,
		contactMode int32,
		hasNonce uint32, nonce uint64,
	) DeRecProtocolCreateContactResult
)

// marshalProtocolConfig renders the JSON config buffer derec_protocol_new
// reads: configJSON, the canonical DeRecProtocolConfig object package protocol
// marshals, with secret_id added beside it. secret_id is a decimal string, so
// a u64 above 2^53 survives JSON number handling.
func marshalProtocolConfig(secretID uint64, configJSON []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(configJSON, &fields); err != nil {
		return nil, fmt.Errorf("native: protocol config is not a JSON object: %w", err)
	}
	if fields == nil {
		fields = map[string]json.RawMessage{}
	}
	id, err := json.Marshal(strconv.FormatUint(secretID, 10))
	if err != nil {
		return nil, err
	}
	fields["secret_id"] = id
	return json.Marshal(fields)
}

// protocolNew wraps derec_protocol_new: the scalar configuration is
// rendered into a single JSON buffer, since purego cannot marshal
// many native arguments in a single call — it panics with "too many stack
// arguments" past a handful of parameters. The six callback structs are
// still passed as individual pointers into cb, which must outlive the
// returned handle — see builtCallbacks' doc comment.
func protocolNew(secretID uint64, configJSON []byte, cb *builtCallbacks) (uintptr, error) {
	protocolNewOnce.Do(func() {
		purego.RegisterFunc(&protocolNewFn, symbol("derec_protocol_new"))
	})

	buf, err := marshalProtocolConfig(secretID, configJSON)
	if err != nil {
		return 0, err
	}

	res := protocolNewFn(
		bytePtr(buf), uintptr(len(buf)),
		// communication_info travels in buf; the proto buffer stays empty.
		nil, 0,
		&cb.Channel, &cb.Secret, &cb.Share, &cb.UserSecret, &cb.State, &cb.Transport,
	)
	if err := errorFrom(res.Error); err != nil {
		return 0, err
	}
	if res.Handle == 0 {
		return 0, fmt.Errorf("native: derec_protocol_new returned a null handle without an error")
	}
	return res.Handle, nil
}

// ProtocolFree wraps derec_protocol_free. Safe to call with handle == 0
// (mirrors the Rust side's null-pointer tolerance).
func ProtocolFree(handle uintptr) {
	protocolFreeOnce.Do(func() {
		purego.RegisterFunc(&protocolFreeFn, symbol("derec_protocol_free"))
	})
	protocolFreeFn(handle)
}

// ProtocolInstance bundles a live derec_protocol_new handle with the
// builtCallbacks (and, transitively, the storeHandle/storeSet registration)
// that must outlive it. Exported so package protocol can hold and release
// one without depending on native's unexported storeSet/builtCallbacks
// types — see the storeSet doc comment in callbacks.go for why those stay
// unexported (avoiding the native<->protocol import cycle).
type ProtocolInstance struct {
	handle    uintptr
	callbacks *builtCallbacks
}

// NewProtocolInstance registers the six store/transport implementations
// under a fresh handle, builds their C callback tables (buildCallbacks),
// and calls derec_protocol_new. On any failure the store
// registration is released before returning, so no dangling entry survives
// a failed construction.
func NewProtocolInstance(
	channel channelStore,
	secret secretStore,
	share shareStore,
	userSecret userSecretStore,
	state stateStore,
	transport transportSender,
	secretID uint64,
	configJSON []byte,
) (*ProtocolInstance, error) {
	s := &storeSet{
		channel:    channel,
		secret:     secret,
		share:      share,
		userSecret: userSecret,
		state:      state,
		transport:  transport,
	}
	built, err := buildCallbacks(s)
	if err != nil {
		return nil, err
	}
	handle, err := protocolNew(secretID, configJSON, built)
	if err != nil {
		built.release()
		return nil, err
	}
	return &ProtocolInstance{handle: handle, callbacks: built}, nil
}

// Free releases the C protocol handle and the store registration backing
// it. Idempotent — safe to call more than once, matching
// derec_protocol_free's own null-pointer tolerance.
func (p *ProtocolInstance) Free() {
	if p.handle != 0 {
		ProtocolFree(p.handle)
		p.handle = 0
	}
	if p.callbacks != nil {
		p.callbacks.release()
		p.callbacks = nil
	}
}

// GetFingerprint wraps derec_protocol_get_fingerprint: derives the
// human-readable fingerprint for channelID's shared key. Fails if the
// channel has no shared key (not yet paired).
func (p *ProtocolInstance) GetFingerprint(channelID uint64) (string, error) {
	protocolGetFingerprintOnce.Do(func() {
		purego.RegisterFunc(&protocolGetFingerprintFn, symbol("derec_protocol_get_fingerprint"))
	})
	res := protocolGetFingerprintFn(p.handle, channelID)
	if err := errorFrom(res.Error); err != nil {
		return "", err
	}
	return stringFromCString(res.Fingerprint), nil
}

// RemoveExpiredChannels wraps derec_protocol_remove_expired_channels:
// removes Pending channels older than olderThanSecs along with their
// pairing keys, returning the UTF-8 JSON array of removed channel ids as
// decimal strings.
//
// Independent of the configured cleanup policy — it sweeps at the
// age given even when that policy is disabled. The age comparison
// is strict, so a channel created within the current second survives
// even olderThanSecs == 0.
func (p *ProtocolInstance) RemoveExpiredChannels(olderThanSecs uint64) ([]byte, error) {
	protocolRemoveExpiredChannelsOnce.Do(func() {
		purego.RegisterFunc(&protocolRemoveExpiredChannelsFn, symbol("derec_protocol_remove_expired_channels"))
	})
	res := protocolRemoveExpiredChannelsFn(p.handle, olderThanSecs)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.Channels), nil
}

// VerifyFingerprint wraps derec_protocol_verify_fingerprint: compares
// fingerprint against channelID's locally-derived one. On match, the
// channel transitions from Pending to Paired. The returned bool is only
// meaningful when err == nil — every error path (including a legitimate
// mismatch surfaced without error) already reports through err or a
// false return, matching the FFI's fail-closed out_matched convention.
func (p *ProtocolInstance) VerifyFingerprint(channelID uint64, fingerprint string) (bool, error) {
	protocolVerifyFingerprintOnce.Do(func() {
		purego.RegisterFunc(&protocolVerifyFingerprintFn, symbol("derec_protocol_verify_fingerprint"))
	})
	// NUL-terminated: the FFI reads fingerprint_ptr via CStr::from_ptr.
	fpBytes := append([]byte(fingerprint), 0)
	var matched uint32
	res := protocolVerifyFingerprintFn(p.handle, channelID, bytePtr(fpBytes), &matched)
	if err := errorFrom(res); err != nil {
		return false, err
	}
	return matched != 0, nil
}

// OwnTransport is one entry of the endpoint list SetOwnTransports takes.
// Mirrors the {uri, protocol} JSON shape the FFI uses for the
// own_transports config array.
type OwnTransport struct {
	URI      string `json:"uri"`
	Protocol int32  `json:"protocol"`
}

// SetOwnTransports wraps derec_protocol_set_own_transports: replaces every
// endpoint this node advertises, in preference order. A node serves at
// most one endpoint per protocol, so this list is a preference order over
// distinct protocols and two entries of the same protocol are rejected.
// Only mutates local state; propagating the change to paired peers requires
// a follow-up UpdateChannelInfo flow.
func (p *ProtocolInstance) SetOwnTransports(transports []OwnTransport) error {
	protocolSetOwnTransportsOnce.Do(func() {
		purego.RegisterFunc(&protocolSetOwnTransportsFn, symbol("derec_protocol_set_own_transports"))
	})
	transportsJSON, err := json.Marshal(transports)
	if err != nil {
		return fmt.Errorf("native: marshal own_transports: %w", err)
	}
	return errorFrom(protocolSetOwnTransportsFn(p.handle, bytePtr(transportsJSON), uintptr(len(transportsJSON))))
}

// SetCommunicationInfo wraps derec_protocol_set_communication_info:
// replaces this node's local communication_info map. info is JSON-encoded
// as a string->string object — the same shape New sends as the config
// JSON's "communication_info" key. A nil/empty map is sent as a
// zero-length body, matching the FFI's "no entries" convention (info_json_len == 0 short-circuits JSON
// parsing on the Rust side instead of rejecting a literal `null`).
func (p *ProtocolInstance) SetCommunicationInfo(info map[string]string) error {
	protocolSetCommunicationInfoOnce.Do(func() {
		purego.RegisterFunc(&protocolSetCommunicationInfoFn, symbol("derec_protocol_set_communication_info"))
	})
	var infoJSON []byte
	if len(info) > 0 {
		var err error
		infoJSON, err = json.Marshal(info)
		if err != nil {
			return fmt.Errorf("native: marshal communication_info: %w", err)
		}
	}
	return errorFrom(protocolSetCommunicationInfoFn(p.handle, bytePtr(infoJSON), uintptr(len(infoJSON))))
}

// Process wraps derec_protocol_process: hands an inbound wire-encoded
// DeRecMessage envelope to the protocol core and returns the resulting
// events as a UTF-8 JSON array (see
// library/src/protocol/events/wire.rs for the per-event shape). An empty
// message is a valid call — the FFI treats message_len == 0 as a
// zero-length body rather than a null-pointer error — but the protocol
// core itself may still reject it (e.g. an unrecognized channel_id),
// surfacing as a non-nil error same as any other rejected message.
//
// The events are returned on failure too: they are what the call produced
// before failing. channelID is the channel the failing message came from,
// nil on success and when the bytes were not a decodable envelope.
func (p *ProtocolInstance) Process(message []byte) (events []byte, channelID *uint64, err error) {
	protocolProcessOnce.Do(func() {
		purego.RegisterFunc(&protocolProcessFn, symbol("derec_protocol_process"))
	})
	res := protocolProcessFn(p.handle, bytePtr(message), uintptr(len(message)))
	events = bytesFromBuffer(res.EventsJSON)
	if res.HasChannelID {
		id := res.ChannelID
		channelID = &id
	}
	return events, channelID, errorFrom(res.Error)
}

// Tick wraps derec_protocol_tick: advances time-driven state without an
// inbound message, returning the resulting events as a UTF-8 JSON array in
// the same shape as Process. Safe to call at any time; with nothing in
// flight the array is empty.
func (p *ProtocolInstance) Tick() ([]byte, error) {
	protocolTickOnce.Do(func() {
		purego.RegisterFunc(&protocolTickFn, symbol("derec_protocol_tick"))
	})
	res := protocolTickFn(p.handle)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.EventsJSON), nil
}

// Start wraps derec_protocol_start: kicks off a new flow. flowKind matches
// the FlowKind constants package protocol exposes; paramsJSON is a UTF-8
// JSON blob shaped to the matching flow's params (see
// library/src/interop/ffi/protocol/flow.rs for the per-variant decoder). Returns
// the resulting events as a UTF-8 JSON array, same shape as Process.
func (p *ProtocolInstance) Start(flowKind uint32, paramsJSON []byte) ([]byte, error) {
	protocolStartOnce.Do(func() {
		purego.RegisterFunc(&protocolStartFn, symbol("derec_protocol_start"))
	})
	res := protocolStartFn(p.handle, flowKind, bytePtr(paramsJSON), uintptr(len(paramsJSON)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.EventsJSON), nil
}

// Accept wraps derec_protocol_accept: accepts a pending action carried by
// an ActionRequired event's Action field, passed verbatim. Returns the
// events produced by resuming the suspended flow.
func (p *ProtocolInstance) Accept(action []byte) ([]byte, error) {
	protocolAcceptOnce.Do(func() {
		purego.RegisterFunc(&protocolAcceptFn, symbol("derec_protocol_accept"))
	})
	res := protocolAcceptFn(p.handle, bytePtr(action), uintptr(len(action)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.EventsJSON), nil
}

// Reject wraps derec_protocol_reject: rejects a pending action carried by
// an ActionRequired event's Action field, with a status + optional memo.
// status matches derec_proto::StatusEnum.
func (p *ProtocolInstance) Reject(action []byte, status int32, memo string) error {
	protocolRejectOnce.Do(func() {
		purego.RegisterFunc(&protocolRejectFn, symbol("derec_protocol_reject"))
	})
	memoBytes := []byte(memo)
	return errorFrom(protocolRejectFn(
		p.handle,
		bytePtr(action), uintptr(len(action)),
		status,
		bytePtr(memoBytes), uintptr(len(memoBytes)),
	))
}

// Restore wraps derec_protocol_restore: rebuilds this protocol's secret_id
// namespace from a recovered Secret. paramsJSON is a UTF-8 JSON blob of the
// {version, recovered_secret} shape documented on
// derec_protocol_restore in library/src/interop/ffi/protocol/handle/flow.rs.
// Returns the resulting events as a UTF-8 JSON array. On failure the
// error is an *Error whose ConflictingChannelIDs carries the channel ids
// the library reported for a CodeRestoreConflict refusal (empty otherwise).
func (p *ProtocolInstance) Restore(paramsJSON []byte) ([]byte, error) {
	protocolRestoreOnce.Do(func() {
		purego.RegisterFunc(&protocolRestoreFn, symbol("derec_protocol_restore"))
	})
	res := protocolRestoreFn(p.handle, bytePtr(paramsJSON), uintptr(len(paramsJSON)))
	events := bytesFromBuffer(res.EventsJSON)
	conflictsJSON := bytesFromBuffer(res.ConflictingChannelIDsJSON)
	err := errorFrom(res.Error)
	if err == nil {
		return events, nil
	}
	if len(conflictsJSON) > 0 {
		var raw []string
		if jerr := json.Unmarshal(conflictsJSON, &raw); jerr != nil {
			return nil, fmt.Errorf("native: Restore: decode conflicting channel ids: %w", jerr)
		}
		ids, perr := parseUint64Strings(&raw, "conflicting_channel_ids_json")
		if perr != nil {
			return nil, perr
		}
		err.(*Error).ConflictingChannelIDs = ids
	}
	return nil, err
}

// CreateContact wraps derec_protocol_create_contact: generates an
// out-of-band ContactMessage used to bootstrap pairing. hasChannelID false
// lets the library mint a random channel id; hasNonce false lets it
// generate a fresh random nonce. Returns the prost-encoded ContactMessage
// bytes.
func (p *ProtocolInstance) CreateContact(
	hasChannelID bool, channelID uint64,
	contactMode int32,
	hasNonce bool, nonce uint64,
) ([]byte, error) {
	protocolCreateContactOnce.Do(func() {
		purego.RegisterFunc(&protocolCreateContactFn, symbol("derec_protocol_create_contact"))
	})
	res := protocolCreateContactFn(p.handle, boolToU32(hasChannelID), channelID, contactMode, boolToU32(hasNonce), nonce)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.ContactWireBytes), nil
}
