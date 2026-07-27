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
// in library/src/ffi/protocol/handle/mod.rs: the standard DeRecError
// envelope plus the opaque protocol handle (null on error).
type DeRecProtocolNewResult struct {
	Error  DeRecError
	Handle uintptr
}

// DeRecProtocolFingerprintResult mirrors #[repr(C)] struct
// DeRecProtocolFingerprintResult in
// library/src/ffi/protocol/handle/pairing.rs: the standard DeRecError
// envelope plus an owned C string (null on error), released via
// stringFromCString.
type DeRecProtocolFingerprintResult struct {
	Error       DeRecError
	Fingerprint *byte
}

// DeRecProtocolEventsResult mirrors #[repr(C)] struct
// DeRecProtocolEventsResult in library/src/ffi/protocol/handle/flow.rs: the
// standard DeRecError envelope plus a UTF-8 JSON array of events, released
// via bytesFromBuffer.
type DeRecProtocolEventsResult struct {
	Error      DeRecError
	EventsJSON DeRecBuffer
}

// DeRecProtocolCreateContactResult mirrors #[repr(C)] struct
// DeRecProtocolCreateContactResult in
// library/src/ffi/protocol/handle/pairing.rs: the standard DeRecError
// envelope plus the prost-encoded ContactMessage bytes, released via
// bytesFromBuffer.
type DeRecProtocolCreateContactResult struct {
	Error            DeRecError
	ContactWireBytes DeRecBuffer
}

// AutoAcceptPolicy is the per-flow auto-accept toggle set carried by the
// packed JSON config's "auto_accept" object, field for field matching
// PackedAutoAcceptPolicy in library/src/ffi/protocol/handle/mod.rs
// (booleans, since JSON has a native boolean type — unlike the deprecated
// 21-arg derec_protocol_new, which used u32-as-bool for a flat C struct
// passed by value).
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

// ProtocolConfig carries every derec_protocol_new_packed argument beyond
// the six callback structs and the communication_info proto buffer, in
// idiomatic Go form. protocolNew renders it into the packed JSON config
// buffer the FFI expects — package protocol is responsible for converting
// its own idiomatic Config into this shape.
type ProtocolConfig struct {
	SecretID uint64

	OwnTransportURI      string
	OwnTransportProtocol int32

	Threshold         uint32
	KeepVersionsCount uint32

	// CommunicationInfo is a proto-encoded derecpb.CommunicationInfo, or
	// nil for none. Stays a separate buffer argument alongside the JSON
	// config — same wire convention as the deprecated derec_protocol_new.
	CommunicationInfo []byte

	TimeoutInSecs        uint32
	AutoRespondOnFailure bool
	// UnpairAck: 0 = Required, 1 = NotRequired.
	UnpairAck   int32
	AutoReplyTo bool
	AutoAccept  AutoAcceptPolicy

	// ReplicaID configures this node's local replica_id. nil leaves it
	// unset (omitted from the JSON config, matching the "absent or null
	// means no replica id" convention documented on PackedProtocolConfig).
	ReplicaID *uint64
}

// packedProtocolConfig is the JSON shape derec_protocol_new_packed expects,
// field-for-field matching PackedProtocolConfig in
// library/src/ffi/protocol/handle/mod.rs. secret_id/replica_id are decimal
// strings rather than JSON numbers: u64 values above 2^53 lose precision
// once round-tripped through JSON's float64-backed number type in common
// encoders, including Go's encoding/json.
type packedProtocolConfig struct {
	SecretID             string           `json:"secret_id"`
	OwnTransportURI      string           `json:"own_transport_uri"`
	OwnTransportProtocol int32            `json:"own_transport_protocol"`
	Threshold            uint32           `json:"threshold"`
	KeepVersionsCount    uint32           `json:"keep_versions_count"`
	TimeoutInSecs        uint32           `json:"timeout_in_secs"`
	AutoRespondOnFailure bool             `json:"auto_respond_on_failure"`
	UnpairAck            int32            `json:"unpair_ack"`
	AutoReplyTo          bool             `json:"auto_reply_to"`
	AutoAccept           AutoAcceptPolicy `json:"auto_accept"`
	ReplicaID            *string          `json:"replica_id,omitempty"`
}

var (
	protocolNewPackedOnce sync.Once
	protocolNewPackedFn   func(
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

	protocolSetOwnTransportOnce sync.Once
	protocolSetOwnTransportFn   func(
		handle uintptr,
		uriPtr *byte, uriLen uintptr,
		protocolNum int32,
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
	) DeRecProtocolEventsResult

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
	) DeRecProtocolEventsResult

	protocolCreateContactOnce sync.Once
	protocolCreateContactFn   func(
		handle uintptr,
		hasChannelID uint32, channelID uint64,
		contactMode int32,
		hasNonce uint32, nonce uint64,
	) DeRecProtocolCreateContactResult
)

// protocolNew wraps derec_protocol_new_packed: the scalar configuration in
// cfg is rendered into a single JSON buffer (the packed entry point's only
// alternative to the deprecated derec_protocol_new's 21 flat arguments,
// which purego cannot call — it panics with "too many stack arguments"
// past a handful of parameters). The six callback structs are still passed
// as individual pointers into cb, which must outlive the returned handle —
// see builtCallbacks' doc comment.
func protocolNew(cfg ProtocolConfig, cb *builtCallbacks) (uintptr, error) {
	protocolNewPackedOnce.Do(func() {
		purego.RegisterFunc(&protocolNewPackedFn, symbol("derec_protocol_new_packed"))
	})

	packed := packedProtocolConfig{
		SecretID:             strconv.FormatUint(cfg.SecretID, 10),
		OwnTransportURI:      cfg.OwnTransportURI,
		OwnTransportProtocol: cfg.OwnTransportProtocol,
		Threshold:            cfg.Threshold,
		KeepVersionsCount:    cfg.KeepVersionsCount,
		TimeoutInSecs:        cfg.TimeoutInSecs,
		AutoRespondOnFailure: cfg.AutoRespondOnFailure,
		UnpairAck:            cfg.UnpairAck,
		AutoReplyTo:          cfg.AutoReplyTo,
		AutoAccept:           cfg.AutoAccept,
	}
	if cfg.ReplicaID != nil {
		id := strconv.FormatUint(*cfg.ReplicaID, 10)
		packed.ReplicaID = &id
	}

	configJSON, err := json.Marshal(packed)
	if err != nil {
		return 0, fmt.Errorf("native: marshal packed protocol config: %w", err)
	}

	res := protocolNewPackedFn(
		bytePtr(configJSON), uintptr(len(configJSON)),
		bytePtr(cfg.CommunicationInfo), uintptr(len(cfg.CommunicationInfo)),
		&cb.Channel, &cb.Secret, &cb.Share, &cb.UserSecret, &cb.State, &cb.Transport,
	)
	if err := errorFrom(res.Error); err != nil {
		return 0, err
	}
	if res.Handle == 0 {
		return 0, fmt.Errorf("native: derec_protocol_new_packed returned a null handle without an error")
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

// ProtocolInstance bundles a live derec_protocol_new_packed handle with the
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
// and calls derec_protocol_new_packed. On any failure the store
// registration is released before returning, so no dangling entry survives
// a failed construction.
func NewProtocolInstance(
	channel channelStore,
	secret secretStore,
	share shareStore,
	userSecret userSecretStore,
	state stateStore,
	transport transportSender,
	cfg ProtocolConfig,
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
	handle, err := protocolNew(cfg, built)
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

// SetOwnTransport wraps derec_protocol_set_own_transport: replaces this
// node's local transport endpoint. Only mutates local state — propagating
// the change to paired peers requires a follow-up UpdateChannelInfo flow.
func (p *ProtocolInstance) SetOwnTransport(uri string, protocolNum int32) error {
	protocolSetOwnTransportOnce.Do(func() {
		purego.RegisterFunc(&protocolSetOwnTransportFn, symbol("derec_protocol_set_own_transport"))
	})
	uriBytes := []byte(uri)
	return errorFrom(protocolSetOwnTransportFn(p.handle, bytePtr(uriBytes), uintptr(len(uriBytes)), protocolNum))
}

// SetCommunicationInfo wraps derec_protocol_set_communication_info:
// replaces this node's local communication_info map. info is JSON-encoded
// as a string->string object — the same wire shape the FFI uses elsewhere
// for this map, distinct from New's proto-encoded CommunicationInfo
// buffer. A nil/empty map is sent as a zero-length body, matching the
// FFI's "no entries" convention (info_json_len == 0 short-circuits JSON
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
func (p *ProtocolInstance) Process(message []byte) ([]byte, error) {
	protocolProcessOnce.Do(func() {
		purego.RegisterFunc(&protocolProcessFn, symbol("derec_protocol_process"))
	})
	res := protocolProcessFn(p.handle, bytePtr(message), uintptr(len(message)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.EventsJSON), nil
}

// Start wraps derec_protocol_start: kicks off a new flow. flowKind matches
// the FlowKind constants package protocol exposes; paramsJSON is a UTF-8
// JSON blob shaped to the matching flow's params (see
// library/src/ffi/protocol/flow.rs for the per-variant decoder). Returns
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
// derec_protocol_restore in library/src/ffi/protocol/handle/flow.rs.
// Returns the resulting events as a UTF-8 JSON array.
func (p *ProtocolInstance) Restore(paramsJSON []byte) ([]byte, error) {
	protocolRestoreOnce.Do(func() {
		purego.RegisterFunc(&protocolRestoreFn, symbol("derec_protocol_restore"))
	})
	res := protocolRestoreFn(p.handle, bytePtr(paramsJSON), uintptr(len(paramsJSON)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.EventsJSON), nil
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
