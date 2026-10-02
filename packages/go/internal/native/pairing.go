// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

type createContactMessageResult struct {
	Error             DeRecError
	ContactWireBytes  DeRecBuffer
	SecretKeyMaterial DeRecBuffer
}

type encodeContactMessageResult struct {
	Error     DeRecError
	WireBytes DeRecBuffer
}

type decodeContactMessageResult struct {
	Error       DeRecError
	ContactJSON DeRecBuffer
}

type producePairRequestMessageResult struct {
	Error                            DeRecError
	RequestWireBytes                 DeRecBuffer
	InitiatorContactMessageWireBytes DeRecBuffer
	SecretKeyMaterial                DeRecBuffer
}

type extractPairRequestResult struct {
	Error             DeRecError
	ChannelID         uint64
	RequestProtoBytes DeRecBuffer
}

type producePairResponseMessageResult struct {
	Error             DeRecError
	ResponseWireBytes DeRecBuffer
	PeerTransports    DeRecBuffer
	SharedKey         DeRecBuffer
	ChannelID         uint64
}

type extractPairResponseResult struct {
	Error              DeRecError
	ChannelID          uint64
	ResponseProtoBytes DeRecBuffer
}

type processPairResponseMessageResult struct {
	Error     DeRecError
	SharedKey DeRecBuffer
	ChannelID uint64
}

type producePrePairRequestMessageResult struct {
	Error             DeRecError
	EnvelopeWireBytes DeRecBuffer
}

type extractPrePairRequestResult struct {
	Error             DeRecError
	ChannelID         uint64
	RequestProtoBytes DeRecBuffer
}

type producePrePairResponseMessageResult struct {
	Error             DeRecError
	EnvelopeWireBytes DeRecBuffer
}

type extractPrePairResponseResult struct {
	Error              DeRecError
	ChannelID          uint64
	ResponseProtoBytes DeRecBuffer
}

type producePrePairNoKeysResponseMessageResult struct {
	Error             DeRecError
	EnvelopeWireBytes DeRecBuffer
	SecretKeyMaterial DeRecBuffer
}

type pairingFingerprintResult struct {
	Error       DeRecError
	Fingerprint *byte
}

type processPrePairResponseMessageResult struct {
	Error                 DeRecError
	MlkemEncapsulationKey DeRecBuffer
	EciesPublicKey        DeRecBuffer
	Nonce                 uint64
}

var (
	createContactOnce sync.Once
	createContactFn   func(channelID uint64, contactMode int32,
		transportProtocol *byte, transportProtocolLen uintptr,
		hasNonce uint32, nonce uint64) createContactMessageResult

	encodeContactOnce sync.Once
	encodeContactFn   func(contactJSON *byte, contactJSONLen uintptr) encodeContactMessageResult

	decodeContactOnce sync.Once
	decodeContactFn   func(contactWire *byte, contactWireLen uintptr) decodeContactMessageResult

	producePairRequestOnce sync.Once
	producePairRequestFn   func(senderKind int32,
		transportProtocol *byte, transportProtocolLen uintptr,
		contactMessage *byte, contactMessageLen uintptr,
		communicationInfo *byte, communicationInfoLen uintptr,
		parameterRange *byte, parameterRangeLen uintptr) producePairRequestMessageResult

	extractPairReqOnce sync.Once
	extractPairReqFn   func(request *byte, requestLen uintptr,
		secretKeyMaterial *byte, secretKeyMaterialLen uintptr,
		parameterRange *byte, parameterRangeLen uintptr) extractPairRequestResult

	producePairResponseOnce sync.Once
	producePairResponseFn   func(channelID uint64,
		requestProto *byte, requestProtoLen uintptr,
		secretKeyMaterial *byte, secretKeyMaterialLen uintptr,
		communicationInfo *byte, communicationInfoLen uintptr,
		parameterRange *byte, parameterRangeLen uintptr,
		unsafeConnection uint32) producePairResponseMessageResult

	extractPairRespOnce sync.Once
	extractPairRespFn   func(response *byte, responseLen uintptr,
		secretKeyMaterial *byte, secretKeyMaterialLen uintptr) extractPairResponseResult

	processPairRespOnce sync.Once
	processPairRespFn   func(contactMessage *byte, contactMessageLen uintptr,
		responseProto *byte, responseProtoLen uintptr,
		secretKeyMaterial *byte, secretKeyMaterialLen uintptr,
		parameterRange *byte, parameterRangeLen uintptr) processPairResponseMessageResult

	producePrePairRequestOnce sync.Once
	producePrePairRequestFn   func(transportProtocol *byte, transportProtocolLen uintptr,
		contactMessage *byte, contactMessageLen uintptr) producePrePairRequestMessageResult

	extractPrePairReqOnce sync.Once
	extractPrePairReqFn   func(envelope *byte, envelopeLen uintptr) extractPrePairRequestResult

	producePrePairResponseOnce sync.Once
	producePrePairResponseFn   func(channelID uint64,
		requestProto *byte, requestProtoLen uintptr,
		secretKeyMaterial *byte, secretKeyMaterialLen uintptr) producePrePairResponseMessageResult

	extractPrePairRespOnce sync.Once
	extractPrePairRespFn   func(envelope *byte, envelopeLen uintptr) extractPrePairResponseResult

	processPrePairRespOnce sync.Once
	processPrePairRespFn   func(contactMessage *byte, contactMessageLen uintptr,
		responseProto *byte, responseProtoLen uintptr) processPrePairResponseMessageResult

	producePrePairNoKeysResponseOnce sync.Once
	producePrePairNoKeysResponseFn   func(channelID uint64,
		requestProto *byte, requestProtoLen uintptr) producePrePairNoKeysResponseMessageResult

	processPrePairNoKeysRespOnce sync.Once
	processPrePairNoKeysRespFn   func(contactMessage *byte, contactMessageLen uintptr,
		responseProto *byte, responseProtoLen uintptr) processPrePairResponseMessageResult

	pairingFingerprintOnce sync.Once
	pairingFingerprintFn   func(sharedKey *byte, sharedKeyLen uintptr) pairingFingerprintResult
)

// CreateContact builds an out-of-band ContactMessage bootstrapping pairing on
// channelID, advertising transportProtocols: a length-delimited sequence of
// serialized TransportProtocol protos (each entry preceded by its varint byte
// length), in this application's preference order. nonce == nil lets the
// library generate a fresh random nonce. Returns the encoded ContactMessage
// wire bytes and (for INLINE_KEYS / HASHED_KEYS contactMode) the opaque
// pairing secret key material to feed back into ExtractPairRequest /
// ProducePairResponse.
func CreateContact(channelID uint64, contactMode int32, transportProtocol []byte, nonce *uint64) ([]byte, []byte, error) {
	createContactOnce.Do(func() {
		purego.RegisterFunc(&createContactFn, symbol("create_contact_message"))
	})
	hasNonce := uint32(0)
	nonceValue := uint64(0)
	if nonce != nil {
		hasNonce = 1
		nonceValue = *nonce
	}
	res := createContactFn(channelID, contactMode,
		bytePtr(transportProtocol), uintptr(len(transportProtocol)),
		hasNonce, nonceValue)
	if err := errorFrom(res.Error); err != nil {
		return nil, nil, err
	}
	return bytesFromBuffer(res.ContactWireBytes), bytesFromBuffer(res.SecretKeyMaterial), nil
}

// EncodeContact turns contactJSON, the JSON shape encode_contact_message
// reads, into the ContactMessage wire bytes delivered out of band. The core
// refuses a contact that violates the invariants of its contact mode.
func EncodeContact(contactJSON []byte) ([]byte, error) {
	encodeContactOnce.Do(func() {
		purego.RegisterFunc(&encodeContactFn, symbol("encode_contact_message"))
	})
	res := encodeContactFn(bytePtr(contactJSON), uintptr(len(contactJSON)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.WireBytes), nil
}

// DecodeContact turns out-of-band ContactMessage wire bytes into the JSON
// shape decode_contact_message writes. The core refuses bytes that are not a
// contact, or a contact that violates the invariants of its contact mode.
func DecodeContact(contactWire []byte) ([]byte, error) {
	decodeContactOnce.Do(func() {
		purego.RegisterFunc(&decodeContactFn, symbol("decode_contact_message"))
	})
	res := decodeContactFn(bytePtr(contactWire), uintptr(len(contactWire)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.ContactJSON), nil
}

// ProducePairRequest builds a pairing request envelope addressed to the
// creator of contactMessage, sent by a party of senderKind reachable at
// transportProtocol. communicationInfo and parameterRange are optional
// serialized proto bytes (nil for none). Returns the wire-encoded request
// envelope, the republished initiator ContactMessage wire bytes, and the
// opaque pairing secret key material to feed back into ExtractPairResponse /
// ProcessPairResponse.
func ProducePairRequest(senderKind int32, transportProtocol, contactMessage, communicationInfo, parameterRange []byte) ([]byte, []byte, []byte, error) {
	producePairRequestOnce.Do(func() {
		purego.RegisterFunc(&producePairRequestFn, symbol("produce_pair_request_message"))
	})
	res := producePairRequestFn(senderKind,
		bytePtr(transportProtocol), uintptr(len(transportProtocol)),
		bytePtr(contactMessage), uintptr(len(contactMessage)),
		bytePtr(communicationInfo), uintptr(len(communicationInfo)),
		bytePtr(parameterRange), uintptr(len(parameterRange)))
	if err := errorFrom(res.Error); err != nil {
		return nil, nil, nil, err
	}
	return bytesFromBuffer(res.RequestWireBytes),
		bytesFromBuffer(res.InitiatorContactMessageWireBytes),
		bytesFromBuffer(res.SecretKeyMaterial),
		nil
}

// ExtractPairRequest decrypts a pairing request envelope using
// secretKeyMaterial (the contact creator's opaque pairing secret key
// material) and returns its channel id and inner PairRequestMessage proto
// bytes for chaining into ProducePairResponse. parameterRange is the
// optional serialized ParameterRange this side accepts (nil for none); a
// request whose range does not overlap it is refused.
func ExtractPairRequest(request, secretKeyMaterial, parameterRange []byte) (uint64, []byte, error) {
	extractPairReqOnce.Do(func() {
		purego.RegisterFunc(&extractPairReqFn, symbol("extract_pair_request"))
	})
	res := extractPairReqFn(bytePtr(request), uintptr(len(request)),
		bytePtr(secretKeyMaterial), uintptr(len(secretKeyMaterial)),
		bytePtr(parameterRange), uintptr(len(parameterRange)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.RequestProtoBytes), nil
}

// ProducePairResponse builds a pairing response envelope acknowledging
// requestProto (the RequestProtoBytes returned by ExtractPairRequest),
// derives the pairing shared key, and returns the rekeyed channel id the
// responder commits to. communicationInfo and parameterRange are optional
// serialized proto bytes (nil for none).
//
// The returned endpoints are every endpoint the requester advertised, in its
// own order, filtered to those the library will record. unsafeConnection
// accepts plaintext peer endpoints (http://, grpc://) and is development-only.
func ProducePairResponse(channelID uint64, requestProto, secretKeyMaterial, communicationInfo, parameterRange []byte, unsafeConnection bool) ([]byte, []Endpoint, []byte, uint64, error) {
	producePairResponseOnce.Do(func() {
		purego.RegisterFunc(&producePairResponseFn, symbol("produce_pair_response_message"))
	})
	res := producePairResponseFn(channelID,
		bytePtr(requestProto), uintptr(len(requestProto)),
		bytePtr(secretKeyMaterial), uintptr(len(secretKeyMaterial)),
		bytePtr(communicationInfo), uintptr(len(communicationInfo)),
		bytePtr(parameterRange), uintptr(len(parameterRange)),
		boolToUint32(unsafeConnection))
	if err := errorFrom(res.Error); err != nil {
		return nil, nil, nil, 0, err
	}
	// Drain every out buffer before the decode can return early; each one is
	// heap-owned by the library and freed as it is copied.
	envelope := bytesFromBuffer(res.ResponseWireBytes)
	framed := bytesFromBuffer(res.PeerTransports)
	sharedKey := bytesFromBuffer(res.SharedKey)

	peerTransports, err := decodeEndpointList(framed)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	return envelope, peerTransports, sharedKey, res.ChannelID, nil
}

// ExtractPairResponse decrypts a pairing response envelope using
// secretKeyMaterial (the initiator's opaque pairing secret key material) and
// returns its (pre-rekey) channel id and inner PairResponseMessage proto
// bytes for chaining into ProcessPairResponse.
func ExtractPairResponse(response, secretKeyMaterial []byte) (uint64, []byte, error) {
	extractPairRespOnce.Do(func() {
		purego.RegisterFunc(&extractPairRespFn, symbol("extract_pair_response"))
	})
	res := extractPairRespFn(bytePtr(response), uintptr(len(response)),
		bytePtr(secretKeyMaterial), uintptr(len(secretKeyMaterial)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.ResponseProtoBytes), nil
}

// ProcessPairResponse validates a pairing response (the ResponseProtoBytes
// returned by ExtractPairResponse) against contactMessage (the initiator
// ContactMessage wire bytes returned by ProducePairRequest), derives the
// pairing shared key, and returns the validated rekeyed channel id.
// parameterRange is the optional serialized ParameterRange this side accepts
// (nil for none); a response whose range does not overlap it is refused
// before any key is derived.
func ProcessPairResponse(contactMessage, responseProto, secretKeyMaterial, parameterRange []byte) ([]byte, uint64, error) {
	processPairRespOnce.Do(func() {
		purego.RegisterFunc(&processPairRespFn, symbol("process_pair_response_message"))
	})
	res := processPairRespFn(bytePtr(contactMessage), uintptr(len(contactMessage)),
		bytePtr(responseProto), uintptr(len(responseProto)),
		bytePtr(secretKeyMaterial), uintptr(len(secretKeyMaterial)),
		bytePtr(parameterRange), uintptr(len(parameterRange)))
	if err := errorFrom(res.Error); err != nil {
		return nil, 0, err
	}
	return bytesFromBuffer(res.SharedKey), res.ChannelID, nil
}

// ProducePrePairRequest builds a plaintext PrePair request envelope
// addressed to the creator of contactMessage (a HASHED_KEYS or NO_KEYS
// contact), sent by a scanner reachable at transportProtocols: a
// length-delimited sequence of serialized TransportProtocol protos (each
// entry preceded by its varint byte length), in the scanner's own
// preference order. Because the envelope carries no shared key yet, these
// MUST be ephemeral endpoints.
func ProducePrePairRequest(transportProtocols, contactMessage []byte) ([]byte, error) {
	producePrePairRequestOnce.Do(func() {
		purego.RegisterFunc(&producePrePairRequestFn, symbol("produce_pre_pair_request_message"))
	})
	res := producePrePairRequestFn(
		bytePtr(transportProtocols), uintptr(len(transportProtocols)),
		bytePtr(contactMessage), uintptr(len(contactMessage)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.EnvelopeWireBytes), nil
}

// ExtractPrePairRequest decodes a plaintext PrePair request envelope (the
// envelope returned by ProducePrePairRequest) and returns its channel id
// and inner PrePairRequestMessage proto bytes for chaining into
// ProducePrePairResponse.
func ExtractPrePairRequest(envelope []byte) (uint64, []byte, error) {
	extractPrePairReqOnce.Do(func() {
		purego.RegisterFunc(&extractPrePairReqFn, symbol("extract_pre_pair_request"))
	})
	res := extractPrePairReqFn(bytePtr(envelope), uintptr(len(envelope)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.RequestProtoBytes), nil
}

// ProducePrePairResponse builds a plaintext PrePair response envelope
// republishing the contact creator's public keys carried in
// secretKeyMaterial, acknowledging requestProto (the RequestProtoBytes
// returned by ExtractPrePairRequest).
func ProducePrePairResponse(channelID uint64, requestProto, secretKeyMaterial []byte) ([]byte, error) {
	producePrePairResponseOnce.Do(func() {
		purego.RegisterFunc(&producePrePairResponseFn, symbol("produce_pre_pair_response_message"))
	})
	res := producePrePairResponseFn(channelID,
		bytePtr(requestProto), uintptr(len(requestProto)),
		bytePtr(secretKeyMaterial), uintptr(len(secretKeyMaterial)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.EnvelopeWireBytes), nil
}

// ExtractPrePairResponse decodes a plaintext PrePair response envelope (the
// envelope returned by ProducePrePairResponse) and returns its channel id
// and inner PrePairResponseMessage proto bytes for chaining into
// ProcessPrePairResponse.
func ExtractPrePairResponse(envelope []byte) (uint64, []byte, error) {
	extractPrePairRespOnce.Do(func() {
		purego.RegisterFunc(&extractPrePairRespFn, symbol("extract_pre_pair_response"))
	})
	res := extractPrePairRespFn(bytePtr(envelope), uintptr(len(envelope)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.ResponseProtoBytes), nil
}

// ProcessPrePairResponse validates a PrePair response (the
// ResponseProtoBytes returned by ExtractPrePairResponse) against
// contactMessage's SHA-384 binding hash, returning the validated ML-KEM
// encapsulation key, ECIES public key, and echoed nonce. On a binding-hash
// mismatch the returned error's Code is derec.CodePrepairHashMismatch.
func ProcessPrePairResponse(contactMessage, responseProto []byte) (mlkemEncapsulationKey, eciesPublicKey []byte, nonce uint64, err error) {
	processPrePairRespOnce.Do(func() {
		purego.RegisterFunc(&processPrePairRespFn, symbol("process_pre_pair_response_message"))
	})
	res := processPrePairRespFn(
		bytePtr(contactMessage), uintptr(len(contactMessage)),
		bytePtr(responseProto), uintptr(len(responseProto)))
	if e := errorFrom(res.Error); e != nil {
		return nil, nil, 0, e
	}
	return bytesFromBuffer(res.MlkemEncapsulationKey), bytesFromBuffer(res.EciesPublicKey), res.Nonce, nil
}

// ProducePrePairNoKeysResponse is the contact-creator side of a NO_KEYS
// pairing: it generates fresh key material and builds a plaintext PrePair
// response envelope publishing its public keys, acknowledging requestProto
// (the RequestProtoBytes returned by ExtractPrePairRequest). The caller MUST
// first match the request's nonce against the contact it issued, and MUST
// persist the returned secret key material: the pair request that follows
// is encrypted to it.
func ProducePrePairNoKeysResponse(channelID uint64, requestProto []byte) (envelope, secretKeyMaterial []byte, err error) {
	producePrePairNoKeysResponseOnce.Do(func() {
		purego.RegisterFunc(&producePrePairNoKeysResponseFn, symbol("produce_pre_pair_no_keys_response_message"))
	})
	res := producePrePairNoKeysResponseFn(channelID,
		bytePtr(requestProto), uintptr(len(requestProto)))
	if e := errorFrom(res.Error); e != nil {
		return nil, nil, e
	}
	return bytesFromBuffer(res.EnvelopeWireBytes), bytesFromBuffer(res.SecretKeyMaterial), nil
}

// ProcessPrePairNoKeysResponse is the scanner side of a NO_KEYS pairing: it
// accepts the public keys in responseProto (the ResponseProtoBytes returned
// by ExtractPrePairResponse) for contactMessage, returning them with the
// echoed nonce. Nothing binds these keys to the contact, so the resulting
// pairing MUST be confirmed by comparing PairingFingerprint out of band.
func ProcessPrePairNoKeysResponse(contactMessage, responseProto []byte) (mlkemEncapsulationKey, eciesPublicKey []byte, nonce uint64, err error) {
	processPrePairNoKeysRespOnce.Do(func() {
		purego.RegisterFunc(&processPrePairNoKeysRespFn, symbol("process_pre_pair_no_keys_response_message"))
	})
	res := processPrePairNoKeysRespFn(
		bytePtr(contactMessage), uintptr(len(contactMessage)),
		bytePtr(responseProto), uintptr(len(responseProto)))
	if e := errorFrom(res.Error); e != nil {
		return nil, nil, 0, e
	}
	return bytesFromBuffer(res.MlkemEncapsulationKey), bytesFromBuffer(res.EciesPublicKey), res.Nonce, nil
}

// PairingFingerprint returns the human-readable fingerprint of a pairing's
// sharedKey, the same value the protocol's GetFingerprint derives.
func PairingFingerprint(sharedKey []byte) (string, error) {
	pairingFingerprintOnce.Do(func() {
		purego.RegisterFunc(&pairingFingerprintFn, symbol("pairing_fingerprint"))
	})
	res := pairingFingerprintFn(bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return "", err
	}
	return stringFromCString(res.Fingerprint), nil
}

// boolToUint32 maps a Go bool onto the C ABI's uint32 flag convention.
func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
