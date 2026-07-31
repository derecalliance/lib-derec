// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package pairing wraps the DeRec pairing flow: the out-of-band
// ContactMessage exchange and the pair-request/pair-response handshake that
// establishes a shared symmetric key between two parties.
//
// For ContactModeInlineKeys, the ContactMessage carries the public keys
// directly and the handshake proceeds straight to Request.Produce /
// Response.Produce / Response.Process. For ContactModeHashedKeys, the
// ContactMessage carries only a SHA-384 binding hash; the real keys are
// obtained first via the plaintext PrePair exchange (Request.ProducePrePair
// / Request.ExtractPrePair / Response.ProducePrePair /
// Response.ExtractPrePair / Response.ProcessPrePair), after which the
// caller republishes the validated keys into an INLINE_KEYS-shaped contact
// and proceeds with the normal handshake. ContactModeNoKeys is a separate
// flow, not covered here.
package pairing

import "github.com/derecalliance/lib-derec/packages/go/internal/native"

// ContactMode selects how the public encryption material is delivered in a
// ContactMessage. Mirrors org.derecalliance.derec.protobuf.ContactMode.
type ContactMode int32

const (
	// ContactModeInlineKeys inlines both the ML-KEM encapsulation key and the
	// ECIES public key in the contact. The recipient may proceed directly to
	// a pair request.
	ContactModeInlineKeys ContactMode = 0
	// ContactModeHashedKeys inlines only a SHA-384 binding hash; keys are
	// obtained via a separate PrePair exchange (not covered by this package).
	ContactModeHashedKeys ContactMode = 1
	// ContactModeNoKeys carries no key material or hash; the contact creator
	// generates keys on the fly when a PrePairRequest arrives (not covered by
	// this package).
	ContactModeNoKeys ContactMode = 2
)

// SenderKind identifies the logical role of the sender of a
// PairRequestMessage. Mirrors org.derecalliance.derec.protobuf.SenderKind.
type SenderKind int32

const (
	// SenderKindOwner marks the sender as an Owner (normal or recovery mode).
	SenderKindOwner SenderKind = 0
	// SenderKindHelper marks the sender as acting as a Helper.
	SenderKindHelper SenderKind = 1
	// SenderKindReplicaSource marks the sender as the Source side of a
	// replica pair.
	SenderKindReplicaSource SenderKind = 3
	// SenderKindReplicaDestination marks the sender as the Destination side
	// of a replica pair.
	SenderKindReplicaDestination SenderKind = 4
)

// CreatedContact is the result of creating an out-of-band ContactMessage.
type CreatedContact struct {
	// ContactWireBytes is the encoded ContactMessage to share out-of-band.
	ContactWireBytes []byte
	// SecretKeyMaterial is the opaque pairing secret key material. Persist it
	// and feed it back into Request.Extract / Response.Produce. Empty for
	// ContactModeNoKeys (no keys exist at contact-creation time).
	SecretKeyMaterial []byte
}

// ProducedRequest is a produced pairing request.
type ProducedRequest struct {
	// Envelope is the wire-encoded pairing request, ready to send over
	// transport.
	Envelope []byte
	// InitiatorContactMessage is the initiator's ContactMessage wire bytes,
	// republished here for the responder to retain and later pass to
	// Response.Process.
	InitiatorContactMessage []byte
	// SecretKeyMaterial is the requester's opaque pairing secret key
	// material. Persist it and feed it back into Response.Extract /
	// Response.Process.
	SecretKeyMaterial []byte
}

// ExtractedRequest is a decrypted pairing request: the channel it arrived on
// and the inner PairRequestMessage proto bytes, which chain into
// Response.Produce.
type ExtractedRequest struct {
	ChannelID    uint64
	RequestProto []byte
}

// ProducedResponse is a produced pairing response.
type ProducedResponse struct {
	// Envelope is the wire-encoded pairing response, ready to send over
	// transport.
	Envelope []byte
	// PeerTransportProtocol is the requester's TransportProtocol proto bytes,
	// as carried in the request.
	PeerTransportProtocol []byte
	// SharedKey is the pairing shared key derived by the responder.
	SharedKey []byte
	// ChannelID is the post-handshake rekey channel id the responder is
	// committing to. Callers MUST atomically rename their local channel
	// record from the pre-rekey id (the one passed to Response.Produce) to
	// this value as part of accepting the response.
	ChannelID uint64
}

// ExtractedResponse is a decrypted pairing response: the (pre-rekey) channel
// it arrived on and the inner PairResponseMessage proto bytes, which chain
// into Response.Process.
type ExtractedResponse struct {
	ChannelID     uint64
	ResponseProto []byte
}

// ProcessedResponse is the result of processing a pairing response.
type ProcessedResponse struct {
	// SharedKey is the pairing shared key derived by the requester.
	SharedKey []byte
	// ChannelID is the post-handshake rekey channel id, already validated
	// against the caller's own derivation. Callers MUST atomically rename
	// their local channel record from the pre-rekey id (the one in the
	// contact) to this value.
	ChannelID uint64
}

// ProducedPrePairRequest is a produced PrePair request.
type ProducedPrePairRequest struct {
	// Envelope is the wire-encoded plaintext PrePair request envelope,
	// ready to send over transport.
	Envelope []byte
}

// ExtractedPrePairRequest is a decoded PrePair request: the channel it
// arrived on and the inner PrePairRequestMessage proto bytes, which chain
// into Response.ProducePrePair.
type ExtractedPrePairRequest struct {
	ChannelID    uint64
	RequestProto []byte
}

// ProducedPrePairResponse is a produced PrePair response.
type ProducedPrePairResponse struct {
	// Envelope is the wire-encoded plaintext PrePair response envelope,
	// ready to send over transport.
	Envelope []byte
}

// ExtractedPrePairResponse is a decoded PrePair response: the channel it
// arrived on and the inner PrePairResponseMessage proto bytes, which chain
// into Response.ProcessPrePair.
type ExtractedPrePairResponse struct {
	ChannelID     uint64
	ResponseProto []byte
}

// ProcessedPrePair is the result of validating a PrePair response against
// the originating ContactMessage's binding hash.
type ProcessedPrePair struct {
	// MlkemEncapsulationKey is the contact creator's validated ML-KEM
	// encapsulation key.
	MlkemEncapsulationKey []byte
	// EciesPublicKey is the contact creator's validated ECIES public key.
	EciesPublicKey []byte
	// Nonce is echoed from the original ContactMessage.
	Nonce uint64
}

type requestAPI struct{}

// Request groups the pairing operations performed by the party that creates
// the contact and later requests pairing, mirroring the Rust
// primitives::pairing::request module.
var Request requestAPI

// CreateContact builds an out-of-band ContactMessage bootstrapping pairing on
// channelID, advertising transportProtocol (serialized TransportProtocol
// proto bytes). nonce == nil lets the library generate a fresh random nonce;
// pass a non-nil value for ContactModeNoKeys, where callers typically pick a
// small human-typable value.
func (requestAPI) CreateContact(channelID uint64, contactMode ContactMode, transportProtocol []byte, nonce *uint64) (CreatedContact, error) {
	contactWireBytes, secretKeyMaterial, err := native.CreateContact(channelID, int32(contactMode), transportProtocol, nonce)
	if err != nil {
		return CreatedContact{}, err
	}
	return CreatedContact{ContactWireBytes: contactWireBytes, SecretKeyMaterial: secretKeyMaterial}, nil
}

// Validate structurally validates proto-encoded ContactMessage bytes against
// the per-contactMode field-presence invariants.
func (requestAPI) Validate(contactMessage []byte) error {
	return native.ValidateContact(contactMessage)
}

// Produce builds a pairing request envelope addressed to the creator of
// contactMessage (the ContactWireBytes returned by CreateContact), sent by a
// party of senderKind reachable at transportProtocol. communicationInfo and
// parameterRange are optional serialized proto bytes (nil for none).
func (requestAPI) Produce(senderKind SenderKind, transportProtocol, contactMessage, communicationInfo, parameterRange []byte) (ProducedRequest, error) {
	envelope, initiatorContactMessage, secretKeyMaterial, err := native.ProducePairRequest(
		int32(senderKind), transportProtocol, contactMessage, communicationInfo, parameterRange)
	if err != nil {
		return ProducedRequest{}, err
	}
	return ProducedRequest{
		Envelope:                envelope,
		InitiatorContactMessage: initiatorContactMessage,
		SecretKeyMaterial:       secretKeyMaterial,
	}, nil
}

// Extract decrypts a pairing request envelope (the Envelope returned by
// Produce) using secretKeyMaterial (the contact creator's SecretKeyMaterial
// from CreateContact) and returns its channel id and inner proto bytes.
func (requestAPI) Extract(request, secretKeyMaterial []byte) (ExtractedRequest, error) {
	channelID, requestProto, err := native.ExtractPairRequest(request, secretKeyMaterial)
	if err != nil {
		return ExtractedRequest{}, err
	}
	return ExtractedRequest{ChannelID: channelID, RequestProto: requestProto}, nil
}

// ProducePrePair builds a plaintext PrePair request envelope addressed to
// the creator of contactMessage (a ContactModeHashedKeys or
// ContactModeNoKeys contact), sent by a scanner reachable at
// transportProtocol. Because no shared key exists yet, the envelope is
// plaintext, so transportProtocol MUST be an ephemeral endpoint.
func (requestAPI) ProducePrePair(transportProtocol, contactMessage []byte) (ProducedPrePairRequest, error) {
	envelope, err := native.ProducePrePairRequest(transportProtocol, contactMessage)
	if err != nil {
		return ProducedPrePairRequest{}, err
	}
	return ProducedPrePairRequest{Envelope: envelope}, nil
}

// ExtractPrePair decodes a plaintext PrePair request envelope (the Envelope
// returned by ProducePrePair) and returns its channel id and inner proto
// bytes.
func (requestAPI) ExtractPrePair(envelope []byte) (ExtractedPrePairRequest, error) {
	channelID, requestProto, err := native.ExtractPrePairRequest(envelope)
	if err != nil {
		return ExtractedPrePairRequest{}, err
	}
	return ExtractedPrePairRequest{ChannelID: channelID, RequestProto: requestProto}, nil
}

type responseAPI struct{}

// Response groups the pairing operations performed by the contact creator
// when responding to a pairing request, mirroring the Rust
// primitives::pairing::response module.
var Response responseAPI

// Produce builds a pairing response envelope acknowledging requestProto (the
// RequestProto returned by Request.Extract), derives the pairing shared key,
// and returns the rekeyed channel id the responder commits to.
// communicationInfo and parameterRange are optional serialized proto bytes
// (nil for none).
func (responseAPI) Produce(channelID uint64, requestProto, secretKeyMaterial, communicationInfo, parameterRange []byte) (ProducedResponse, error) {
	envelope, peerTransportProtocol, sharedKey, rekeyedChannelID, err := native.ProducePairResponse(
		channelID, requestProto, secretKeyMaterial, communicationInfo, parameterRange)
	if err != nil {
		return ProducedResponse{}, err
	}
	return ProducedResponse{
		Envelope:              envelope,
		PeerTransportProtocol: peerTransportProtocol,
		SharedKey:             sharedKey,
		ChannelID:             rekeyedChannelID,
	}, nil
}

// Extract decrypts a pairing response envelope (the Envelope returned by
// Produce) using secretKeyMaterial (the requester's SecretKeyMaterial from
// Request.Produce) and returns its (pre-rekey) channel id and inner proto
// bytes.
func (responseAPI) Extract(response, secretKeyMaterial []byte) (ExtractedResponse, error) {
	channelID, responseProto, err := native.ExtractPairResponse(response, secretKeyMaterial)
	if err != nil {
		return ExtractedResponse{}, err
	}
	return ExtractedResponse{ChannelID: channelID, ResponseProto: responseProto}, nil
}

// Process validates a pairing response (the ResponseProto returned by
// Extract) against contactMessage (the InitiatorContactMessage returned by
// Request.Produce), derives the pairing shared key, and returns the
// validated rekeyed channel id.
func (responseAPI) Process(contactMessage, responseProto, secretKeyMaterial []byte) (ProcessedResponse, error) {
	sharedKey, channelID, err := native.ProcessPairResponse(contactMessage, responseProto, secretKeyMaterial)
	if err != nil {
		return ProcessedResponse{}, err
	}
	return ProcessedResponse{SharedKey: sharedKey, ChannelID: channelID}, nil
}

// ProducePrePair builds a plaintext PrePair response envelope republishing
// the contact creator's public keys from secretKeyMaterial (the
// SecretKeyMaterial returned by Request.CreateContact), acknowledging
// requestProto (the RequestProto returned by Request.ExtractPrePair).
func (responseAPI) ProducePrePair(channelID uint64, requestProto, secretKeyMaterial []byte) (ProducedPrePairResponse, error) {
	envelope, err := native.ProducePrePairResponse(channelID, requestProto, secretKeyMaterial)
	if err != nil {
		return ProducedPrePairResponse{}, err
	}
	return ProducedPrePairResponse{Envelope: envelope}, nil
}

// ExtractPrePair decodes a plaintext PrePair response envelope (the
// Envelope returned by ProducePrePair) and returns its channel id and inner
// proto bytes.
func (responseAPI) ExtractPrePair(envelope []byte) (ExtractedPrePairResponse, error) {
	channelID, responseProto, err := native.ExtractPrePairResponse(envelope)
	if err != nil {
		return ExtractedPrePairResponse{}, err
	}
	return ExtractedPrePairResponse{ChannelID: channelID, ResponseProto: responseProto}, nil
}

// ProcessPrePair validates a PrePair response (the ResponseProto returned by
// ExtractPrePair) against contactMessage (the ContactModeHashedKeys
// ContactWireBytes returned by Request.CreateContact), recomputing its
// SHA-384 binding hash over the republished keys and returning them once
// verified, along with the echoed nonce. If the recomputed hash does not
// match contactMessage's binding hash, the returned error's Code is
// derec.CodePrepairHashMismatch — the caller MUST NOT proceed to build an
// INLINE_KEYS contact from unvalidated keys.
func (responseAPI) ProcessPrePair(contactMessage, responseProto []byte) (ProcessedPrePair, error) {
	mlkemEncapsulationKey, eciesPublicKey, nonce, err := native.ProcessPrePairResponse(contactMessage, responseProto)
	if err != nil {
		return ProcessedPrePair{}, err
	}
	return ProcessedPrePair{
		MlkemEncapsulationKey: mlkemEncapsulationKey,
		EciesPublicKey:        eciesPublicKey,
		Nonce:                 nonce,
	}, nil
}
