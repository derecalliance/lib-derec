// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package derecpb

// AdvertisedEndpoints reports the endpoints a peer-supplied message
// advertises, in the peer's own order.
//
// It yields SupportedTransports when that list is non-empty, and otherwise the
// singular TransportProtocol — which is how every implementation predating the
// offer list advertises, and the reason this is a function rather than a field
// read.
//
// Reading GetTransportProtocol directly is a bug. That field's meaning narrowed
// in 0.0.3 from "the endpoint" to "one entry of a list, and possibly absent":
// a peer that has moved past it advertises only SupportedTransports, so a
// reader that was correct before 0.0.3 now sees nil and treats a reachable peer
// as unreachable. The field is removed at 0.0.5.
//
// This reports what was advertised, not what is acceptable — nothing here is
// validated, and the protocol still applies its own transport policy to
// whatever it records.
//
// Implemented by ContactMessage, PairRequestMessage, PrePairRequestMessage and
// UpdateChannelInfoRequestMessage, which are the four messages carrying the
// field pair.
func AdvertisedEndpoints(m EndpointAdvertiser) []*TransportProtocol {
	if m == nil {
		return nil
	}
	if offers := m.GetSupportedTransports(); len(offers) > 0 {
		return offers
	}
	if legacy := m.GetTransportProtocol(); legacy != nil {
		return []*TransportProtocol{legacy}
	}
	return nil
}

// EndpointAdvertiser is any peer-supplied message that advertises where its
// sender can be reached. The generated accessors on the four carrying message
// types satisfy it without further declaration.
type EndpointAdvertiser interface {
	GetSupportedTransports() []*TransportProtocol
	GetTransportProtocol() *TransportProtocol
}

// ReplyToEndpoints reports the endpoints a request asked its response to be
// delivered to, in the requester's own order.
//
// The same offer-list-else-legacy-field rule as AdvertisedEndpoints, applied to
// the ReplyTo / ReplyToTransports pair. The two are separate functions because
// the fields mean different things: what AdvertisedEndpoints reports is where a
// peer can be reached in general and is recorded on the channel, while this
// overrides that for a single exchange and is deliberately not persisted.
//
// Reading GetReplyTo directly is a bug for the same reason it is on
// GetTransportProtocol: that field's meaning narrowed in 0.0.3 from "the
// endpoint" to "one entry of a list, and possibly absent". It is removed at
// 0.0.5.
//
// An empty result means the requester named no endpoint, which tells the
// responder to answer on the endpoints recorded for the channel rather than
// that the requester is unreachable.
//
// Implemented by StoreShareRequestMessage, VerifyShareRequestMessage,
// GetSecretIdsVersionsRequestMessage, GetShareRequestMessage and
// UnpairRequestMessage, the five requests carrying the field pair.
func ReplyToEndpoints(m ReplyToAdvertiser) []*TransportProtocol {
	if m == nil {
		return nil
	}
	if offers := m.GetReplyToTransports(); len(offers) > 0 {
		return offers
	}
	if legacy := m.GetReplyTo(); legacy != nil {
		return []*TransportProtocol{legacy}
	}
	return nil
}

// ReplyToAdvertiser is any request that names where its response should go.
type ReplyToAdvertiser interface {
	GetReplyToTransports() []*TransportProtocol
	GetReplyTo() *TransportProtocol
}
