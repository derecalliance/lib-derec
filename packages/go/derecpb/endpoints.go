// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package derecpb

// AdvertisedEndpoints reports the endpoints a peer-supplied message
// advertises, in the peer's own order.
//
// This reports what was advertised, not what is acceptable — nothing here is
// validated, and the protocol still applies its own transport policy to
// whatever it records.
//
// Implemented by ContactMessage, PairRequestMessage, PrePairRequestMessage and
// UpdateChannelInfoRequestMessage, the four messages carrying
// SupportedTransports.
func AdvertisedEndpoints(m EndpointAdvertiser) []*TransportProtocol {
	if m == nil {
		return nil
	}
	return m.GetSupportedTransports()
}

// EndpointAdvertiser is any peer-supplied message that advertises where its
// sender can be reached. The generated accessors on the four carrying message
// types satisfy it without further declaration.
type EndpointAdvertiser interface {
	GetSupportedTransports() []*TransportProtocol
}

// ReplyToEndpoints reports the endpoints a request asked its response to be
// delivered to, in the requester's own order.
//
// The two are separate functions because the fields mean different things:
// what AdvertisedEndpoints reports is where a peer can be reached in general
// and is recorded on the channel, while this overrides that for a single
// exchange and is deliberately not persisted.
//
// An empty result means the requester named no endpoint, which tells the
// responder to answer on the endpoints recorded for the channel rather than
// that the requester is unreachable.
//
// Implemented by StoreShareRequestMessage, VerifyShareRequestMessage,
// GetSecretIdsVersionsRequestMessage, GetShareRequestMessage and
// UnpairRequestMessage, the five requests carrying ReplyToTransports.
func ReplyToEndpoints(m ReplyToAdvertiser) []*TransportProtocol {
	if m == nil {
		return nil
	}
	return m.GetReplyToTransports()
}

// ReplyToAdvertiser is any request that names where its response should go.
type ReplyToAdvertiser interface {
	GetReplyToTransports() []*TransportProtocol
}
