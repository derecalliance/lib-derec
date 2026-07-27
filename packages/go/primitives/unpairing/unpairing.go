// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package unpairing wraps the DeRec unpairing flow, which terminates a
// paired relationship between two channel endpoints.
package unpairing

import "github.com/derecalliance/lib-derec/packages/go/internal/native"

// ExtractedRequest is the decrypted unpair request: the channel it arrived
// on, the human-readable reason for termination, and the inner
// UnpairRequestMessage proto bytes, which chain into response production.
type ExtractedRequest struct {
	ChannelID    uint64
	Memo         string
	RequestProto []byte
}

type requestAPI struct{}

// Request groups the unpair request operations, mirroring the Rust
// primitives::unpairing::request module.
var Request requestAPI

// Produce builds the wire-encoded DeRecMessage asking the peer on channelID
// to drop all state for the paired relationship, carrying memo, encrypted
// under sharedKey.
func (requestAPI) Produce(channelID uint64, memo string, sharedKey []byte) ([]byte, error) {
	return native.ProduceUnpairRequest(channelID, memo, sharedKey)
}

// Extract decrypts an unpair request envelope and returns its channel id,
// memo, and inner proto bytes.
func (requestAPI) Extract(request, sharedKey []byte) (ExtractedRequest, error) {
	channelID, memo, proto, err := native.ExtractUnpairRequest(request, sharedKey)
	if err != nil {
		return ExtractedRequest{}, err
	}
	return ExtractedRequest{ChannelID: channelID, Memo: memo, RequestProto: proto}, nil
}

// ExtractedResponse is the decrypted unpair response: the channel it arrived
// on and the inner UnpairResponseMessage proto bytes, which chain into
// Response.Process.
type ExtractedResponse struct {
	ChannelID     uint64
	ResponseProto []byte
}

type responseAPI struct{}

// Response groups the unpair response operations, mirroring the Rust
// primitives::unpairing::response module.
var Response responseAPI

// Produce builds the wire-encoded DeRecMessage acknowledging termination of
// the paired relationship on channelID, encrypted under sharedKey.
func (responseAPI) Produce(channelID uint64, sharedKey []byte) ([]byte, error) {
	return native.ProduceUnpairResponse(channelID, sharedKey)
}

// Extract decrypts an unpair response envelope and returns its channel id
// and inner proto bytes.
func (responseAPI) Extract(response, sharedKey []byte) (ExtractedResponse, error) {
	channelID, proto, err := native.ExtractUnpairResponse(response, sharedKey)
	if err != nil {
		return ExtractedResponse{}, err
	}
	return ExtractedResponse{ChannelID: channelID, ResponseProto: proto}, nil
}

// Process validates an unpair response (the ResponseProto returned by
// Response.Extract), confirming the peer acknowledged termination of the
// paired relationship.
func (responseAPI) Process(responseProto []byte) error {
	return native.ProcessUnpairResponse(responseProto)
}
