// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package verification wraps the DeRec verification (challenge-response) flow.
package verification

import "github.com/derecalliance/lib-derec/packages/go/internal/native"

// ExtractedRequest is the decrypted verification request: the channel it
// arrived on and the inner VerifyShareRequestMessage proto bytes, which chain
// into response production.
type ExtractedRequest struct {
	ChannelID    uint64
	RequestProto []byte
}

type requestAPI struct{}

// Request groups the owner-side request operations, mirroring the Rust
// primitives::verification::request module.
var Request requestAPI

// Produce builds the wire-encoded DeRecMessage carrying a verification
// challenge for (channelID, secretID, version), encrypted under sharedKey.
func (requestAPI) Produce(channelID, secretID uint64, version uint32, sharedKey []byte) ([]byte, error) {
	return native.ProduceVerifyShareRequest(channelID, secretID, version, sharedKey)
}

// Extract decrypts a verification request envelope and returns its channel id
// and inner proto bytes.
func (requestAPI) Extract(request, sharedKey []byte) (ExtractedRequest, error) {
	channelID, proto, err := native.ExtractVerifyShareRequest(request, sharedKey)
	if err != nil {
		return ExtractedRequest{}, err
	}
	return ExtractedRequest{ChannelID: channelID, RequestProto: proto}, nil
}

// ExtractedResponse is the decrypted verification response: the channel it
// arrived on and the inner VerifyShareResponseMessage proto bytes, which
// chain into Response.Process.
type ExtractedResponse struct {
	ChannelID     uint64
	ResponseProto []byte
}

type responseAPI struct{}

// Response groups the helper-side verification operations, mirroring the
// Rust primitives::verification::response module.
var Response responseAPI

// Produce builds the wire-encoded DeRecMessage proving possession of
// shareContent in answer to requestProto (the RequestProto returned by
// Request.Extract), encrypted under sharedKey.
func (responseAPI) Produce(channelID uint64, requestProto, sharedKey, shareContent []byte) ([]byte, error) {
	return native.ProduceVerifyShareResponse(channelID, requestProto, sharedKey, shareContent)
}

// Extract decrypts a verification response envelope and returns its channel
// id and inner proto bytes.
func (responseAPI) Extract(response, sharedKey []byte) (ExtractedResponse, error) {
	channelID, proto, err := native.ExtractVerifyShareResponse(response, sharedKey)
	if err != nil {
		return ExtractedResponse{}, err
	}
	return ExtractedResponse{ChannelID: channelID, ResponseProto: proto}, nil
}

// Process checks a verification response (the ResponseProto returned by
// Response.Extract) against the originating requestProto (the RequestProto
// returned by Request.Extract) and the expected shareContent, reporting
// whether the response proves possession of that exact share.
func (responseAPI) Process(requestProto, responseProto, shareContent []byte) (bool, error) {
	return native.ProcessVerifyShareResponse(requestProto, responseProto, shareContent)
}
