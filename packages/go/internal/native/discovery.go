// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

type produceGetSecretIdsVersionsRequestMessageResult struct {
	Error             DeRecError
	EnvelopeWireBytes DeRecBuffer
}

type extractGetSecretIdsVersionsRequestResult struct {
	Error             DeRecError
	ChannelID         uint64
	RequestProtoBytes DeRecBuffer
}

type produceGetSecretIdsVersionsResponseMessageResult struct {
	Error             DeRecError
	EnvelopeWireBytes DeRecBuffer
}

type extractGetSecretIdsVersionsResponseResult struct {
	Error              DeRecError
	ChannelID          uint64
	ResponseProtoBytes DeRecBuffer
}

type processGetSecretIdsVersionsResponseMessageResult struct {
	Error           DeRecError
	SecretListBytes DeRecBuffer
}

var (
	produceDiscoveryReqOnce sync.Once
	produceDiscoveryReqFn   func(channelID uint64,
		sharedKey *byte, sharedKeyLen uintptr,
		replyTo *byte, replyToLen uintptr) produceGetSecretIdsVersionsRequestMessageResult

	extractDiscoveryReqOnce sync.Once
	extractDiscoveryReqFn   func(request *byte, requestLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) extractGetSecretIdsVersionsRequestResult

	produceDiscoveryRespOnce sync.Once
	produceDiscoveryRespFn   func(channelID uint64,
		secretList *byte, secretListLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) produceGetSecretIdsVersionsResponseMessageResult

	extractDiscoveryRespOnce sync.Once
	extractDiscoveryRespFn   func(response *byte, responseLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) extractGetSecretIdsVersionsResponseResult

	processDiscoveryRespOnce sync.Once
	processDiscoveryRespFn   func(responseProto *byte, responseProtoLen uintptr) processGetSecretIdsVersionsResponseMessageResult
)

// ProduceGetSecretIdsVersionsRequest builds the wire-encoded DeRecMessage
// carrying a discovery request on channelID, encrypted under sharedKey.
func ProduceGetSecretIdsVersionsRequest(channelID uint64, sharedKey []byte) ([]byte, error) {
	produceDiscoveryReqOnce.Do(func() {
		purego.RegisterFunc(&produceDiscoveryReqFn, symbol("produce_get_secret_ids_versions_request_message"))
	})
	res := produceDiscoveryReqFn(channelID,
		bytePtr(sharedKey), uintptr(len(sharedKey)),
		nil, 0)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.EnvelopeWireBytes), nil
}

// ExtractGetSecretIdsVersionsRequest decrypts a discovery request envelope
// and returns its channel id and inner proto bytes.
func ExtractGetSecretIdsVersionsRequest(request, sharedKey []byte) (uint64, []byte, error) {
	extractDiscoveryReqOnce.Do(func() {
		purego.RegisterFunc(&extractDiscoveryReqFn, symbol("extract_get_secret_ids_versions_request"))
	})
	res := extractDiscoveryReqFn(bytePtr(request), uintptr(len(request)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.RequestProtoBytes), nil
}

// ProduceGetSecretIdsVersionsResponse builds the wire-encoded DeRecMessage
// advertising secretList (encoded in the binary format documented at
// library/src/interop/ffi/discovery.rs) on channelID, encrypted under sharedKey.
func ProduceGetSecretIdsVersionsResponse(channelID uint64, secretList, sharedKey []byte) ([]byte, error) {
	produceDiscoveryRespOnce.Do(func() {
		purego.RegisterFunc(&produceDiscoveryRespFn, symbol("produce_get_secret_ids_versions_response_message"))
	})
	res := produceDiscoveryRespFn(channelID,
		bytePtr(secretList), uintptr(len(secretList)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.EnvelopeWireBytes), nil
}

// ExtractGetSecretIdsVersionsResponse decrypts a discovery response envelope
// and returns its channel id and inner proto bytes.
func ExtractGetSecretIdsVersionsResponse(response, sharedKey []byte) (uint64, []byte, error) {
	extractDiscoveryRespOnce.Do(func() {
		purego.RegisterFunc(&extractDiscoveryRespFn, symbol("extract_get_secret_ids_versions_response"))
	})
	res := extractDiscoveryRespFn(bytePtr(response), uintptr(len(response)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.ResponseProtoBytes), nil
}

// ProcessGetSecretIdsVersionsResponse validates a discovery response (the
// inner GetSecretIdsVersionsResponseMessage proto bytes returned by
// ExtractGetSecretIdsVersionsResponse) and returns the advertised secret list
// in the binary format documented at library/src/interop/ffi/discovery.rs.
func ProcessGetSecretIdsVersionsResponse(responseProto []byte) ([]byte, error) {
	processDiscoveryRespOnce.Do(func() {
		purego.RegisterFunc(&processDiscoveryRespFn, symbol("process_get_secret_ids_versions_response_message"))
	})
	res := processDiscoveryRespFn(bytePtr(responseProto), uintptr(len(responseProto)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.SecretListBytes), nil
}
