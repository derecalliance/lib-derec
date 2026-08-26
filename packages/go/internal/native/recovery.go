// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

type produceGetShareRequestMessageResult struct {
	Error            DeRecError
	RequestWireBytes DeRecBuffer
}

type extractGetShareRequestResult struct {
	Error             DeRecError
	ChannelID         uint64
	RequestProtoBytes DeRecBuffer
}

type produceGetShareResponseMessageResult struct {
	Error             DeRecError
	ResponseWireBytes DeRecBuffer
}

type extractGetShareResponseResult struct {
	Error              DeRecError
	ChannelID          uint64
	ResponseProtoBytes DeRecBuffer
}

type recoverFromShareResponsesResult struct {
	Error      DeRecError
	SecretData DeRecBuffer
}

var (
	produceGetShareReqOnce sync.Once
	produceGetShareReqFn   func(channelID, secretID uint64, version uint32,
		sharedKey *byte, sharedKeyLen uintptr,
		replyTo *byte, replyToLen uintptr) produceGetShareRequestMessageResult

	extractGetShareReqOnce sync.Once
	extractGetShareReqFn   func(request *byte, requestLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) extractGetShareRequestResult

	produceGetShareRespOnce sync.Once
	produceGetShareRespFn   func(channelID uint64,
		requestProto *byte, requestProtoLen uintptr,
		storedShareProto *byte, storedShareProtoLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) produceGetShareResponseMessageResult

	extractGetShareRespOnce sync.Once
	extractGetShareRespFn   func(response *byte, responseLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) extractGetShareResponseResult

	recoverFromRespOnce sync.Once
	recoverFromRespFn   func(responses *byte, responsesLen uintptr,
		secretID uint64, version uint32) recoverFromShareResponsesResult
)

// ProduceGetShareRequest builds the wire-encoded DeRecMessage requesting the
// helper's stored share for (secretID, version) on channelID, encrypted under
// sharedKey.
func ProduceGetShareRequest(channelID, secretID uint64, version uint32, sharedKey []byte) ([]byte, error) {
	produceGetShareReqOnce.Do(func() {
		purego.RegisterFunc(&produceGetShareReqFn, symbol("produce_get_share_request_message"))
	})
	res := produceGetShareReqFn(channelID, secretID, version,
		bytePtr(sharedKey), uintptr(len(sharedKey)),
		nil, 0)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.RequestWireBytes), nil
}

// ExtractGetShareRequest decrypts a get-share request envelope and returns
// its channel id and inner proto bytes.
func ExtractGetShareRequest(request, sharedKey []byte) (uint64, []byte, error) {
	extractGetShareReqOnce.Do(func() {
		purego.RegisterFunc(&extractGetShareReqFn, symbol("extract_get_share_request"))
	})
	res := extractGetShareReqFn(bytePtr(request), uintptr(len(request)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.RequestProtoBytes), nil
}

// ProduceGetShareResponse builds the wire-encoded DeRecMessage answering
// requestProto (the inner GetShareRequestMessage proto bytes returned by
// ExtractGetShareRequest) with the helper's storedShareProto (the inner
// StoreShareRequestMessage proto bytes persisted at sharing time), encrypted
// under sharedKey.
func ProduceGetShareResponse(channelID uint64, requestProto, storedShareProto, sharedKey []byte) ([]byte, error) {
	produceGetShareRespOnce.Do(func() {
		purego.RegisterFunc(&produceGetShareRespFn, symbol("produce_get_share_response_message"))
	})
	res := produceGetShareRespFn(channelID,
		bytePtr(requestProto), uintptr(len(requestProto)),
		bytePtr(storedShareProto), uintptr(len(storedShareProto)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.ResponseWireBytes), nil
}

// ExtractGetShareResponse decrypts a get-share response envelope and returns
// its channel id and inner proto bytes. Accumulate the returned bytes across
// helpers to build the responses set passed to RecoverFromShareResponses.
func ExtractGetShareResponse(response, sharedKey []byte) (uint64, []byte, error) {
	extractGetShareRespOnce.Do(func() {
		purego.RegisterFunc(&extractGetShareRespFn, symbol("extract_get_share_response"))
	})
	res := extractGetShareRespFn(bytePtr(response), uintptr(len(response)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.ResponseProtoBytes), nil
}

// RecoverFromShareResponses reconstructs the secret stored under
// (secretID, version) from responsesWire, a length-prefixed sequence of
// decrypted GetShareResponseMessage proto bytes matching the format
// documented at library/src/interop/ffi/recovery.rs:
//
//	[count: u32 LE]
//	for each entry:
//	  [response_len: u32 LE]
//	  [serialized GetShareResponseMessage]
func RecoverFromShareResponses(responsesWire []byte, secretID uint64, version uint32) ([]byte, error) {
	recoverFromRespOnce.Do(func() {
		purego.RegisterFunc(&recoverFromRespFn, symbol("recover_from_share_responses"))
	})
	res := recoverFromRespFn(bytePtr(responsesWire), uintptr(len(responsesWire)), secretID, version)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.SecretData), nil
}
