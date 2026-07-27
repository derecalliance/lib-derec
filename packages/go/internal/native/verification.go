// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

type produceVerifyRequestResult struct {
	Error            DeRecError
	RequestWireBytes DeRecBuffer
}

type extractVerifyRequestResult struct {
	Error             DeRecError
	ChannelID         uint64
	RequestProtoBytes DeRecBuffer
}

type produceVerifyShareResponseMessageResult struct {
	Error             DeRecError
	ResponseWireBytes DeRecBuffer
}

type extractVerifyShareResponseResult struct {
	Error              DeRecError
	ChannelID          uint64
	ResponseProtoBytes DeRecBuffer
}

type verifyShareResponseResult struct {
	Error   DeRecError
	IsValid bool
}

var (
	produceVerifyReqOnce sync.Once
	produceVerifyReqFn   func(channelID, secretID uint64, version uint32,
		sharedKey *byte, sharedKeyLen uintptr,
		replyTo *byte, replyToLen uintptr) produceVerifyRequestResult

	extractVerifyReqOnce sync.Once
	extractVerifyReqFn   func(request *byte, requestLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) extractVerifyRequestResult

	produceVerifyRespOnce sync.Once
	produceVerifyRespFn   func(channelID uint64,
		requestProto *byte, requestProtoLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr,
		shareContent *byte, shareContentLen uintptr) produceVerifyShareResponseMessageResult

	extractVerifyRespOnce sync.Once
	extractVerifyRespFn   func(response *byte, responseLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) extractVerifyShareResponseResult

	processVerifyRespOnce sync.Once
	processVerifyRespFn   func(requestProto *byte, requestProtoLen uintptr,
		responseProto *byte, responseProtoLen uintptr,
		shareContent *byte, shareContentLen uintptr) verifyShareResponseResult
)

// bytePtr returns the address of the first byte of s, or nil for an empty
// slice. purego maps this to the C void* argument; the paired length argument
// carries the size.
func bytePtr(s []byte) *byte {
	if len(s) == 0 {
		return nil
	}
	return &s[0]
}

func ProduceVerifyShareRequest(channelID, secretID uint64, version uint32, sharedKey []byte) ([]byte, error) {
	produceVerifyReqOnce.Do(func() {
		purego.RegisterFunc(&produceVerifyReqFn, symbol("produce_verify_share_request_message"))
	})
	res := produceVerifyReqFn(channelID, secretID, version,
		bytePtr(sharedKey), uintptr(len(sharedKey)),
		nil, 0)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.RequestWireBytes), nil
}

func ExtractVerifyShareRequest(request, sharedKey []byte) (uint64, []byte, error) {
	extractVerifyReqOnce.Do(func() {
		purego.RegisterFunc(&extractVerifyReqFn, symbol("extract_verify_share_request"))
	})
	res := extractVerifyReqFn(bytePtr(request), uintptr(len(request)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.RequestProtoBytes), nil
}

// ProduceVerifyShareResponse builds the wire-encoded DeRecMessage proving
// possession of shareContent in answer to requestProto (the inner
// VerifyShareRequestMessage proto bytes returned by ExtractVerifyShareRequest),
// encrypted under sharedKey.
func ProduceVerifyShareResponse(channelID uint64, requestProto, sharedKey, shareContent []byte) ([]byte, error) {
	produceVerifyRespOnce.Do(func() {
		purego.RegisterFunc(&produceVerifyRespFn, symbol("produce_verify_share_response_message"))
	})
	res := produceVerifyRespFn(channelID,
		bytePtr(requestProto), uintptr(len(requestProto)),
		bytePtr(sharedKey), uintptr(len(sharedKey)),
		bytePtr(shareContent), uintptr(len(shareContent)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.ResponseWireBytes), nil
}

// ExtractVerifyShareResponse decrypts a verification response envelope and
// returns its channel id and inner proto bytes.
func ExtractVerifyShareResponse(response, sharedKey []byte) (uint64, []byte, error) {
	extractVerifyRespOnce.Do(func() {
		purego.RegisterFunc(&extractVerifyRespFn, symbol("extract_verify_share_response"))
	})
	res := extractVerifyRespFn(bytePtr(response), uintptr(len(response)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.ResponseProtoBytes), nil
}

// ProcessVerifyShareResponse checks a verification response (the inner
// VerifyShareResponseMessage proto bytes returned by
// ExtractVerifyShareResponse) against the originating requestProto (the inner
// VerifyShareRequestMessage proto bytes the challenger produced) and the
// expected shareContent, reporting whether the response proves possession of
// that exact share.
func ProcessVerifyShareResponse(requestProto, responseProto, shareContent []byte) (bool, error) {
	processVerifyRespOnce.Do(func() {
		purego.RegisterFunc(&processVerifyRespFn, symbol("process_verify_share_response_message"))
	})
	res := processVerifyRespFn(
		bytePtr(requestProto), uintptr(len(requestProto)),
		bytePtr(responseProto), uintptr(len(responseProto)),
		bytePtr(shareContent), uintptr(len(shareContent)))
	if err := errorFrom(res.Error); err != nil {
		return false, err
	}
	return res.IsValid, nil
}
