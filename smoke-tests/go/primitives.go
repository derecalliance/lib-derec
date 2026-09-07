// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Primitive-level smoke tests: exercises the low-level produce/extract/
// process surface for pairing, sharing, verification, recovery, and
// discovery, plus the cross-cutting envelope trace-id helpers. Mirrors
// smoke-tests/rust/src/primitives.rs. Imports only the public
// packages/go/primitives/* packages, packages/go/derec, and
// packages/go/derecpb — the same surface an external consumer has.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/primitives/discovery"
	"github.com/derecalliance/lib-derec/packages/go/primitives/envelope"
	"github.com/derecalliance/lib-derec/packages/go/primitives/pairing"
	"github.com/derecalliance/lib-derec/packages/go/primitives/recovery"
	"github.com/derecalliance/lib-derec/packages/go/primitives/sharing"
	"github.com/derecalliance/lib-derec/packages/go/primitives/verification"
)

func runPrimitives() {
	runPairingFlow()
	runSharingFlow()
	runVerificationFlow()
	runRecoveryFlow()
	runDiscoveryFlow()
	runEnvelopeTraceID()
}

// transportListBytes frames a preference-ordered endpoint list the way
// CreateContact and Request.Produce take it: each proto-encoded
// derecpb.TransportProtocol preceded by its varint byte length, the same
// framing protobuf uses for a repeated embedded message field. The SDK makes
// no assumption about how the application constructs these, so they cross as
// raw bytes.
func transportListBytes(uris ...string) []byte {
	var out []byte
	for _, uri := range uris {
		entry, err := proto.Marshal(&derecpb.TransportProtocol{
			Uri:      uri,
			Protocol: derecpb.Protocol_HTTPS,
		})
		if err != nil {
			fail("marshal TransportProtocol: %v", err)
		}
		out = binary.AppendUvarint(out, uint64(len(entry)))
		out = append(out, entry...)
	}
	return out
}

func sharedKeyFill(fill byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return key
}

// runPairingFlow mirrors run_pairing_flow_test in smoke-tests/rust/src/primitives.rs:
// a full INLINE_KEYS handshake, asserting both sides derive the same shared
// key and the same rekeyed channel id, which must differ from the original.
func runPairingFlow() {
	fmt.Println("=== Pairing flow test ===")

	const channelID = uint64(1)

	aliceTransport := transportListBytes("https://example.com/alice")
	created, err := pairing.Request.CreateContact(channelID, pairing.ContactModeInlineKeys, aliceTransport, nil)
	must(err, "pairing.Request.CreateContact")
	assertTrue(len(created.ContactWireBytes) != 0, "contact wire bytes must not be empty")
	assertTrue(len(created.SecretKeyMaterial) != 0, "contact secret key material must not be empty")

	must(pairing.Request.Validate(created.ContactWireBytes), "pairing.Request.Validate")

	bobTransport := transportListBytes("https://example.com/helper")
	producedReq, err := pairing.Request.Produce(pairing.SenderKindHelper, bobTransport, created.ContactWireBytes, nil, nil)
	must(err, "pairing.Request.Produce")
	assertTrue(len(producedReq.Envelope) != 0, "pair request envelope must not be empty")
	assertTrue(len(producedReq.SecretKeyMaterial) != 0, "pair request secret key material must not be empty")

	extractedReq, err := pairing.Request.Extract(producedReq.Envelope, created.SecretKeyMaterial)
	must(err, "pairing.Request.Extract")
	assertTrue(len(extractedReq.RequestProto) != 0, "extracted pair request proto must not be empty")

	producedResp, err := pairing.Response.Produce(channelID, extractedReq.RequestProto, created.SecretKeyMaterial, nil, nil, false)
	must(err, "pairing.Response.Produce")
	assertTrue(len(producedResp.Envelope) != 0, "pair response envelope must not be empty")
	assertTrue(len(producedResp.PeerTransports) != 0, "peer transports must not be empty")
	assertTrue(len(producedResp.SharedKey) != 0, "initiator shared key must not be empty")

	extractedResp, err := pairing.Response.Extract(producedResp.Envelope, producedReq.SecretKeyMaterial)
	must(err, "pairing.Response.Extract")
	assertTrue(len(extractedResp.ResponseProto) != 0, "extracted pair response proto must not be empty")

	processed, err := pairing.Response.Process(producedReq.InitiatorContactMessage, extractedResp.ResponseProto, producedReq.SecretKeyMaterial)
	must(err, "pairing.Response.Process")
	assertTrue(len(processed.SharedKey) != 0, "responder shared key must not be empty")

	assertTrue(bytes.Equal(producedResp.SharedKey, processed.SharedKey), "shared keys derived by both sides must match")
	assertTrue(producedResp.ChannelID == processed.ChannelID, "both sides must derive the same rekeyed channel id")
	assertTrue(producedResp.ChannelID != channelID, "rekeyed channel id must differ from the pre-rekey id")

	fmt.Println("Pairing flow test passed.")
}

// runSharingFlow mirrors run_sharing_flow_test in smoke-tests/rust/src/primitives.rs:
// split a secret into committed shares across three channels, then walk the
// full store-share request/response/process round trip for each.
func runSharingFlow() {
	fmt.Println("=== Sharing flow test ===")

	const secretID = uint64(0x0102_0304_05ff)
	secretData := []byte{5, 6, 7, 8, 255}
	channelIDs := []uint64{1, 2, 3}
	const threshold = 2
	const version = uint32(1)

	shares, err := sharing.Request.Split(secretID, secretData, channelIDs, threshold, version)
	must(err, "sharing.Request.Split")
	assertTrue(len(shares) == len(channelIDs), "expected one share per channel, got %d", len(shares))

	sharedKey := sharedKeyFill(42)

	for _, channelID := range channelIDs {
		committedShare, ok := shares[channelID]
		assertTrue(ok, "missing share for channel %d", channelID)
		assertTrue(len(committedShare) != 0, "empty committed share for channel %d", channelID)

		requestWire, err := sharing.Request.Produce(channelID, version, secretID, committedShare, nil, "", sharedKey)
		must(err, fmt.Sprintf("sharing.Request.Produce channel %d", channelID))
		assertTrue(len(requestWire) != 0, "empty store share request envelope for channel %d", channelID)

		extractedReq, err := sharing.Request.Extract(requestWire, sharedKey)
		must(err, fmt.Sprintf("sharing.Request.Extract channel %d", channelID))

		respResult, err := sharing.Response.Produce(channelID, extractedReq.RequestProto, sharedKey)
		must(err, fmt.Sprintf("sharing.Response.Produce channel %d", channelID))
		assertTrue(len(respResult.Envelope) != 0, "empty store share response envelope for channel %d", channelID)
		assertTrue(len(respResult.CommittedShare) != 0, "empty committed_share for channel %d", channelID)
		assertTrue(respResult.SecretID == secretID, "secret_id mismatch for channel %d", channelID)
		assertTrue(respResult.Version == version, "version mismatch for channel %d", channelID)

		extractedResp, err := sharing.Response.Extract(respResult.Envelope, sharedKey)
		must(err, fmt.Sprintf("sharing.Response.Extract channel %d", channelID))

		must(sharing.Response.Process(version, extractedResp.ResponseProto), fmt.Sprintf("sharing.Response.Process channel %d", channelID))
	}

	fmt.Println("Sharing flow test passed.")
}

// runVerificationFlow mirrors run_verification_flow_test in
// smoke-tests/rust/src/primitives.rs: challenge channel 1 for its share of a
// split secret, confirm a response proving possession of the exact share
// validates, and confirm a response checked against a different channel's
// share content does not.
func runVerificationFlow() {
	fmt.Println("=== Verification flow test ===")

	const secretID = uint64(0x0102_0304_05ff)
	secretData := []byte{5, 6, 7, 8, 255}
	channelIDs := []uint64{1, 2, 3}
	const threshold = 2
	const version = uint32(1)
	const channel1, channel2 = uint64(1), uint64(2)

	sharedKey := sharedKeyFill(1)

	shares, err := sharing.Request.Split(secretID, secretData, channelIDs, threshold, version)
	must(err, "sharing.Request.Split")
	shareContent1 := shares[channel1]
	shareContent2 := shares[channel2]

	challengeEnvelope, err := verification.Request.Produce(channel1, secretID, version, sharedKey)
	must(err, "verification.Request.Produce")

	extractedReq, err := verification.Request.Extract(challengeEnvelope, sharedKey)
	must(err, "verification.Request.Extract")
	assertTrue(extractedReq.ChannelID == channel1, "channel_id mismatch in verification request: got %d want %d", extractedReq.ChannelID, channel1)

	respEnvelope, err := verification.Response.Produce(channel1, extractedReq.RequestProto, sharedKey, shareContent1)
	must(err, "verification.Response.Produce")
	assertTrue(len(respEnvelope) != 0, "verification response envelope must not be empty")

	extractedResp, err := verification.Response.Extract(respEnvelope, sharedKey)
	must(err, "verification.Response.Extract")
	assertTrue(extractedResp.ChannelID == channel1, "channel_id mismatch in verification response")

	valid, err := verification.Response.Process(extractedReq.RequestProto, extractedResp.ResponseProto, shareContent1)
	must(err, "verification.Response.Process (valid case)")
	assertTrue(valid, "expected a valid verification response")

	respEnvelope2, err := verification.Response.Produce(channel1, extractedReq.RequestProto, sharedKey, shareContent1)
	must(err, "second verification.Response.Produce")
	extractedResp2, err := verification.Response.Extract(respEnvelope2, sharedKey)
	must(err, "second verification.Response.Extract")

	invalid, err := verification.Response.Process(extractedReq.RequestProto, extractedResp2.ResponseProto, shareContent2)
	must(err, "verification.Response.Process (invalid case)")
	assertTrue(!invalid, "expected an invalid verification response for the wrong share")

	fmt.Println("Verification flow test passed.")
}

// runRecoveryFlow mirrors run_recovery_flow_test in smoke-tests/rust/src/primitives.rs:
// store committed shares with two of three channels, walk the get-share
// request/response exchange with each, and reconstruct the original secret.
func runRecoveryFlow() {
	fmt.Println("=== Recovery flow test ===")

	const secretID = uint64(0x0102_0304_05ff)
	secretData := []byte{5, 6, 7, 8, 255}
	channelIDs := []uint64{1, 2, 3}
	const threshold = 2
	const version = uint32(1)

	shares, err := sharing.Request.Split(secretID, secretData, channelIDs, threshold, version)
	must(err, "sharing.Request.Split")

	keys := map[uint64][]byte{1: sharedKeyFill(1), 2: sharedKeyFill(2), 3: sharedKeyFill(3)}

	storedRequests := make(map[uint64][]byte)
	for _, channelID := range []uint64{1, 2} {
		key := keys[channelID]

		requestWire, err := sharing.Request.Produce(channelID, version, secretID, shares[channelID], nil, "", key)
		must(err, fmt.Sprintf("sharing.Request.Produce channel %d", channelID))

		extracted, err := sharing.Request.Extract(requestWire, key)
		must(err, fmt.Sprintf("sharing.Request.Extract channel %d", channelID))

		storedRequests[channelID] = extracted.RequestProto
	}

	var responses []recovery.ShareResponse
	for _, channelID := range []uint64{1, 2} {
		key := keys[channelID]

		getRequestWire, err := recovery.Request.Produce(channelID, secretID, version, key)
		must(err, fmt.Sprintf("recovery.Request.Produce channel %d", channelID))

		extractedReq, err := recovery.Request.Extract(getRequestWire, key)
		must(err, fmt.Sprintf("recovery.Request.Extract channel %d", channelID))
		assertTrue(extractedReq.ChannelID == channelID, "recovery request channel_id mismatch for channel %d", channelID)

		getResponseWire, err := recovery.Response.Produce(channelID, extractedReq.RequestProto, storedRequests[channelID], key)
		must(err, fmt.Sprintf("recovery.Response.Produce channel %d", channelID))

		extractedResp, err := recovery.Response.Extract(getResponseWire, key)
		must(err, fmt.Sprintf("recovery.Response.Extract channel %d", channelID))
		assertTrue(extractedResp.ChannelID == channelID, "recovery response channel_id mismatch for channel %d", channelID)

		responses = append(responses, recovery.ShareResponse{Response: getResponseWire, SharedKey: key})
	}

	recovered, err := recovery.Response.Recover(responses, secretID, version)
	must(err, "recovery.Response.Recover")
	assertTrue(bytes.Equal(recovered, secretData), "recovered secret does not match the original: got %x want %x", recovered, secretData)

	fmt.Println("Recovery flow test passed.")
}

// runDiscoveryFlow mirrors run_discovery_flow_test in smoke-tests/rust/src/primitives.rs:
// a discovery request/response round trip advertising a small secret-id/
// version list, asserting it decodes unchanged.
func runDiscoveryFlow() {
	fmt.Println("=== Discovery flow test ===")

	const channelID = uint64(7)
	sharedKey := sharedKeyFill(11)

	requestWire, err := discovery.Request.Produce(channelID, sharedKey)
	must(err, "discovery.Request.Produce")
	assertTrue(len(requestWire) != 0, "discovery request envelope must not be empty")

	_, err = discovery.Request.Extract(requestWire, sharedKey)
	must(err, "discovery.Request.Extract")

	secretList := []discovery.SecretVersionEntry{
		{
			SecretID: 0xABCD,
			Versions: []discovery.VersionEntry{
				{Version: 1, Description: "wallet seed"},
				{Version: 2, Description: "wallet seed v2"},
			},
		},
	}

	responseWire, err := discovery.Response.Produce(channelID, secretList, sharedKey)
	must(err, "discovery.Response.Produce")

	extractedResp, err := discovery.Response.Extract(responseWire, sharedKey)
	must(err, "discovery.Response.Extract")

	processed, err := discovery.Response.Process(extractedResp.ResponseProto)
	must(err, "discovery.Response.Process")

	assertTrue(len(processed) == len(secretList), "discovery secret list must round-trip unchanged: got %d entries want %d", len(processed), len(secretList))
	assertTrue(processed[0].SecretID == secretList[0].SecretID, "secret_id mismatch: got %d want %d", processed[0].SecretID, secretList[0].SecretID)
	assertTrue(len(processed[0].Versions) == len(secretList[0].Versions), "versions count mismatch")
	for i := range secretList[0].Versions {
		assertTrue(processed[0].Versions[i].Version == secretList[0].Versions[i].Version, "version mismatch at index %d", i)
		assertTrue(processed[0].Versions[i].Description == secretList[0].Versions[i].Description, "description mismatch at index %d", i)
	}

	fmt.Println("Discovery flow test passed.")
}

// runEnvelopeTraceID mirrors run_envelope_trace_id_test in
// smoke-tests/rust/src/primitives.rs: the trace_id helpers round-trip a value
// through an envelope's outer field without disturbing the encrypted inner
// payload — Extract still succeeds after re-stamping.
func runEnvelopeTraceID() {
	fmt.Println("=== Envelope trace_id helpers test ===")

	const channelID = uint64(42)
	sharedKey := sharedKeyFill(9)

	result, err := discovery.Request.Produce(channelID, sharedKey)
	must(err, "discovery.Request.Produce")

	traceBefore, err := envelope.ReadTraceID(result)
	must(err, "envelope.ReadTraceID (before)")
	assertTrue(traceBefore == 0, "primitive default trace_id must be 0, got %d", traceBefore)

	const traceID = uint64(0xDEAD_BEEF_F00D_CAFE)
	stamped, err := envelope.ApplyTraceID(result, traceID)
	must(err, "envelope.ApplyTraceID")

	traceAfter, err := envelope.ReadTraceID(stamped)
	must(err, "envelope.ReadTraceID (after)")
	assertTrue(traceAfter == traceID, "trace_id must round-trip through apply + read: got %d want %d", traceAfter, traceID)

	_, err = discovery.Request.Extract(stamped, sharedKey)
	must(err, "discovery.Request.Extract on re-stamped envelope")

	fmt.Println("Envelope trace_id helpers test passed.")
}
