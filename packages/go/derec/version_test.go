// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package derec_test

import (
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/primitives/unpairing"
	"google.golang.org/protobuf/proto"
)

func TestCurrentProtocolVersionMatchesCore(t *testing.T) {
	got := derec.CurrentProtocolVersion()
	// library/src/protocol_version.rs: CURRENT = { major: 0, minor: 0 }.
	if want := (derec.ProtocolVersion{Major: 0, Minor: 0}); got != want {
		t.Fatalf("want %+v got %+v", want, got)
	}
}

func TestCurrentProtocolVersionMatchesEnvelopeStamp(t *testing.T) {
	key := make([]byte, 32)
	wire, err := unpairing.Request.Produce(1, "", key, nil)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	var msg derecpb.DeRecMessage
	if err := proto.Unmarshal(wire, &msg); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	got := derec.CurrentProtocolVersion()
	if int64(got.Major) != int64(msg.GetProtocolVersionMajor()) || int64(got.Minor) != int64(msg.GetProtocolVersionMinor()) {
		t.Fatalf("version %+v differs from envelope stamp %d.%d", got, msg.GetProtocolVersionMajor(), msg.GetProtocolVersionMinor())
	}
}
