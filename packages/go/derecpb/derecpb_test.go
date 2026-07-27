// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package derecpb_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
)

func TestTransportProtocolRoundTrips(t *testing.T) {
	tp := &derecpb.TransportProtocol{Uri: "https://example.com/a", Protocol: derecpb.Protocol_HTTPS}
	b, err := proto.Marshal(tp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got derecpb.TransportProtocol
	if err := proto.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Uri != tp.Uri || got.Protocol != tp.Protocol {
		t.Fatalf("round-trip mismatch: %v vs %v", &got, tp)
	}
}
