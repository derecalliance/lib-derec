// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/protocol"
	"google.golang.org/protobuf/proto"
)

// runProtocolConfig builds a node from library/tests/fixtures/protocol_config.json,
// the canonical config JSON every SDK reads, pairs it, and checks that
// layering is last-write-wins and that a misspelled key is refused rather
// than dropped.
func runProtocolConfig() {
	fmt.Println("=== Protocol config record test ===")

	path := filepath.Join("..", "..", "library", "tests", "fixtures", "protocol_config.json")
	raw, err := os.ReadFile(path)
	must(err, "read "+path)
	var fixture map[string]json.RawMessage
	must(json.Unmarshal(raw, &fixture), "parse "+path)

	// A node built from the full fixture pairs like any other.
	cfg := protocol.Config{SecretID: protocolSecretID}
	must(json.Unmarshal(fixture["full"], &cfg.DeRecProtocolConfig), "unmarshal fixture `full`")
	assertTrue(*cfg.Threshold == 3 && *cfg.ReplicaID == 9007199254740993 && len(cfg.OwnTransports) == 2,
		"fixture `full` did not unmarshal into every field: %+v", cfg.DeRecProtocolConfig)
	owner, err := newPeerFromConfig("owner", cfg)
	must(err, "protocol.New(fixture `full`)")
	defer owner.proto.Close()
	helper := newPeer("helper", "https://helper.example.com", 2)
	defer helper.proto.Close()
	channel := pairPeers(owner, helper, 7)
	fmt.Printf("  node built from fixture `full` pairs (channel %d)  ✓\n", channel)

	// A misspelled key fails the unmarshal, naming the key, at any level.
	for _, bad := range []struct{ json, key string }{
		{`{"treshold": 3}`, "treshold"},
		{`{"timeouts": {"sharing_round": 30}}`, "sharing_round"},
		{`{"own_transports": [{"uri": "https://a.example", "protocl": "https"}]}`, "protocl"},
	} {
		var c protocol.DeRecProtocolConfig
		err := json.Unmarshal([]byte(bad.json), &c)
		assertTrue(err != nil && strings.Contains(err.Error(), bad.key),
			"%s must be refused naming %q, got %v", bad.json, bad.key, err)
		fmt.Printf("  %s refused: %v  ✓\n", bad.json, err)
	}

	// Layering: one json.Unmarshal per layer, then plain assignments; the
	// last write wins and the library validates the result at New.
	build := func(assign func(*protocol.Config), layers ...string) error {
		c := protocol.Config{SecretID: protocolSecretID}
		for _, layer := range append([]string{string(fixture["minimal"])}, layers...) {
			must(json.Unmarshal([]byte(layer), &c.DeRecProtocolConfig), "unmarshal "+layer)
		}
		if assign != nil {
			assign(&c)
		}
		p, err := newPeerFromConfig("layered", c)
		if err == nil {
			p.proto.Close()
		}
		return err
	}
	invalidInput := func(err error) bool {
		var de *derec.Error
		return errors.As(err, &de) && de.Code == derec.CodeInvalidInput
	}
	must(build(nil, `{"threshold": 1}`, `{"threshold": 3}`), "threshold 1 then 3")
	fmt.Println("  threshold 1 then 3 builds  ✓")
	assertTrue(invalidInput(build(nil, `{"threshold": 3}`, `{"max_subshares": "2"}`)),
		"a later layer must keep an earlier threshold, so a cap of 2 under threshold 3 is refused")
	fmt.Println("  a later layer keeps an earlier threshold (cap 2 < threshold 3 refused)  ✓")
	must(build(func(c *protocol.Config) { c.Threshold = proto.Uint32(2) },
		`{"threshold": 3}`, `{"max_subshares": "2"}`), "assignment after the layers")
	fmt.Println("  an assignment after the layers wins  ✓")

	fmt.Println("Protocol config record test passed.")
}
