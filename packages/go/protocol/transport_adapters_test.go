// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"errors"
	"reflect"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
)

// recordingDialer records every endpoint it was asked to dial and refuses the
// ones named.
type recordingDialer struct {
	attempted []string
	refuse    map[string]bool
}

func newDialer(refuse ...string) *recordingDialer {
	set := make(map[string]bool, len(refuse))
	for _, uri := range refuse {
		set[uri] = true
	}
	return &recordingDialer{refuse: set}
}

func (d *recordingDialer) SendOne(endpoint Endpoint, _ []byte) error {
	d.attempted = append(d.attempted, endpoint.URI)
	if d.refuse[endpoint.URI] {
		return errors.New("refused " + endpoint.URI)
	}
	return nil
}

func endpoints(uris ...string) []Endpoint {
	out := make([]Endpoint, 0, len(uris))
	for _, uri := range uris {
		out = append(out, Endpoint{URI: uri, Protocol: 0})
	}
	return out
}

const a, b, c = "https://a.example", "https://b.example", "https://c.example"

// Delivering to every endpoint would send one authenticated message to the
// same peer several times, so the first success has to end the attempt.
func TestSequentialFailover_StopsAtTheFirstSuccess(t *testing.T) {
	d := newDialer()
	if err := (SequentialFailover{Dialer: d}).Send(endpoints(a, b), []byte("m")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if want := []string{a}; !reflect.DeepEqual(d.attempted, want) {
		t.Fatalf("attempted = %v, want %v", d.attempted, want)
	}
}

func TestSequentialFailover_AdvancesPastAFailingEndpoint(t *testing.T) {
	d := newDialer(a)
	if err := (SequentialFailover{Dialer: d}).Send(endpoints(a, b), []byte("m")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if want := []string{a, b}; !reflect.DeepEqual(d.attempted, want) {
		t.Fatalf("attempted = %v, want %v", d.attempted, want)
	}
}

// The order is the peer's and is not reinterpreted.
func TestSequentialFailover_UsesThePeersOrder(t *testing.T) {
	d := newDialer(a)
	if err := (SequentialFailover{Dialer: d}).Send(endpoints(a, b, c), []byte("m")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if want := []string{a, b}; !reflect.DeepEqual(d.attempted, want) {
		t.Fatalf("attempted = %v, want %v", d.attempted, want)
	}
}

func TestSequentialFailover_FailsOnlyWhenEveryEndpointDid(t *testing.T) {
	d := newDialer(a, b)
	if err := (SequentialFailover{Dialer: d}).Send(endpoints(a, b), []byte("m")); err == nil {
		t.Fatal("expected an error when no endpoint accepted the message")
	}
	if want := []string{a, b}; !reflect.DeepEqual(d.attempted, want) {
		t.Fatalf("attempted = %v, want %v", d.attempted, want)
	}
}

func TestSingleEndpointTransport_IgnoresTheRest(t *testing.T) {
	d := newDialer()
	if err := (SingleEndpointTransport{Dialer: d}).Send(endpoints(a, b), []byte("m")); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if want := []string{a}; !reflect.DeepEqual(d.attempted, want) {
		t.Fatalf("attempted = %v, want %v", d.attempted, want)
	}
}

// The distinguishing property: where SequentialFailover would recover, this
// reports the failure. That is the cost of choosing it, made observable.
func TestSingleEndpointTransport_DoesNotFallBack(t *testing.T) {
	d := newDialer(a)
	if err := (SingleEndpointTransport{Dialer: d}).Send(endpoints(a, b), []byte("m")); err == nil {
		t.Fatal("expected an error: the only endpoint tried was refused")
	}
	if want := []string{a}; !reflect.DeepEqual(d.attempted, want) {
		t.Fatalf("attempted = %v, want %v", d.attempted, want)
	}
}

// Both adapters satisfy the interface the builder takes.
func TestAdaptersAreTransports(t *testing.T) {
	var _ Transport = SequentialFailover{Dialer: newDialer()}
	var _ Transport = SingleEndpointTransport{Dialer: newDialer()}
}

type sentinelDialer struct{ errs map[string]error }

func (d sentinelDialer) SendOne(endpoint Endpoint, _ []byte) error { return d.errs[endpoint.URI] }

// When no endpoint accepts the message the adapters return the dialer's own
// error unchanged, so a caller matches it with errors.Is / errors.As exactly
// as it would its dialer's error; the adapters add no library error code.
func TestAdapters_ReturnTheDialersErrorUnchanged(t *testing.T) {
	errA, errB := errors.New("a down"), errors.New("b down")
	d := sentinelDialer{errs: map[string]error{a: errA, b: errB}}

	err := (SequentialFailover{Dialer: d}).Send(endpoints(a, b), []byte("m"))
	if !errors.Is(err, errB) {
		t.Fatalf("SequentialFailover: got %v, want the last dialer error %v", err, errB)
	}
	var derecErr *derec.Error
	if errors.As(err, &derecErr) {
		t.Fatalf("SequentialFailover: dialer error was replaced by %v", derecErr)
	}

	if err := (SingleEndpointTransport{Dialer: d}).Send(endpoints(a, b), []byte("m")); !errors.Is(err, errA) {
		t.Fatalf("SingleEndpointTransport: got %v, want the dialer error %v", err, errA)
	}
}
