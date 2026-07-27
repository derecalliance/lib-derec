// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"
	"testing"
)

func TestRegisterStoresAssignsDistinctNonZeroHandles(t *testing.T) {
	h1 := registerStores(&storeSet{})
	h2 := registerStores(&storeSet{})
	defer releaseStores(h1)
	defer releaseStores(h2)

	if h1 == 0 || h2 == 0 {
		t.Fatalf("expected non-zero handles, got %d and %d", h1, h2)
	}
	if h1 == h2 {
		t.Fatalf("expected distinct handles, got %d twice", h1)
	}
}

func TestLookupStoresReturnsRegisteredSet(t *testing.T) {
	s := &storeSet{}
	h := registerStores(s)
	defer releaseStores(h)

	got, ok := lookupStores(h)
	if !ok {
		t.Fatal("expected lookup to succeed for a registered handle")
	}
	if got != s {
		t.Fatalf("expected lookup to return the registered *storeSet, got %p want %p", got, s)
	}
}

func TestReleaseStoresRemovesMapping(t *testing.T) {
	h := registerStores(&storeSet{})
	releaseStores(h)

	if _, ok := lookupStores(h); ok {
		t.Fatal("expected lookup to fail after release")
	}
}

func TestLookupStoresUnknownHandleFails(t *testing.T) {
	if _, ok := lookupStores(storeHandle(0)); ok {
		t.Fatal("expected lookup of the zero handle to fail")
	}
	if _, ok := lookupStores(storeHandle(1 << 40)); ok {
		t.Fatal("expected lookup of an unregistered handle to fail")
	}
}

// TestRegisterStoresConcurrentUnique registers from multiple goroutines
// simultaneously and asserts every handle handed out is unique and non-zero,
// guarding against a data race in the monotonic counter.
func TestRegisterStoresConcurrentUnique(t *testing.T) {
	const n = 100
	handles := make(chan storeHandle, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handles <- registerStores(&storeSet{})
		}()
	}
	wg.Wait()
	close(handles)

	seen := make(map[storeHandle]bool, n)
	for h := range handles {
		if h == 0 {
			t.Fatal("got zero handle from concurrent registration")
		}
		if seen[h] {
			t.Fatalf("duplicate handle %d from concurrent registration", h)
		}
		seen[h] = true
		releaseStores(h)
	}
}
