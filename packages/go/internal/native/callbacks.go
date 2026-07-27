// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import "sync"

// storeSet holds the Go implementations of the six store/transport
// interfaces backing one protocol instance. Each field's type
// (channelStore, secretStore, shareStore, userSecretStore, stateStore,
// transportSender — declared alongside their dispatch logic in
// callbacks_channel.go, callbacks_secret.go, callbacks_share.go,
// callbacks_usersecret.go, callbacks_state.go, callbacks_transport.go) is
// an interface native declares itself, with a method set identical to the
// corresponding public interface in package protocol.
//
// native cannot import protocol to reference protocol.ChannelStore etc.
// directly: protocol already imports native for the FFI bridge, so the
// reverse import would cycle. Re-declaring the same method set locally
// sidesteps that without an adapter — protocol's domain types (Channel,
// Share, SecretValue, ...) are type aliases for native's, so any
// protocol.ChannelStore/SecretStore/.../Transport implementation already
// satisfies the matching field here structurally, with no conversion.
type storeSet struct {
	channel    channelStore
	secret     secretStore
	share      shareStore
	userSecret userSecretStore
	state      stateStore
	transport  transportSender
}

// storeHandle is the integer identifier passed across the FFI boundary as
// the C user_data for a protocol instance's callbacks, in place of a Go
// pointer: Go pointers must never cross into C, since the Go runtime is free
// to move or collect the memory they refer to.
type storeHandle uintptr

var (
	storesMu   sync.Mutex
	stores     = make(map[storeHandle]*storeSet)
	nextHandle storeHandle
)

// registerStores assigns s a new, unique, non-zero handle and returns it.
// Handles are a monotonically increasing counter under storesMu — never
// derived from time or randomness, both of which are unavailable in this
// no-cgo binding.
func registerStores(s *storeSet) storeHandle {
	storesMu.Lock()
	defer storesMu.Unlock()
	nextHandle++
	h := nextHandle
	stores[h] = s
	return h
}

// lookupStores resolves a handle back to its *storeSet, as done on every
// incoming C callback invocation.
func lookupStores(h storeHandle) (*storeSet, bool) {
	storesMu.Lock()
	defer storesMu.Unlock()
	s, ok := stores[h]
	return s, ok
}

// releaseStores removes h's mapping once its protocol instance is torn down.
func releaseStores(h storeHandle) {
	storesMu.Lock()
	defer storesMu.Unlock()
	delete(stores, h)
}
