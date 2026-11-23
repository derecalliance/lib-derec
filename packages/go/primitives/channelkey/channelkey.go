// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package channelkey derives channel keys forward along a channel's key chain.
package channelkey

import "github.com/derecalliance/lib-derec/packages/go/internal/native"

// Derive returns the 32-byte channel key at toEpoch, derived forward from key,
// the channel key at epoch.
//
// A toEpoch below epoch, or more than 512 above it, is refused as invalid
// input.
func Derive(key []byte, epoch, toEpoch uint32) ([]byte, error) {
	return native.DeriveChannelKey(key, epoch, toEpoch)
}
