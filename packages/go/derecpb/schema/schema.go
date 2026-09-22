// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package schema carries the DeRec protocol schema so consumers can generate
// code from it without a lib-derec checkout.
package schema

import "embed"

// FileDescriptorSet is the complete import closure of the DeRec schema,
// including the well-known types it imports. It needs no include path to
// resolve.
//
//go:embed derec_descriptor.bin
var FileDescriptorSet []byte

// Proto holds the schema source. Every import in it is a bare filename, so
// the flat directory resolves the whole closure with one include root.
//
//go:embed proto
var Proto embed.FS
