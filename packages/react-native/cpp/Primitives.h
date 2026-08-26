// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <jsi/jsi.h>

extern "C" {
#include "derec_ffi.h"
}

namespace derec {

/// Convert a failed `DeRecError` into a JavaScript exception and throw it.
/// The thrown value carries the same field names the WASM bindings emit, so
/// application error handling ports between the JavaScript SDKs unchanged.
[[noreturn]] void throwDeRecError(facebook::jsi::Runtime& rt, const DeRecError& error);

/// Read an `ArrayBuffer` or typed-array argument as a byte range.
/// Returns `{nullptr, 0}` for `null`/`undefined`.
struct ByteView {
  const uint8_t* ptr;
  size_t len;
};
ByteView asBytes(facebook::jsi::Runtime& rt, const facebook::jsi::Value& value);

/// Copy `bytes` into a fresh `ArrayBuffer`.
facebook::jsi::Value toArrayBuffer(facebook::jsi::Runtime& rt,
                                    const uint8_t* bytes,
                                    size_t len);

/// Read a `bigint` or `number` argument as a `uint64_t`.
uint64_t asU64(facebook::jsi::Runtime& rt, const facebook::jsi::Value& value);

/// Install every stateless FFI primitive as a host function on `host`, named
/// exactly after its C symbol.
void installPrimitives(facebook::jsi::Runtime& rt, facebook::jsi::Object& host);

}  // namespace derec
