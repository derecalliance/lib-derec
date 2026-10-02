// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <jsi/jsi.h>

#include <vector>

extern "C" {
#include "derec_ffi.h"
}

namespace derec {

/// Convert a failed `DeRecError` into a JavaScript exception and throw it.
/// The thrown value carries the same field names the WASM bindings emit, so
/// application error handling ports between the JavaScript SDKs unchanged.
[[noreturn]] void throwDeRecError(facebook::jsi::Runtime& rt, const DeRecError& error);

/// As above, additionally attaching `channel_ids` — the JSON array of
/// decimal-string ids in `conflictingChannelIdsJson`, verbatim — when that
/// buffer is non-empty. Only `restore` produces one.
[[noreturn]] void throwDeRecError(facebook::jsi::Runtime& rt,
                                  const DeRecError& error,
                                  const std::vector<uint8_t>& conflictingChannelIdsJson);

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
/// A genuine `Uint8Array` holding a copy of `bytes`.
facebook::jsi::Value toUint8ArrayVal(facebook::jsi::Runtime& rt,
                                     const uint8_t* bytes,
                                     size_t len);
facebook::jsi::Value toUint8ArrayVal(facebook::jsi::Runtime& rt,
                                     const std::vector<uint8_t>& bytes);

uint64_t asU64(facebook::jsi::Runtime& rt, const facebook::jsi::Value& value);

/// Install every stateless FFI primitive as a host function on `host`, named
/// exactly after its C symbol.
void installPrimitives(facebook::jsi::Runtime& rt, facebook::jsi::Object& host);

}  // namespace derec
