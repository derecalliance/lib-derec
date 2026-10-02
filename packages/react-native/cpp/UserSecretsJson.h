// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <jsi/jsi.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace derec {

/// `JSON.parse` of a UTF-8 buffer, through the runtime's own parser.
facebook::jsi::Value jsonParseUtf8(facebook::jsi::Runtime& rt, const uint8_t* bytes, size_t len);

/// A JS `UserSecrets` object as the `UserSecretsRecord` wire JSON
/// (`library/src/interop/ffi/protocol/stores.rs`).
std::vector<uint8_t> userSecretsToWire(facebook::jsi::Runtime& rt,
                                       const facebook::jsi::Object& src);

/// `UserSecretsRecord` wire JSON as the JS `UserSecrets` shape
/// `src/types.ts` declares.
facebook::jsi::Value userSecretsFromWire(facebook::jsi::Runtime& rt,
                                         const uint8_t* ptr,
                                         size_t len);

}  // namespace derec
