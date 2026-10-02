// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include "derec_ffi.h"
}

namespace derec {

/// A byte buffer allocated by this binding. Ownership passes to Rust across a
/// store callback out-parameter; Rust copies the contents and hands the
/// pointer back through the callback struct's `free_buffer`.
struct OwnedBytes {
  uint8_t* ptr;
  size_t len;
};

OwnedBytes allocBytes(size_t len);
void freeBytes(uint8_t* ptr, size_t len);

/// Copy `buffer` into a vector and release the Rust allocation.
std::vector<uint8_t> takeBuffer(DeRecBuffer& buffer);

/// Copy a Rust-owned C string and release it via `derec_free_string`.
std::string takeString(char* owned);

/// Every owned part of a `DeRecProtocolRestoreResult`, copied out with both
/// buffers already released. `error`'s strings stay owned: they are released
/// by `throwDeRecError`, as for every other result.
struct RestoreOutcome {
  DeRecError error;
  std::vector<uint8_t> events;
  std::vector<uint8_t> conflictingChannelIdsJson;
};

/// Releases both buffers of `result` on every path, including a failed copy.
RestoreOutcome takeRestoreResult(DeRecProtocolRestoreResult& result);

/// Resolve the `(category, code)` name pair from the crate's accessors.
std::pair<std::string, std::string> errorName(int32_t category, int32_t code);

// Decoders for the payloads Rust hands the store callbacks.
// They hold no `jsi` state, so the standalone test harness exercises them
// against the real crate.

/// Parse a bare `[n, n, ...]` array of unsigned decimal integers.
std::vector<uint64_t> parseUnsignedJsonArray(const uint8_t* ptr, size_t len);

/// The `bytes` field of a `{"kind":<n>,"bytes":[<n>,...]}` `SecretValueRecord`.
std::vector<uint8_t> decodeSecretValueBytes(const uint8_t* ptr, size_t len);

/// A `ShareRecord` as `ShareStore.save` receives it. `secretId` is the
/// record's own `secret_id`, kept as the decimal string Rust wrote.
struct DecodedShare {
  std::string secretId;
  uint32_t version;
  std::vector<uint8_t> bytes;
};

/// Decode `{"secret_id":"...","version":<n>,"bytes":[<n>,...]}`. Empty when
/// any of the three fields is absent.
std::optional<DecodedShare> decodeShareRecord(const uint8_t* ptr, size_t len);

}  // namespace derec
