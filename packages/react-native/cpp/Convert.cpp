// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "Convert.h"

#include <cstdlib>
#include <cstring>
#include <utility>

namespace derec {

OwnedBytes allocBytes(size_t len) {
  if (len == 0) {
    return OwnedBytes{nullptr, 0};
  }
  auto* ptr = static_cast<uint8_t*>(std::malloc(len));
  return OwnedBytes{ptr, ptr == nullptr ? 0 : len};
}

void freeBytes(uint8_t* ptr, size_t /*len*/) {
  if (ptr != nullptr) {
    std::free(ptr);
  }
}

std::vector<uint8_t> takeBuffer(DeRecBuffer& buffer) {
  std::vector<uint8_t> out;
  if (buffer.ptr != nullptr && buffer.len > 0) {
    out.assign(buffer.ptr, buffer.ptr + buffer.len);
  }
  derec_free_buffer(buffer.ptr, buffer.len);
  buffer.ptr = nullptr;
  buffer.len = 0;
  return out;
}

RestoreOutcome takeRestoreResult(DeRecProtocolRestoreResult& result) {
  RestoreOutcome out{result.error, {}, {}};
  try {
    out.events = takeBuffer(result.events_json);
    out.conflictingChannelIdsJson = takeBuffer(result.conflicting_channel_ids_json);
  } catch (...) {
    // `takeBuffer` clears a buffer only after releasing it, so whichever is
    // still set here was never released.
    derec_free_buffer(result.events_json.ptr, result.events_json.len);
    derec_free_buffer(result.conflicting_channel_ids_json.ptr,
                      result.conflicting_channel_ids_json.len);
    derec_free_error(&result.error);
    throw;
  }
  return out;
}

std::string takeString(char* owned) {
  if (owned == nullptr) {
    return {};
  }
  std::string out(owned);
  derec_free_string(owned);
  return out;
}

std::pair<std::string, std::string> errorName(int32_t category, int32_t code) {
  return {std::string(derec_error_category_name(category)),
          std::string(derec_error_code_name(code))};
}


// Minimal decoders for the wire's "bare JSON array/object of unsigned
// integers" convention (`versions_json`, `channel_ids_json`, the `bytes`
// field of a `ShareRecord` / `SecretValueRecord`). These are produced by
// `serde_json`'s default compact, whitespace-free output over a fixed,
// known shape, so a substring scan is sufficient and — critically — never
// routes a `u64` through a JS `number`, which cannot represent every value
// in that range exactly.

namespace {

/// Offset just past `"key":` in a flat, compact JSON object, or
/// `std::string::npos` if `key` is absent.
size_t fieldValueOffset(const std::string& json, const char* key) {
  std::string needle = std::string("\"") + key + "\":";
  size_t pos = json.find(needle);
  return pos == std::string::npos ? std::string::npos : pos + needle.size();
}

uint64_t parseUnsignedAt(const std::string& json, size_t pos) {
  uint64_t value = 0;
  while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
    value = value * 10 + static_cast<uint64_t>(json[pos] - '0');
    ++pos;
  }
  return value;
}

std::vector<uint8_t> parseByteArrayAt(const std::string& json, size_t pos) {
  std::vector<uint8_t> out;
  while (pos < json.size() && json[pos] != '[') ++pos;
  if (pos >= json.size()) return out;
  ++pos;
  while (pos < json.size() && json[pos] != ']') {
    if (json[pos] < '0' || json[pos] > '9') {
      ++pos;
      continue;
    }
    uint64_t value = 0;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
      value = value * 10 + static_cast<uint64_t>(json[pos] - '0');
      ++pos;
    }
    out.push_back(static_cast<uint8_t>(value));
  }
  return out;
}

/// The string inside `"key":"..."` in a flat, compact JSON object, or empty
/// if `key` is absent.
std::optional<std::string> quotedFieldValue(const std::string& json, const char* key) {
  size_t pos = fieldValueOffset(json, key);
  if (pos == std::string::npos || pos >= json.size() || json[pos] != '"') return std::nullopt;
  size_t end = json.find('"', pos + 1);
  if (end == std::string::npos) return std::nullopt;
  return json.substr(pos + 1, end - pos - 1);
}

}  // namespace

/// Parse a bare `[n, n, ...]` array of unsigned decimal integers.
std::vector<uint64_t> parseUnsignedJsonArray(const uint8_t* ptr, size_t len) {
  std::vector<uint64_t> out;
  size_t i = 0;
  while (i < len && ptr[i] != '[') ++i;
  if (i >= len) return out;
  ++i;
  while (i < len && ptr[i] != ']') {
    if (ptr[i] < '0' || ptr[i] > '9') {
      ++i;
      continue;
    }
    uint64_t value = 0;
    while (i < len && ptr[i] >= '0' && ptr[i] <= '9') {
      value = value * 10 + static_cast<uint64_t>(ptr[i] - '0');
      ++i;
    }
    out.push_back(value);
  }
  return out;
}

/// `{"kind":<n>,"bytes":[<n>,...]}` — the wire shape `SecretStore.save`
/// receives; `kind` is already carried as a separate FFI argument so only
/// `bytes` needs to be read back out.
std::vector<uint8_t> decodeSecretValueBytes(const uint8_t* ptr, size_t len) {
  std::string json(reinterpret_cast<const char*>(ptr), len);
  size_t pos = fieldValueOffset(json, "bytes");
  if (pos == std::string::npos) return {};
  return parseByteArrayAt(json, pos);
}

std::optional<DecodedShare> decodeShareRecord(const uint8_t* ptr, size_t len) {
  std::string json(reinterpret_cast<const char*>(ptr), len);
  std::optional<std::string> secretId = quotedFieldValue(json, "secret_id");
  size_t versionPos = fieldValueOffset(json, "version");
  size_t bytesPos = fieldValueOffset(json, "bytes");
  if (!secretId || versionPos == std::string::npos || bytesPos == std::string::npos) {
    return std::nullopt;
  }
  DecodedShare out;
  out.secretId = std::move(*secretId);
  out.version = static_cast<uint32_t>(parseUnsignedAt(json, versionPos));
  out.bytes = parseByteArrayAt(json, bytesPos);
  return out;
}

}  // namespace derec
