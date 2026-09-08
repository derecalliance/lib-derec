// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "StoreCallbacks.h"

#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "Convert.h"
#include "Primitives.h"

using namespace facebook;

namespace derec {

namespace {

// Struct-layout guards. Every field is pointer-sized, so a struct's
// size is exactly its member count times `sizeof(void*)` on every ABI this
// binding targets; a mismatch means `derec_ffi.h` grew or shrank a field
// this file has not been updated to match.

static_assert(sizeof(ChannelStoreCallbacks) == 9 * sizeof(void*),
              "ChannelStoreCallbacks layout changed; update the bindings");
static_assert(sizeof(SecretStoreCallbacks) == 5 * sizeof(void*),
              "SecretStoreCallbacks layout changed; update the bindings");
static_assert(sizeof(ShareStoreCallbacks) == 8 * sizeof(void*),
              "ShareStoreCallbacks layout changed; update the bindings");
static_assert(sizeof(UserSecretStoreCallbacks) == 5 * sizeof(void*),
              "UserSecretStoreCallbacks layout changed; update the bindings");
static_assert(sizeof(StateStoreCallbacks) == 6 * sizeof(void*),
              "StateStoreCallbacks layout changed; update the bindings");
static_assert(sizeof(TransportCallbacks) == 2 * sizeof(void*),
              "TransportCallbacks layout changed; update the bindings");

/// Write `bytes` into a store callback's out-parameters. Returns `false`
/// only when the allocation itself failed; a genuinely empty `bytes` still
/// returns `true` with `*outPtr = nullptr, *outLen = 0` — that is the
/// documented "no payload" encoding, not an error. Callers MUST map a
/// `false` return to `kBackendFailure` rather than the success code they
/// were about to return: silently degrading an allocation failure into an
/// empty successful payload would make an out-of-memory condition
/// indistinguishable from a legitimate "not found", which can corrupt a
/// secret recovery exactly as a fabricated `1` would.
///
/// The buffer is allocated by this binding; Rust copies the contents and
/// returns the pointer through the same struct's `free_buffer`, so no
/// cross-allocator free can occur.
bool writeOut(const std::vector<uint8_t>& bytes, uint8_t** outPtr, size_t* outLen) {
  if (bytes.empty()) {
    *outPtr = nullptr;
    *outLen = 0;
    return true;
  }
  OwnedBytes owned = allocBytes(bytes.size());
  if (owned.ptr == nullptr) {
    *outPtr = nullptr;
    *outLen = 0;
    return false;
  }
  std::memcpy(owned.ptr, bytes.data(), bytes.size());
  *outPtr = owned.ptr;
  *outLen = owned.len;
  return true;
}

/// A decimal-string `jsi::Value`, matching every id parameter in
/// `src/types.ts` (`secretId`, `channelId`, `replicaId` are `string`, not
/// `bigint`, so real ids beyond `Number.MAX_SAFE_INTEGER` survive JS number
/// handling intact).
jsi::Value idVal(jsi::Runtime& rt, uint64_t id) {
  return jsi::Value(rt, jsi::String::createFromUtf8(rt, std::to_string(id)));
}

/// Build a genuine `Uint8Array` (not a bare `ArrayBuffer`) — every store
/// interface types its byte payloads as `Uint8Array`, and application code
/// is entitled to index or slice it directly.
jsi::Value toUint8ArrayVal(jsi::Runtime& rt, const uint8_t* bytes, size_t len) {
  jsi::Uint8Array arr(rt, len);
  if (len > 0 && bytes != nullptr) {
    jsi::ArrayBuffer buffer = arr.buffer(rt);
    std::memcpy(buffer.data(rt), bytes, len);
  }
  return jsi::Value(rt, std::move(arr));
}

jsi::Value toUint8ArrayVal(jsi::Runtime& rt, const std::vector<uint8_t>& bytes) {
  return toUint8ArrayVal(rt, bytes.data(), bytes.size());
}

// Minimal decoders for the wire's "bare JSON array/object of unsigned
// integers" convention (`versions_json`, `channel_ids_json`, the `bytes`
// field of a `ShareRecord` / `SecretValueRecord`). These are produced by
// `serde_json`'s default compact, whitespace-free output over a fixed,
// known shape, so a substring scan is sufficient and — critically — never
// routes a `u64` through a JS `number`, which cannot represent every value
// in that range exactly.

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

/// `{"kind":<n>,"bytes":[<n>,...]}` — the wire shape `SecretStore.save`
/// receives; `kind` is already carried as a separate FFI argument so only
/// `bytes` needs to be read back out.
std::vector<uint8_t> decodeSecretValueBytes(const uint8_t* ptr, size_t len) {
  std::string json(reinterpret_cast<const char*>(ptr), len);
  size_t pos = fieldValueOffset(json, "bytes");
  if (pos == std::string::npos) return {};
  return parseByteArrayAt(json, pos);
}

/// `{"secret_id":"...","version":<n>,"bytes":[<n>,...]}` — the wire shape
/// `ShareStore.save` receives. `secret_id` duplicates the FFI's own
/// `secret_id` argument, so only `version` and `bytes` are decoded.
struct DecodedShare {
  uint32_t version;
  std::vector<uint8_t> bytes;
};

DecodedShare decodeShareRecord(const uint8_t* ptr, size_t len) {
  std::string json(reinterpret_cast<const char*>(ptr), len);
  size_t versionPos = fieldValueOffset(json, "version");
  size_t bytesPos = fieldValueOffset(json, "bytes");
  DecodedShare out{};
  out.version =
      versionPos == std::string::npos ? 0 : static_cast<uint32_t>(parseUnsignedAt(json, versionPos));
  out.bytes = bytesPos == std::string::npos ? std::vector<uint8_t>{} : parseByteArrayAt(json, bytesPos);
  return out;
}

/// True only for a non-empty run of ASCII decimal digits.
///
/// Every `u64` id crosses this boundary as a decimal string, and the wire
/// JSON built below splices those strings in directly — as a bare integer
/// literal for a channel id, and inside quotes for a secret id — rather than
/// routing them through a JS number, which loses precision above 2^53. That
/// splice is only sound if the string really is nothing but digits: any other
/// content would produce malformed JSON, or inject application-chosen
/// structure into the document Rust then deserialises. The store contract
/// already says these are `u64`-as-decimal-string, so anything else is a
/// malformed store return, not a value to interpret.
bool isDecimalDigits(const std::string& text) {
  if (text.empty()) {
    return false;
  }
  for (char c : text) {
    if (c < '0' || c > '9') {
      return false;
    }
  }
  return true;
}

/// Append a byte range as a bare JSON array of decimal integers.
void appendByteArrayJson(std::string& text, const uint8_t* bytes, size_t len) {
  text += '[';
  for (size_t i = 0; i < len; ++i) {
    if (i != 0) text += ',';
    text += std::to_string(bytes[i]);
  }
  text += ']';
}

std::vector<uint8_t> secretValueRecordJson(uint32_t kind, const uint8_t* bytes, size_t len) {
  std::string text = "{\"kind\":" + std::to_string(kind) + ",\"bytes\":";
  appendByteArrayJson(text, bytes, len);
  text += '}';
  return std::vector<uint8_t>(text.begin(), text.end());
}

jsi::Array u32VectorToJsArray(jsi::Runtime& rt, const std::vector<uint32_t>& values) {
  jsi::Array arr(rt, values.size());
  for (size_t i = 0; i < values.size(); ++i) {
    arr.setValueAtIndex(rt, i, jsi::Value(static_cast<int>(values[i])));
  }
  return arr;
}

jsi::Array u64VectorToJsStringArray(jsi::Runtime& rt, const std::vector<uint64_t>& ids) {
  jsi::Array arr(rt, ids.size());
  for (size_t i = 0; i < ids.size(); ++i) {
    arr.setValueAtIndex(rt, i, jsi::Value(rt, jsi::String::createFromUtf8(rt, std::to_string(ids[i]))));
  }
  return arr;
}

// `ResultConverter`s. Each encodes a settled JS value into the private
// `CallResult.bytes` payload the calling extern "C" function decodes once
// `callSync` returns — a channel this file controls end to end, so each
// converter is free to define its own encoding.

/// Load-family convention: `null`/`undefined` is "absent" (code `1`); any
/// other value is read as bytes and passed through unmodified (code `0`).
/// Valid whenever the wire's out-parameter bytes are exactly what the JS
/// store returns, with no re-encoding needed.
CallResult toCallResult(jsi::Runtime& rt, const jsi::Value& value) {
  if (value.isNull() || value.isUndefined()) {
    return CallResult{1, {}};
  }
  ByteView view = asBytes(rt, value);
  return CallResult{0, std::vector<uint8_t>(view.ptr, view.ptr + view.len)};
}

/// For `save`/`remove`/`link`/`send`-family methods: the resolved value is
/// `undefined` (a `Promise<void>`) and carries no information. Success is
/// always code `0`; only a rejection (handled by `settleFromPromise`'s
/// `onErr`) becomes a backend failure. Never routes a value through the
/// load-family "null means absent" convention.
CallResult toVoidResult(jsi::Runtime&, const jsi::Value&) { return CallResult{0, {}}; }

/// Boolean-shaped outputs (`ChannelStore.remove`, `StateStore.remove`):
/// encode `true` as one byte, `false` as zero bytes. The calling function
/// derives `out_existed` / `out_removed` from `result.bytes.empty()`.
///
/// A non-boolean is a malformed store return, not a `false`: reporting it as
/// `false` would tell the protocol that a record it just asked to delete was
/// never there, which is a claim about storage this binding has no grounds to
/// make. It is a backend failure.
CallResult toBoolResult(jsi::Runtime&, const jsi::Value& value) {
  if (!value.isBool()) {
    return CallResult{kBackendFailure, {}};
  }
  return CallResult{0, value.asBool() ? std::vector<uint8_t>{1} : std::vector<uint8_t>{}};
}

/// `ShareStore.latestVersion(): Promise<number | null>`. Absent (`null`)
/// encodes as zero bytes; a version encodes as 4 little-endian bytes so the
/// calling function can rebuild `out_has_version` / `out_version`.
CallResult toVersionResult(jsi::Runtime&, const jsi::Value& value) {
  if (value.isNull() || value.isUndefined()) {
    return CallResult{0, {}};
  }
  auto version = static_cast<uint32_t>(value.asNumber());
  std::vector<uint8_t> bytes(4);
  bytes[0] = static_cast<uint8_t>(version & 0xFF);
  bytes[1] = static_cast<uint8_t>((version >> 8) & 0xFF);
  bytes[2] = static_cast<uint8_t>((version >> 16) & 0xFF);
  bytes[3] = static_cast<uint8_t>((version >> 24) & 0xFF);
  return CallResult{0, bytes};
}

/// `ChannelStore.linkedChannels(): Promise<string[]>`. Rust decodes this as
/// a bare JSON array of `u64`; an empty JS array is written as literally
/// empty bytes so Rust's own "nothing linked" fallback (defaulting to the
/// channel itself) applies, matching what an absent record would produce.
///
/// A non-array return is a backend failure. Reporting it as the empty result
/// would trigger that same fallback and silently narrow the set of channels a
/// share is linked to, which is a protocol-visible outcome invented by the
/// binding rather than read from storage.
CallResult toLinkedChannelsResult(jsi::Runtime& rt, const jsi::Value& value) {
  if (!value.isObject()) {
    return CallResult{kBackendFailure, {}};
  }
  jsi::Array arr = value.asObject(rt).asArray(rt);
  size_t n = arr.size(rt);
  if (n == 0) {
    return CallResult{0, {}};
  }
  std::string text = "[";
  for (size_t i = 0; i < n; ++i) {
    if (i != 0) text += ',';
    // Each element is a decimal-digit channel id string — already a valid
    // bare JSON integer literal, so splice it in verbatim rather than
    // routing it through a JS number, which loses precision above 2^53.
    std::string channelId = arr.getValueAtIndex(rt, i).asString(rt).utf8(rt);
    if (!isDecimalDigits(channelId)) {
      return CallResult{kBackendFailure, {}};
    }
    text += channelId;
  }
  text += ']';
  return CallResult{0, std::vector<uint8_t>(text.begin(), text.end())};
}

/// `ShareStore.{load,loadMany,loadAll}(): Promise<Share[]>`. Encodes the
/// resolved array as the wire's `Vec<ShareRecord>` JSON.
///
/// A non-array return is a backend failure, never an empty list: "zero
/// shares, successfully" is exactly the report that turns an unreadable store
/// into a failed recovery with no error to trace it back to.
CallResult toShareListResult(jsi::Runtime& rt, const jsi::Value& value) {
  if (!value.isObject()) {
    return CallResult{kBackendFailure, {}};
  }
  jsi::Array arr = value.asObject(rt).asArray(rt);
  size_t n = arr.size(rt);
  std::string text = "[";
  for (size_t i = 0; i < n; ++i) {
    if (i != 0) text += ',';
    jsi::Object entry = arr.getValueAtIndex(rt, i).asObject(rt);
    std::string secretIdStr = entry.getProperty(rt, "secretId").asString(rt).utf8(rt);
    if (!isDecimalDigits(secretIdStr)) {
      return CallResult{kBackendFailure, {}};
    }
    auto version = static_cast<uint32_t>(entry.getProperty(rt, "version").asNumber());
    ByteView bytes = asBytes(rt, entry.getProperty(rt, "bytes"));
    text += "{\"secret_id\":\"" + secretIdStr + "\",\"version\":" + std::to_string(version) +
            ",\"bytes\":";
    appendByteArrayJson(text, bytes.ptr, bytes.len);
    text += '}';
  }
  text += ']';
  return CallResult{0, std::vector<uint8_t>(text.begin(), text.end())};
}

/// `SecretStore.load(): Promise<Uint8Array | null | undefined>`. `kind` is
/// captured by value so the returned bytes can be re-wrapped as the wire's
/// `SecretValueRecord`, whose `kind` field the FFI struct's `load` does not
/// otherwise carry back out.
ResultConverter makeSecretLoadResult(uint32_t kind) {
  return [kind](jsi::Runtime& rt, const jsi::Value& value) -> CallResult {
    if (value.isNull() || value.isUndefined()) {
      return CallResult{1, {}};
    }
    ByteView bytes = asBytes(rt, value);
    return CallResult{0, secretValueRecordJson(kind, bytes.ptr, bytes.len)};
  };
}

/// `StateStore.loadAll(): Promise<Uint8Array[]>`. Each element is already
/// the exact item-JSON blob the wire expects; splice the raw bytes into an
/// array rather than re-parsing and re-serialising them.
///
/// A non-array return is a backend failure, never an empty list: an empty
/// list is a truthful claim that no state was persisted, and reporting it for
/// a store that simply did not answer correctly would let a restore silently
/// come up blank.
CallResult toStateLoadAllResult(jsi::Runtime& rt, const jsi::Value& value) {
  if (!value.isObject()) {
    return CallResult{kBackendFailure, {}};
  }
  jsi::Array arr = value.asObject(rt).asArray(rt);
  size_t n = arr.size(rt);
  std::string text = "[";
  for (size_t i = 0; i < n; ++i) {
    if (i != 0) text += ',';
    ByteView bv = asBytes(rt, arr.getValueAtIndex(rt, i));
    text.append(reinterpret_cast<const char*>(bv.ptr), bv.len);
  }
  text += ']';
  return CallResult{0, std::vector<uint8_t>(text.begin(), text.end())};
}

// `UserSecrets` JSON <-> JS object conversion. Unlike the flat integer-only
// records above, `UserSecrets` carries application-controlled `name` /
// `description` strings, so building or reading its wire JSON goes through
// the runtime's own `JSON.parse` / `JSON.stringify` rather than a hand-rolled
// scanner — the only place in this file that needs real string escaping.

jsi::Value jsonParseUtf8(jsi::Runtime& rt, const uint8_t* bytes, size_t len) {
  jsi::Object json = rt.global().getPropertyAsObject(rt, "JSON");
  jsi::Function parse = json.getPropertyAsFunction(rt, "parse");
  std::string text(reinterpret_cast<const char*>(bytes), len);
  return parse.call(rt, jsi::Value(rt, jsi::String::createFromUtf8(rt, text)));
}

std::vector<uint8_t> jsonStringifyToUtf8(jsi::Runtime& rt, const jsi::Value& value) {
  jsi::Object json = rt.global().getPropertyAsObject(rt, "JSON");
  jsi::Function stringify = json.getPropertyAsFunction(rt, "stringify");
  jsi::Value result = stringify.call(rt, value);
  std::string text = result.asString(rt).utf8(rt);
  return std::vector<uint8_t>(text.begin(), text.end());
}

jsi::Array bytesToNumberArray(jsi::Runtime& rt, ByteView view) {
  jsi::Array arr(rt, view.len);
  for (size_t i = 0; i < view.len; ++i) {
    arr.setValueAtIndex(rt, i, jsi::Value(static_cast<int>(view.ptr[i])));
  }
  return arr;
}

std::vector<uint8_t> numberArrayToBytes(jsi::Runtime& rt, jsi::Array arr) {
  size_t n = arr.size(rt);
  std::vector<uint8_t> out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    out.push_back(static_cast<uint8_t>(arr.getValueAtIndex(rt, i).asNumber()));
  }
  return out;
}

/// `UserSecretStore.loadLatest(): Promise<UserSecrets | null | undefined>`.
CallResult toUserSecretsResult(jsi::Runtime& rt, const jsi::Value& value) {
  if (value.isNull() || value.isUndefined()) {
    return CallResult{1, {}};
  }
  jsi::Object src = value.asObject(rt);
  jsi::Object wire(rt);
  wire.setProperty(rt, "version", jsi::Value(rt, src.getProperty(rt, "version")));
  jsi::Array srcSecrets = src.getProperty(rt, "secrets").asObject(rt).asArray(rt);
  size_t n = srcSecrets.size(rt);
  jsi::Array wireSecrets(rt, n);
  for (size_t i = 0; i < n; ++i) {
    jsi::Object entry = srcSecrets.getValueAtIndex(rt, i).asObject(rt);
    jsi::Object wireEntry(rt);
    wireEntry.setProperty(rt, "id", jsi::Value(rt, bytesToNumberArray(rt, asBytes(rt, entry.getProperty(rt, "id")))));
    wireEntry.setProperty(rt, "name", jsi::Value(rt, entry.getProperty(rt, "name")));
    wireEntry.setProperty(
        rt, "data", jsi::Value(rt, bytesToNumberArray(rt, asBytes(rt, entry.getProperty(rt, "data")))));
    wireSecrets.setValueAtIndex(rt, i, jsi::Value(rt, wireEntry));
  }
  wire.setProperty(rt, "secrets", jsi::Value(rt, wireSecrets));
  if (src.hasProperty(rt, "description")) {
    jsi::Value description = src.getProperty(rt, "description");
    if (!description.isUndefined()) {
      wire.setProperty(rt, "description", description);
    }
  }
  return CallResult{0, jsonStringifyToUtf8(rt, jsi::Value(rt, wire))};
}

/// Decode `UserSecretStore.saveLatest`'s incoming wire JSON into the JS
/// `UserSecrets` shape `src/types.ts` declares.
jsi::Value buildUserSecretsFromWire(jsi::Runtime& rt, const uint8_t* ptr, size_t len) {
  jsi::Value parsed = jsonParseUtf8(rt, ptr, len);
  jsi::Object src = parsed.asObject(rt);
  jsi::Object out(rt);
  out.setProperty(rt, "version", jsi::Value(rt, src.getProperty(rt, "version")));
  jsi::Array srcSecrets = src.getProperty(rt, "secrets").asObject(rt).asArray(rt);
  size_t n = srcSecrets.size(rt);
  jsi::Array outSecrets(rt, n);
  for (size_t i = 0; i < n; ++i) {
    jsi::Object entry = srcSecrets.getValueAtIndex(rt, i).asObject(rt);
    jsi::Object outEntry(rt);
    std::vector<uint8_t> idBytes =
        numberArrayToBytes(rt, entry.getProperty(rt, "id").asObject(rt).asArray(rt));
    std::vector<uint8_t> dataBytes =
        numberArrayToBytes(rt, entry.getProperty(rt, "data").asObject(rt).asArray(rt));
    outEntry.setProperty(rt, "id", toUint8ArrayVal(rt, idBytes));
    outEntry.setProperty(rt, "name", jsi::Value(rt, entry.getProperty(rt, "name")));
    outEntry.setProperty(rt, "data", toUint8ArrayVal(rt, dataBytes));
    outSecrets.setValueAtIndex(rt, i, jsi::Value(rt, outEntry));
  }
  out.setProperty(rt, "secrets", jsi::Value(rt, outSecrets));
  if (src.hasProperty(rt, "description")) {
    jsi::Value description = src.getProperty(rt, "description");
    if (!description.isUndefined()) {
      out.setProperty(rt, "description", description);
    }
  }
  return jsi::Value(rt, out);
}

/// Releases a buffer this binding handed to Rust through an out-parameter.
/// Shared by every struct's `free_buffer` field — the signature is
/// identical across all six.
extern "C" void storeFreeBuffer(void* /*userData*/, uint8_t* ptr, size_t len) { freeBytes(ptr, len); }

/// `ChannelStore.load(secretId, channelId, replicaId) -> Uint8Array | null`
extern "C" int32_t channelStoreLoad(void* userData, uint64_t secretId, uint64_t channelId,
                                     uint64_t replicaId, uint8_t** outPtr, size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result = keepAlive->bridge().callSync(
      [keepAlive, secretId, channelId, replicaId](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->channelStore();
        auto method = store->getPropertyAsFunction(rt, "load");
        jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, channelId),
                                                  idVal(rt, replicaId));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toCallResult);
      });

  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// `ChannelStore.save(secretId, channelId, replicaId, bytes) -> void`
extern "C" int32_t channelStoreSave(void* userData, uint64_t secretId, uint64_t channelId,
                                     uint64_t replicaId, const uint8_t* bytes, size_t len) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint8_t> payload(bytes, bytes + len);
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId, channelId, replicaId,
                                                payload](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->channelStore();
    auto method = store->getPropertyAsFunction(rt, "save");
    jsi::Value promise =
        method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, channelId), idVal(rt, replicaId),
                             toUint8ArrayVal(rt, payload));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVoidResult);
  });
  return result.code;
}

/// `ChannelStore.remove(secretId, channelId, replicaId) -> boolean`
extern "C" int32_t channelStoreRemove(void* userData, uint64_t secretId, uint64_t channelId,
                                       uint64_t replicaId, uint32_t* outExisted) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result = keepAlive->bridge().callSync(
      [keepAlive, secretId, channelId, replicaId](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->channelStore();
        auto method = store->getPropertyAsFunction(rt, "remove");
        jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, channelId),
                                                  idVal(rt, replicaId));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toBoolResult);
      });
  *outExisted = result.bytes.empty() ? 0 : 1;
  return result.code;
}

/// `ChannelStore.listHelpers(secretId, filter) -> Uint8Array | null`
///
/// `filter` arrives as JSON and is handed to JavaScript as a plain object —
/// see `ChannelFilter` in the SDK's types. The buffer is owned by the core and
/// valid only for this call, so it is parsed before the promise is awaited.
extern "C" int32_t channelStoreListHelpers(void* userData, uint64_t secretId, const uint8_t* filter,
                                            size_t filterLen, uint8_t** outPtr, size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint8_t> filterJson(filter, filter + filterLen);
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId, filterJson](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->channelStore();
    auto method = store->getPropertyAsFunction(rt, "listHelpers");
    // Ids arrive as decimal strings — the core encodes them that way because
    // `JSON.parse` cannot hold a u64; see `encode_filter` in
    // `interop/ffi/protocol/stores.rs`.
    jsi::Value filterVal = filterJson.empty()
                               ? jsi::Value(jsi::Object(rt))
                               : jsonParseUtf8(rt, filterJson.data(), filterJson.size());
    jsi::Value promise =
        method.callWithThis(rt, *store, idVal(rt, secretId), std::move(filterVal));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toCallResult);
  });
  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// `ChannelStore.listReplicas(secretId, filter) -> Uint8Array | null`
///
/// `filter` arrives as JSON and is handed to JavaScript as a plain object —
/// see `ChannelFilter` in the SDK's types. The buffer is owned by the core and
/// valid only for this call, so it is parsed before the promise is awaited.
extern "C" int32_t channelStoreListReplicas(void* userData, uint64_t secretId, const uint8_t* filter,
                                            size_t filterLen, uint8_t** outPtr, size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint8_t> filterJson(filter, filter + filterLen);
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId, filterJson](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->channelStore();
    auto method = store->getPropertyAsFunction(rt, "listReplicas");
    // Ids arrive as decimal strings — the core encodes them that way because
    // `JSON.parse` cannot hold a u64; see `encode_filter` in
    // `interop/ffi/protocol/stores.rs`.
    jsi::Value filterVal = filterJson.empty()
                               ? jsi::Value(jsi::Object(rt))
                               : jsonParseUtf8(rt, filterJson.data(), filterJson.size());
    jsi::Value promise =
        method.callWithThis(rt, *store, idVal(rt, secretId), std::move(filterVal));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toCallResult);
  });
  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// `ChannelStore.linkChannel(secretId, channelId, linkedChannelId) -> void`
extern "C" int32_t channelStoreLinkChannel(void* userData, uint64_t secretId, uint64_t a, uint64_t b) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result =
      keepAlive->bridge().callSync([keepAlive, secretId, a, b](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->channelStore();
        auto method = store->getPropertyAsFunction(rt, "linkChannel");
        jsi::Value promise =
            method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, a), idVal(rt, b));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVoidResult);
      });
  return result.code;
}

/// `ChannelStore.linkedChannels(secretId, channelId) -> string[]`
extern "C" int32_t channelStoreLinkedChannels(void* userData, uint64_t secretId, uint64_t channelId,
                                               uint8_t** outPtr, size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result =
      keepAlive->bridge().callSync([keepAlive, secretId, channelId](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->channelStore();
        auto method = store->getPropertyAsFunction(rt, "linkedChannels");
        jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, channelId));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toLinkedChannelsResult);
      });
  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// `SecretStore.load(secretId, channelId, kind) -> Uint8Array | null`
extern "C" int32_t secretStoreLoad(void* userData, uint64_t secretId, uint64_t channelId, uint32_t kind,
                                    uint8_t** outPtr, size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result = keepAlive->bridge().callSync(
      [keepAlive, secretId, channelId, kind](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->secretStore();
        auto method = store->getPropertyAsFunction(rt, "load");
        jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, channelId),
                                                  jsi::Value(static_cast<int>(kind)));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), makeSecretLoadResult(kind));
      });
  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// `SecretStore.save(secretId, channelId, kind, value) -> void`
extern "C" int32_t secretStoreSave(void* userData, uint64_t secretId, uint64_t channelId, uint32_t kind,
                                    const uint8_t* bytes, size_t len) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint8_t> payload = decodeSecretValueBytes(bytes, len);
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId, channelId, kind,
                                                payload](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->secretStore();
    auto method = store->getPropertyAsFunction(rt, "save");
    jsi::Value promise =
        method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, channelId),
                             jsi::Value(static_cast<int>(kind)), toUint8ArrayVal(rt, payload));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVoidResult);
  });
  return result.code;
}

/// `SecretStore.remove(secretId, channelId, kind) -> void`
extern "C" int32_t secretStoreRemove(void* userData, uint64_t secretId, uint64_t channelId,
                                      uint32_t kind) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result = keepAlive->bridge().callSync(
      [keepAlive, secretId, channelId, kind](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->secretStore();
        auto method = store->getPropertyAsFunction(rt, "remove");
        jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, channelId),
                                                  jsi::Value(static_cast<int>(kind)));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVoidResult);
      });
  return result.code;
}

/// `ShareStore.load(secretId, channelId, versions) -> Share[]`
extern "C" int32_t shareStoreLoad(void* userData, uint64_t secretId, uint64_t channelId,
                                   const uint8_t* versionsJsonPtr, size_t versionsJsonLen,
                                   uint8_t** outPtr, size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint64_t> raw = parseUnsignedJsonArray(versionsJsonPtr, versionsJsonLen);
  std::vector<uint32_t> versions(raw.begin(), raw.end());
  CallResult result = keepAlive->bridge().callSync(
      [keepAlive, secretId, channelId, versions](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->shareStore();
        auto method = store->getPropertyAsFunction(rt, "load");
        jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, channelId),
                                                  jsi::Value(rt, u32VectorToJsArray(rt, versions)));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toShareListResult);
      });
  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// `ShareStore.loadMany(secretId, channelIds, versions) -> Share[]`
extern "C" int32_t shareStoreLoadMany(void* userData, uint64_t secretId, const uint8_t* channelIdsJsonPtr,
                                       size_t channelIdsJsonLen, const uint8_t* versionsJsonPtr,
                                       size_t versionsJsonLen, uint8_t** outPtr, size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint64_t> channelIds = parseUnsignedJsonArray(channelIdsJsonPtr, channelIdsJsonLen);
  std::vector<uint64_t> rawVersions = parseUnsignedJsonArray(versionsJsonPtr, versionsJsonLen);
  std::vector<uint32_t> versions(rawVersions.begin(), rawVersions.end());
  CallResult result = keepAlive->bridge().callSync(
      [keepAlive, secretId, channelIds, versions](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->shareStore();
        auto method = store->getPropertyAsFunction(rt, "loadMany");
        jsi::Value promise =
            method.callWithThis(rt, *store, idVal(rt, secretId),
                                 jsi::Value(rt, u64VectorToJsStringArray(rt, channelIds)),
                                 jsi::Value(rt, u32VectorToJsArray(rt, versions)));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toShareListResult);
      });
  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// `ShareStore.loadAll(secretId, channelIds) -> Share[]`
extern "C" int32_t shareStoreLoadAll(void* userData, uint64_t secretId, const uint8_t* channelIdsJsonPtr,
                                      size_t channelIdsJsonLen, uint8_t** outPtr, size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint64_t> channelIds = parseUnsignedJsonArray(channelIdsJsonPtr, channelIdsJsonLen);
  CallResult result = keepAlive->bridge().callSync(
      [keepAlive, secretId, channelIds](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->shareStore();
        auto method = store->getPropertyAsFunction(rt, "loadAll");
        jsi::Value promise = method.callWithThis(
            rt, *store, idVal(rt, secretId), jsi::Value(rt, u64VectorToJsStringArray(rt, channelIds)));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toShareListResult);
      });
  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// `ShareStore.latestVersion(secretId) -> number | null`
extern "C" int32_t shareStoreLatestVersion(void* userData, uint64_t secretId, uint32_t* outHasVersion,
                                            uint32_t* outVersion) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->shareStore();
    auto method = store->getPropertyAsFunction(rt, "latestVersion");
    jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVersionResult);
  });
  if (result.bytes.size() == 4) {
    *outHasVersion = 1;
    *outVersion = static_cast<uint32_t>(result.bytes[0]) | (static_cast<uint32_t>(result.bytes[1]) << 8) |
                  (static_cast<uint32_t>(result.bytes[2]) << 16) |
                  (static_cast<uint32_t>(result.bytes[3]) << 24);
  } else {
    *outHasVersion = 0;
    *outVersion = 0;
  }
  return result.code;
}

/// `ShareStore.save(secretId, channelId, share) -> void`
extern "C" int32_t shareStoreSave(void* userData, uint64_t secretId, uint64_t channelId,
                                   const uint8_t* shareJsonPtr, size_t shareJsonLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  DecodedShare decoded = decodeShareRecord(shareJsonPtr, shareJsonLen);
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId, channelId,
                                                decoded](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->shareStore();
    auto method = store->getPropertyAsFunction(rt, "save");
    jsi::Object shareObj(rt);
    shareObj.setProperty(rt, "secretId", idVal(rt, secretId));
    shareObj.setProperty(rt, "version", jsi::Value(static_cast<int>(decoded.version)));
    shareObj.setProperty(rt, "bytes", toUint8ArrayVal(rt, decoded.bytes));
    jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, channelId),
                                              jsi::Value(rt, shareObj));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVoidResult);
  });
  return result.code;
}

/// `ShareStore.removeChannel(secretId, channelId) -> void`
extern "C" int32_t shareStoreRemoveChannel(void* userData, uint64_t secretId, uint64_t channelId) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result =
      keepAlive->bridge().callSync([keepAlive, secretId, channelId](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->shareStore();
        auto method = store->getPropertyAsFunction(rt, "removeChannel");
        jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), idVal(rt, channelId));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVoidResult);
      });
  return result.code;
}

/// `UserSecretStore.loadLatest(secretId) -> UserSecrets | null`
extern "C" int32_t userSecretStoreLoadLatest(void* userData, uint64_t secretId, uint8_t** outPtr,
                                              size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->userSecretStore();
    auto method = store->getPropertyAsFunction(rt, "loadLatest");
    jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toUserSecretsResult);
  });
  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// `UserSecretStore.saveLatest(secretId, value) -> void`
extern "C" int32_t userSecretStoreSaveLatest(void* userData, uint64_t secretId,
                                              const uint8_t* valueJsonPtr, size_t valueJsonLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint8_t> payload(valueJsonPtr, valueJsonPtr + valueJsonLen);
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId, payload](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->userSecretStore();
    auto method = store->getPropertyAsFunction(rt, "saveLatest");
    jsi::Value userSecrets = buildUserSecretsFromWire(rt, payload.data(), payload.size());
    jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), std::move(userSecrets));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVoidResult);
  });
  return result.code;
}

/// `UserSecretStore.remove(secretId) -> void`
extern "C" int32_t userSecretStoreRemove(void* userData, uint64_t secretId) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->userSecretStore();
    auto method = store->getPropertyAsFunction(rt, "remove");
    jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVoidResult);
  });
  return result.code;
}

/// `StateStore.save(secretId, itemJson) -> void`
extern "C" int32_t stateStoreSave(void* userData, uint64_t secretId, const uint8_t* itemJsonPtr,
                                   size_t itemJsonLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint8_t> payload(itemJsonPtr, itemJsonPtr + itemJsonLen);
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId, payload](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->stateStore();
    auto method = store->getPropertyAsFunction(rt, "save");
    jsi::Value promise =
        method.callWithThis(rt, *store, idVal(rt, secretId), toUint8ArrayVal(rt, payload));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVoidResult);
  });
  return result.code;
}

/// `StateStore.load(secretId, keyJson) -> Uint8Array | null`
extern "C" int32_t stateStoreLoad(void* userData, uint64_t secretId, const uint8_t* keyJsonPtr,
                                   size_t keyJsonLen, uint8_t** outPtr, size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint8_t> key(keyJsonPtr, keyJsonPtr + keyJsonLen);
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId, key](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->stateStore();
    auto method = store->getPropertyAsFunction(rt, "load");
    jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), toUint8ArrayVal(rt, key));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toCallResult);
  });
  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// `StateStore.remove(secretId, keyJson) -> boolean`
extern "C" int32_t stateStoreRemove(void* userData, uint64_t secretId, const uint8_t* keyJsonPtr,
                                     size_t keyJsonLen, uint32_t* outRemoved) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  std::vector<uint8_t> key(keyJsonPtr, keyJsonPtr + keyJsonLen);
  CallResult result = keepAlive->bridge().callSync([keepAlive, secretId, key](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->stateStore();
    auto method = store->getPropertyAsFunction(rt, "remove");
    jsi::Value promise = method.callWithThis(rt, *store, idVal(rt, secretId), toUint8ArrayVal(rt, key));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toBoolResult);
  });
  *outRemoved = result.bytes.empty() ? 0 : 1;
  return result.code;
}

/// `StateStore.loadAll(secretId, kind) -> Uint8Array[]`
extern "C" int32_t stateStoreLoadAll(void* userData, uint64_t secretId, uint32_t kind, uint8_t** outPtr,
                                      size_t* outLen) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();
  CallResult result =
      keepAlive->bridge().callSync([keepAlive, secretId, kind](std::function<void(CallResult)> settle) {
        jsi::Runtime& rt = keepAlive->runtime();
        auto store = keepAlive->stateStore();
        auto method = store->getPropertyAsFunction(rt, "loadAll");
        jsi::Value promise =
            method.callWithThis(rt, *store, idVal(rt, secretId), jsi::Value(static_cast<int>(kind)));
        keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toStateLoadAllResult);
      });
  if (result.code == 0) {
    if (!writeOut(result.bytes, outPtr, outLen)) {
      return kBackendFailure;
    }
  } else {
    *outPtr = nullptr;
    *outLen = 0;
  }
  return result.code;
}

/// Maps the wire's `derec_proto::Protocol` discriminant to the string
/// `Transport.send`'s endpoint carries. Only `HTTPS = 0` is defined today;
/// the protocol is explicitly extensible, so an unrecognised discriminant
/// is reported rather than guessed at.
std::string protocolToString(int32_t protocol) { return protocol == 0 ? "https" : "unknown"; }

/// Minimal reader for an encoded `TransportProtocol`: field 1 is the URI
/// (length-delimited string), field 2 the protocol discriminant (varint).
/// Hand-rolled rather than linking a protobuf runtime into the JSI layer for
/// two fields; unknown fields are skipped so a newer library stays readable.
static std::optional<std::pair<std::string, int32_t>> decodeTransportProtocol(
    const uint8_t* data, size_t len) {
  std::string uri;
  int32_t protocol = 0;
  size_t i = 0;

  auto readVarint = [&](uint64_t& out) -> bool {
    out = 0;
    int shift = 0;
    while (i < len) {
      uint8_t b = data[i++];
      out |= static_cast<uint64_t>(b & 0x7F) << shift;
      if ((b & 0x80) == 0) return true;
      shift += 7;
      if (shift > 63) return false;
    }
    return false;
  };

  while (i < len) {
    uint64_t tag = 0;
    if (!readVarint(tag)) return std::nullopt;
    uint32_t field = static_cast<uint32_t>(tag >> 3);
    uint32_t wire = static_cast<uint32_t>(tag & 0x7);

    if (field == 1 && wire == 2) {
      uint64_t size = 0;
      if (!readVarint(size) || i + size > len) return std::nullopt;
      uri.assign(reinterpret_cast<const char*>(data + i), size);
      i += size;
    } else if (field == 2 && wire == 0) {
      uint64_t value = 0;
      if (!readVarint(value)) return std::nullopt;
      protocol = static_cast<int32_t>(value);
    } else if (wire == 0) {
      uint64_t skip = 0;
      if (!readVarint(skip)) return std::nullopt;
    } else if (wire == 2) {
      uint64_t size = 0;
      if (!readVarint(size) || i + size > len) return std::nullopt;
      i += size;
    } else {
      return std::nullopt;
    }
  }
  return std::make_pair(uri, protocol);
}

/// `Transport.send(endpoints, message) -> void`
///
/// `endpoints` is every address the peer advertised, in the peer's order,
/// already filtered to those the library will record. The library does not
/// rank them: which to dial, and whether to fall back, is the JavaScript
/// implementation's choice. Delivery to any one of them is success.
extern "C" int32_t transportSend(void* userData, const uint8_t* endpointsPtr, size_t endpointsLen,
                                  const uint8_t* bytes, size_t len) {
  auto* self = static_cast<StoreBindings*>(userData);
  // Kept alive past this call so the lambda handed to `callSync` — which the
  // JavaScript CallInvoker's queue may still be holding after this object's
  // owner has released its own reference — has somewhere safe to run.
  auto keepAlive = self->shared_from_this();

  // Length-delimited TransportProtocol sequence: each entry preceded by its
  // protobuf varint byte length.
  std::vector<std::pair<std::string, int32_t>> endpoints;
  size_t offset = 0;
  while (offset < endpointsLen) {
    uint64_t size = 0;
    int shift = 0;
    while (offset < endpointsLen) {
      uint8_t b = endpointsPtr[offset++];
      size |= static_cast<uint64_t>(b & 0x7F) << shift;
      if ((b & 0x80) == 0) break;
      shift += 7;
    }
    if (offset + size > endpointsLen) return -1;
    auto parsed = decodeTransportProtocol(endpointsPtr + offset, size);
    if (!parsed) return -1;
    endpoints.push_back(*parsed);
    offset += size;
  }

  std::vector<uint8_t> message(bytes, bytes + len);
  CallResult result = keepAlive->bridge().callSync([keepAlive, endpoints,
                                                message](std::function<void(CallResult)> settle) {
    jsi::Runtime& rt = keepAlive->runtime();
    auto store = keepAlive->transportStore();
    auto method = store->getPropertyAsFunction(rt, "send");
    jsi::Array endpointsJs(rt, endpoints.size());
    for (size_t i = 0; i < endpoints.size(); ++i) {
      jsi::Object endpoint(rt);
      endpoint.setProperty(rt, "protocol",
                            jsi::Value(rt, jsi::String::createFromUtf8(
                                               rt, protocolToString(endpoints[i].second))));
      endpoint.setProperty(rt, "uri",
                            jsi::Value(rt, jsi::String::createFromUtf8(rt, endpoints[i].first)));
      endpointsJs.setValueAtIndex(rt, i, endpoint);
    }
    jsi::Value promise =
        method.callWithThis(rt, *store, jsi::Value(rt, endpointsJs), toUint8ArrayVal(rt, message));
    keepAlive->settleFromPromise(rt, std::move(promise), std::move(settle), toVoidResult);
  });
  return result.code;
}

/// Throws a `jsi::JSError` naming `name` if `fn` is null. Guards against a
/// callback struct silently shipping with an unset member — e.g. a future
/// field added to `derec_ffi.h` that this file forgot to wire up.
template <typename Fn>
void requireField(jsi::Runtime& rt, Fn fn, const char* qualifiedName) {
  if (fn == nullptr) {
    throw jsi::JSError(rt, std::string("StoreBindings: ") + qualifiedName + " is not set");
  }
}

/// Reads and retains the JS object stored at `stores[name]`, throwing a
/// `jsi::JSError` naming the missing or malformed store.
std::shared_ptr<jsi::Object> requireStore(jsi::Runtime& rt, jsi::Object& stores, const char* name) {
  if (!stores.hasProperty(rt, name)) {
    throw jsi::JSError(rt, std::string("StoreBindings: missing store \"") + name + "\"");
  }
  jsi::Value value = stores.getProperty(rt, name);
  if (!value.isObject()) {
    throw jsi::JSError(rt, std::string("StoreBindings: store \"") + name + "\" is not an object");
  }
  return std::make_shared<jsi::Object>(value.asObject(rt));
}

}  // namespace

StoreBindings::StoreBindings(jsi::Runtime& rt, JsCallbackBridge& bridge,
                              std::shared_ptr<InstanceState> state)
    : rt_(rt), bridge_(bridge), instanceState_(std::move(state)) {}

void StoreBindings::settleFromPromise(jsi::Runtime& rt, jsi::Value value,
                                       std::function<void(CallResult)> settle,
                                       ResultConverter convert) {
  // A store may legitimately return a plain value; only route through
  // `then` when the result actually is a thenable.
  if (!value.isObject()) {
    settle(convert(rt, value));
    return;
  }
  auto object = value.asObject(rt);
  if (!object.hasProperty(rt, "then")) {
    settle(convert(rt, value));
    return;
  }

  auto shared = std::make_shared<std::function<void(CallResult)>>(std::move(settle));

  // A converter can throw (e.g. `asBytes` on a non-buffer, `asNumber()` on
  // a non-number, `asString()` on a non-string — all reachable when a
  // store resolves the wrong type, and all checked forms: the `get*`
  // variants only `assert`, so under NDEBUG they would read the wrong union
  // member instead of throwing). Left uncaught, that exception would
  // escape into the promise machinery without ever calling `settle`,
  // stranding the blocked worker for the full `kStoreTimeout` instead of
  // failing fast. The synchronous, non-thenable branch above is already
  // covered by `JsCallbackBridge::callSync`'s own try/catch; this `then`
  // branch runs later, on its own turn of the microtask queue, so it needs
  // the same guarantee here.
  auto onOk = jsi::Function::createFromHostFunction(
      rt, jsi::PropNameID::forAscii(rt, "onOk"), 1,
      [shared, convert](jsi::Runtime& rt, const jsi::Value&, const jsi::Value* args,
                         size_t count) -> jsi::Value {
        try {
          (*shared)(count > 0 ? convert(rt, args[0]) : convert(rt, jsi::Value::undefined()));
        } catch (...) {
          (*shared)(CallResult{kBackendFailure, {}});
        }
        return jsi::Value::undefined();
      });

  auto onErr = jsi::Function::createFromHostFunction(
      rt, jsi::PropNameID::forAscii(rt, "onErr"), 1,
      [shared](jsi::Runtime&, const jsi::Value&, const jsi::Value*, size_t) -> jsi::Value {
        try {
          (*shared)(CallResult{kBackendFailure, {}});
        } catch (...) {
          // `settle` on an already-resolved slot is a documented no-op, but
          // guard uniformly with `onOk` in case a future `settle`
          // implementation grows a fallible step.
        }
        return jsi::Value::undefined();
      });

  object.getPropertyAsFunction(rt, "then").callWithThis(rt, object, std::move(onOk), std::move(onErr));
}

std::shared_ptr<StoreBindings> StoreBindings::create(jsi::Runtime& rt, jsi::Object& stores,
                                                      JsCallbackBridge& bridge,
                                                      std::shared_ptr<InstanceState> state) {
  std::shared_ptr<StoreBindings> bindings(new StoreBindings(rt, bridge, std::move(state)));

  bindings->channelStore_ = requireStore(rt, stores, "channelStore");
  bindings->secretStore_ = requireStore(rt, stores, "secretStore");
  bindings->shareStore_ = requireStore(rt, stores, "shareStore");
  bindings->userSecretStore_ = requireStore(rt, stores, "userSecretStore");
  bindings->stateStore_ = requireStore(rt, stores, "stateStore");
  bindings->transport_ = requireStore(rt, stores, "transport");

  auto* self = bindings.get();

  bindings->channelCallbacks_ = ChannelStoreCallbacks{
      self,                        // user_data
      channelStoreLoad,            // load
      channelStoreSave,            // save
      channelStoreRemove,          // remove
      channelStoreListHelpers,     // list_helpers
      channelStoreListReplicas,    // list_replicas
      channelStoreLinkChannel,     // link_channel
      channelStoreLinkedChannels,  // linked_channels
      storeFreeBuffer,             // free_buffer
  };
  bindings->secretCallbacks_ = SecretStoreCallbacks{
      self,              // user_data
      secretStoreLoad,   // load
      secretStoreSave,   // save
      secretStoreRemove, // remove
      storeFreeBuffer,   // free_buffer
  };
  bindings->shareCallbacks_ = ShareStoreCallbacks{
      self,                    // user_data
      shareStoreLoad,          // load
      shareStoreLoadMany,      // load_many
      shareStoreLoadAll,       // load_all
      shareStoreLatestVersion, // latest_version
      shareStoreSave,          // save
      shareStoreRemoveChannel, // remove_channel
      storeFreeBuffer,         // free_buffer
  };
  bindings->userSecretCallbacks_ = UserSecretStoreCallbacks{
      self,                       // user_data
      userSecretStoreLoadLatest,  // load_latest
      userSecretStoreSaveLatest,  // save_latest
      userSecretStoreRemove,      // remove
      storeFreeBuffer,            // free_buffer
  };
  bindings->stateCallbacks_ = StateStoreCallbacks{
      self,               // user_data
      stateStoreSave,     // save
      stateStoreLoad,     // load
      stateStoreRemove,   // remove
      stateStoreLoadAll,  // load_all
      storeFreeBuffer,    // free_buffer
  };
  bindings->transportCallbacks_ = TransportCallbacks{
      self,          // user_data
      transportSend, // send
  };

  requireField(rt, bindings->channelCallbacks_.user_data, "ChannelStoreCallbacks.user_data");
  requireField(rt, bindings->channelCallbacks_.load, "ChannelStoreCallbacks.load");
  requireField(rt, bindings->channelCallbacks_.save, "ChannelStoreCallbacks.save");
  requireField(rt, bindings->channelCallbacks_.remove, "ChannelStoreCallbacks.remove");
  requireField(rt, bindings->channelCallbacks_.list_helpers, "ChannelStoreCallbacks.list_helpers");
  requireField(rt, bindings->channelCallbacks_.list_replicas, "ChannelStoreCallbacks.list_replicas");
  requireField(rt, bindings->channelCallbacks_.link_channel, "ChannelStoreCallbacks.link_channel");
  requireField(rt, bindings->channelCallbacks_.linked_channels, "ChannelStoreCallbacks.linked_channels");
  requireField(rt, bindings->channelCallbacks_.free_buffer, "ChannelStoreCallbacks.free_buffer");

  requireField(rt, bindings->secretCallbacks_.user_data, "SecretStoreCallbacks.user_data");
  requireField(rt, bindings->secretCallbacks_.load, "SecretStoreCallbacks.load");
  requireField(rt, bindings->secretCallbacks_.save, "SecretStoreCallbacks.save");
  requireField(rt, bindings->secretCallbacks_.remove, "SecretStoreCallbacks.remove");
  requireField(rt, bindings->secretCallbacks_.free_buffer, "SecretStoreCallbacks.free_buffer");

  requireField(rt, bindings->shareCallbacks_.user_data, "ShareStoreCallbacks.user_data");
  requireField(rt, bindings->shareCallbacks_.load, "ShareStoreCallbacks.load");
  requireField(rt, bindings->shareCallbacks_.load_many, "ShareStoreCallbacks.load_many");
  requireField(rt, bindings->shareCallbacks_.load_all, "ShareStoreCallbacks.load_all");
  requireField(rt, bindings->shareCallbacks_.latest_version, "ShareStoreCallbacks.latest_version");
  requireField(rt, bindings->shareCallbacks_.save, "ShareStoreCallbacks.save");
  requireField(rt, bindings->shareCallbacks_.remove_channel, "ShareStoreCallbacks.remove_channel");
  requireField(rt, bindings->shareCallbacks_.free_buffer, "ShareStoreCallbacks.free_buffer");

  requireField(rt, bindings->userSecretCallbacks_.user_data, "UserSecretStoreCallbacks.user_data");
  requireField(rt, bindings->userSecretCallbacks_.load_latest, "UserSecretStoreCallbacks.load_latest");
  requireField(rt, bindings->userSecretCallbacks_.save_latest, "UserSecretStoreCallbacks.save_latest");
  requireField(rt, bindings->userSecretCallbacks_.remove, "UserSecretStoreCallbacks.remove");
  requireField(rt, bindings->userSecretCallbacks_.free_buffer, "UserSecretStoreCallbacks.free_buffer");

  requireField(rt, bindings->stateCallbacks_.user_data, "StateStoreCallbacks.user_data");
  requireField(rt, bindings->stateCallbacks_.save, "StateStoreCallbacks.save");
  requireField(rt, bindings->stateCallbacks_.load, "StateStoreCallbacks.load");
  requireField(rt, bindings->stateCallbacks_.remove, "StateStoreCallbacks.remove");
  requireField(rt, bindings->stateCallbacks_.load_all, "StateStoreCallbacks.load_all");
  requireField(rt, bindings->stateCallbacks_.free_buffer, "StateStoreCallbacks.free_buffer");

  requireField(rt, bindings->transportCallbacks_.user_data, "TransportCallbacks.user_data");
  requireField(rt, bindings->transportCallbacks_.send, "TransportCallbacks.send");

  return bindings;
}

}  // namespace derec
