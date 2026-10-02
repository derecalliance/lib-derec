// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "UserSecretsJson.h"

#include <string>

#include "Primitives.h"

using namespace facebook;

namespace derec {

// `UserSecrets` carries application-controlled `name` / `description`
// strings, so building or reading its wire JSON goes through the runtime's
// own `JSON.parse` / `JSON.stringify` rather than a hand-rolled scanner.

namespace {

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

}  // namespace

jsi::Value jsonParseUtf8(jsi::Runtime& rt, const uint8_t* bytes, size_t len) {
  jsi::Object json = rt.global().getPropertyAsObject(rt, "JSON");
  jsi::Function parse = json.getPropertyAsFunction(rt, "parse");
  std::string text(reinterpret_cast<const char*>(bytes), len);
  return parse.call(rt, jsi::Value(rt, jsi::String::createFromUtf8(rt, text)));
}

// Only the byte arrays inside `secrets` change representation (`Uint8Array`
// on the JS side, a JSON number array on the wire). Every record-level field
// (`version`, `description`, `author_replica_id`, ...) crosses verbatim, so
// whatever Rust writes is what the store hands back.

std::vector<uint8_t> userSecretsToWire(jsi::Runtime& rt, const jsi::Object& src) {
  jsi::Object wire(rt);
  jsi::Array names = src.getPropertyNames(rt);
  size_t fieldCount = names.size(rt);
  for (size_t i = 0; i < fieldCount; ++i) {
    std::string name = names.getValueAtIndex(rt, i).asString(rt).utf8(rt);
    if (name == "secrets") continue;
    jsi::Value value = src.getProperty(rt, name.c_str());
    if (!value.isUndefined()) {
      wire.setProperty(rt, name.c_str(), value);
    }
  }
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
  return jsonStringifyToUtf8(rt, jsi::Value(rt, wire));
}

jsi::Value userSecretsFromWire(jsi::Runtime& rt, const uint8_t* ptr, size_t len) {
  jsi::Object out = jsonParseUtf8(rt, ptr, len).asObject(rt);
  jsi::Array srcSecrets = out.getProperty(rt, "secrets").asObject(rt).asArray(rt);
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
  return jsi::Value(rt, out);
}

}  // namespace derec
