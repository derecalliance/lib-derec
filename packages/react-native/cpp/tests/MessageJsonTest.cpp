// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Exercises the message JSON codec across the real C ABI.
//
// The Rust unit tests in `library/src/interop/ffi/message_json.rs` already cover the
// conversions themselves. What this adds is the boundary: that the checked-in
// `derec_ffi.h` declares the two entry points and the result struct the way
// the crate actually exports them, and that the buffers they hand back are
// safe to read and release from the host binding. A header that drifted out of
// step with the crate would link here and misread the result — the failure the
// JSI layer would otherwise hit only on a device.

#include "../Convert.h"
#include "TestMain.h"

#include <cstring>
#include <string>

using namespace derec;
using derec::testing::expect;

namespace {

/// Copies a result buffer into a string and releases it, mirroring what the
/// host functions in `Primitives.cpp` do with the same struct.
std::string takeJson(DeRecMessageJsonResult& result) {
  std::string out;
  if (result.bytes.ptr != nullptr && result.bytes.len > 0) {
    out.assign(reinterpret_cast<const char*>(result.bytes.ptr), result.bytes.len);
  }
  derec_free_buffer(result.bytes.ptr, result.bytes.len);
  result.bytes.ptr = nullptr;
  result.bytes.len = 0;
  return out;
}

bool contains(const std::string& haystack, const char* needle) {
  return haystack.find(needle) != std::string::npos;
}

}  // namespace

/// An empty protobuf message is the default-valued one, so every kind must
/// decode it rather than treating zero length as an error.
static void everyKindDecodesAnEmptyMessage() {
  for (int32_t kind = DEREC_MESSAGE_KIND_PAIR_REQUEST;
       kind <= DEREC_MESSAGE_KIND_COMMITTED_DEREC_SHARE; ++kind) {
    DeRecMessageJsonResult result = derec_decode_message_json(kind, nullptr, 0);
    expect(result.error.code == 0,
           "kind " + std::to_string(kind) + " decodes an empty message");
    std::string json = takeJson(result);
    expect(!json.empty(), "kind " + std::to_string(kind) + " produces JSON");
  }
}

/// The reason the wide fields cross as strings rather than JSON numbers.
static void wideIdsCrossAsDecimalStrings() {
  // `reply_to` is omitted rather than sent as `null`. The DTO declares it
  // `Vec<TransportProtocol>` with `#[serde(default)]`, and `default` covers a
  // *missing* key, not an explicit null — so `null` fails to deserialize.
  //
  // That is the encoder's real contract, not a quirk this test works around:
  // `src/messages.ts` drops undefined fields for exactly this reason, with the
  // same explanation. `timestamp` stays `null` because it *is* an `Option`,
  // which does accept one — the asymmetry is the point worth pinning here.
  const std::string json =
      R"({"secret_id":"18446744073709551615","version":1,)"
      R"("nonce":"9007199254740993","timestamp":null})";

  DeRecMessageJsonResult encoded = derec_encode_message_json(
      DEREC_MESSAGE_KIND_VERIFY_SHARE_REQUEST,
      reinterpret_cast<const uint8_t*>(json.data()), json.size());
  expect(encoded.error.code == 0, "a wide id string encodes");

  std::vector<uint8_t> proto;
  if (encoded.bytes.ptr != nullptr) {
    proto.assign(encoded.bytes.ptr, encoded.bytes.ptr + encoded.bytes.len);
  }
  derec_free_buffer(encoded.bytes.ptr, encoded.bytes.len);

  DeRecMessageJsonResult decoded = derec_decode_message_json(
      DEREC_MESSAGE_KIND_VERIFY_SHARE_REQUEST, proto.data(), proto.size());
  expect(decoded.error.code == 0, "the encoded message decodes again");
  std::string roundTripped = takeJson(decoded);

  expect(contains(roundTripped, "\"18446744073709551615\""),
         "a full-width u64 survives the round trip exactly");
  expect(contains(roundTripped, "\"9007199254740993\""),
         "a nonce above 2^53 survives the round trip exactly");
}

static void unknownKindIsRejected() {
  DeRecMessageJsonResult result = derec_decode_message_json(9999, nullptr, 0);
  expect(result.error.code != 0, "an unknown message kind is rejected");
  derec_free_buffer(result.bytes.ptr, result.bytes.len);
}

static void malformedJsonIsRejected() {
  const char* json = "{not json";
  DeRecMessageJsonResult result = derec_encode_message_json(
      DEREC_MESSAGE_KIND_PAIR_REQUEST,
      reinterpret_cast<const uint8_t*>(json), std::strlen(json));
  expect(result.error.code != 0, "malformed JSON is rejected");
  derec_free_buffer(result.bytes.ptr, result.bytes.len);
}

/// The error carries the same `(category, code)` names the rest of the SDK
/// surfaces, so a failure here is reportable without a second mapping table.
static void errorsCarryNamedCategories() {
  DeRecMessageJsonResult result = derec_decode_message_json(9999, nullptr, 0);
  auto named = errorName(result.error.category, result.error.code);
  expect(named.first != "unknown", "the error category has a name");
  expect(named.second != "unknown", "the error code has a name");
  derec_free_buffer(result.bytes.ptr, result.bytes.len);
}

int main() {
  derec::testing::run("everyKindDecodesAnEmptyMessage",
                      everyKindDecodesAnEmptyMessage);
  derec::testing::run("wideIdsCrossAsDecimalStrings", wideIdsCrossAsDecimalStrings);
  derec::testing::run("unknownKindIsRejected", unknownKindIsRejected);
  derec::testing::run("malformedJsonIsRejected", malformedJsonIsRejected);
  derec::testing::run("errorsCarryNamedCategories", errorsCarryNamedCategories);
  return derec::testing::summary();
}
