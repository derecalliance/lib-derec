// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.

#include <hermes/hermes.h>

#include <string>
#include <vector>

#include "../Primitives.h"
#include "TestMain.h"

using namespace facebook;
using derec::testing::expect;

namespace {

constexpr uint64_t kChannelId = 3;
constexpr uint64_t kSecretId = 5;

jsi::Value arrayBuffer(jsi::Runtime& rt, const std::vector<uint8_t>& bytes) {
  return derec::toArrayBuffer(rt, bytes.data(), bytes.size());
}

std::vector<uint8_t> bytesOf(jsi::Runtime& rt, const jsi::Value& value) {
  auto buffer = value.asObject(rt).getArrayBuffer(rt);
  return std::vector<uint8_t>(buffer.data(rt), buffer.data(rt) + buffer.size(rt));
}

jsi::Value call(jsi::Runtime& rt,
                jsi::Object& host,
                const char* name,
                std::initializer_list<jsi::Value> args) {
  std::vector<jsi::Value> argv;
  for (const auto& arg : args) {
    argv.emplace_back(rt, arg);
  }
  return host.getPropertyAsFunction(rt, name)
      .call(rt, static_cast<const jsi::Value*>(argv.data()), argv.size());
}

/// The `code` of the `DeRecError` a host call throws, or empty if it did not
/// throw one.
std::string thrownCode(jsi::Runtime& rt,
                       jsi::Object& host,
                       const char* name,
                       std::initializer_list<jsi::Value> args) {
  try {
    call(rt, host, name, args);
  } catch (const jsi::JSError& error) {
    if (error.value().isObject()) {
      jsi::Value code = error.value().asObject(rt).getProperty(rt, "code");
      if (code.isString()) {
        return code.asString(rt).utf8(rt);
      }
    }
  }
  return {};
}

}  // namespace

/// A verification request produced at epoch 3 carries `sequence` 3, and the
/// receiver derives the matching key from epoch 0 to open it.
static void rotatedChannelRoundTrips() {
  auto rt = facebook::hermes::makeHermesRuntime();
  auto host = jsi::Object(*rt);
  derec::installPrimitives(*rt, host);

  std::vector<uint8_t> k0(32, 7);
  std::vector<uint8_t> k3 = bytesOf(
      *rt, call(*rt, host, "derive_channel_key",
                {arrayBuffer(*rt, k0), jsi::Value(0), jsi::Value(3)}));
  expect(k3.size() == 32, "the derived key is 32 bytes");
  expect(k3 != k0, "the derived key differs from the epoch-0 key");

  std::vector<uint8_t> envelope = bytesOf(
      *rt, call(*rt, host, "produce_verify_share_request_message",
                {jsi::BigInt::fromUint64(*rt, kChannelId),
                 jsi::BigInt::fromUint64(*rt, kSecretId), jsi::Value(1),
                 arrayBuffer(*rt, k3), jsi::Value(3), jsi::Value::null()}));

  jsi::Value sequence =
      call(*rt, host, "read_sequence_from_envelope", {arrayBuffer(*rt, envelope)});
  expect(sequence.isNumber() && sequence.asNumber() == 3,
         "the envelope's sequence is the producing key's epoch");

  std::vector<uint8_t> receiverKey = bytesOf(
      *rt, call(*rt, host, "derive_channel_key",
                {arrayBuffer(*rt, k0), jsi::Value(0), jsi::Value(*rt, sequence)}));
  expect(receiverKey == k3, "the receiver derives the sender's key");

  jsi::Value extracted = call(*rt, host, "extract_verify_share_request",
                              {arrayBuffer(*rt, envelope), arrayBuffer(*rt, receiverKey)});
  expect(extracted.asObject(*rt).getProperty(*rt, "channel_id").asBigInt(*rt).asUint64(*rt) ==
             kChannelId,
         "the derived key opens the envelope");

  expect(!thrownCode(*rt, host, "extract_verify_share_request",
                     {arrayBuffer(*rt, envelope), arrayBuffer(*rt, k0)})
              .empty(),
         "the epoch-0 key does not open an epoch-3 envelope");
}

/// Derivation runs forward only, and at most 512 epochs in one call.
static void deriveBounds() {
  auto rt = facebook::hermes::makeHermesRuntime();
  auto host = jsi::Object(*rt);
  derec::installPrimitives(*rt, host);

  std::vector<uint8_t> k0(32, 7);
  expect(thrownCode(*rt, host, "derive_channel_key",
                    {arrayBuffer(*rt, k0), jsi::Value(3), jsi::Value(2)}) == "invalid_input",
         "a backward derivation is refused as invalid input");
  expect(thrownCode(*rt, host, "derive_channel_key",
                    {arrayBuffer(*rt, k0), jsi::Value(0), jsi::Value(513)}) == "invalid_input",
         "a derivation past 512 epochs is refused as invalid input");
  expect(bytesOf(*rt, call(*rt, host, "derive_channel_key",
                           {arrayBuffer(*rt, k0), jsi::Value(0), jsi::Value(512)}))
                 .size() == 32,
         "a derivation of exactly 512 epochs succeeds");
  expect(!thrownCode(*rt, host, "derive_channel_key",
                     {arrayBuffer(*rt, std::vector<uint8_t>(31, 7)), jsi::Value(0),
                      jsi::Value(1)})
              .empty(),
         "a 31-byte key is refused with a structured error");
}

int main() {
  derec::testing::run("rotatedChannelRoundTrips", rotatedChannelRoundTrips);
  derec::testing::run("deriveBounds", deriveBounds);
  return derec::testing::summary();
}
