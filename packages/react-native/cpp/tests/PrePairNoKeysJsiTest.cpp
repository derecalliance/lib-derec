// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.

#include <hermes/hermes.h>

#include <cstring>
#include <string>
#include <vector>

#include "../Primitives.h"
#include "TestMain.h"

using namespace facebook;
using derec::testing::expect;

namespace {

constexpr uint64_t kChannelId = 3;
constexpr uint64_t kNonce = 424242;

/// One length-framed `TransportProtocol` list holding a single HTTPS endpoint.
std::vector<uint8_t> framedEndpoint(const std::string& uri) {
  std::vector<uint8_t> entry{0x0A, static_cast<uint8_t>(uri.size())};
  entry.insert(entry.end(), uri.begin(), uri.end());
  std::vector<uint8_t> out{static_cast<uint8_t>(entry.size())};
  out.insert(out.end(), entry.begin(), entry.end());
  return out;
}

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

jsi::Value property(jsi::Runtime& rt, const jsi::Value& object, const char* name) {
  return object.asObject(rt).getProperty(rt, name);
}

}  // namespace

/// Contact creator answers a scanner's `PrePairRequest` for a `NO_KEYS`
/// contact with fresh keys, and the scanner accepts them, all through the
/// host functions over the real library.
static void noKeysPrePairRoundTrips() {
  auto rt = facebook::hermes::makeHermesRuntime();
  auto host = jsi::Object(*rt);
  derec::installPrimitives(*rt, host);

  jsi::Value contact = call(
      *rt, host, "create_contact_message",
      {jsi::BigInt::fromUint64(*rt, kChannelId), jsi::Value(2),
       arrayBuffer(*rt, framedEndpoint("https://alice.example/ephemeral")),
       jsi::Value(1), jsi::BigInt::fromUint64(*rt, kNonce)});
  jsi::Value contactBytes = property(*rt, contact, "contact_wire_bytes");

  jsi::Value prePairRequest = call(
      *rt, host, "produce_pre_pair_request_message",
      {arrayBuffer(*rt, framedEndpoint("https://bob.example/ephemeral")),
       jsi::Value(*rt, contactBytes)});
  jsi::Value extractedRequest =
      call(*rt, host, "extract_pre_pair_request", {jsi::Value(*rt, prePairRequest)});

  jsi::Value produced = call(
      *rt, host, "produce_pre_pair_no_keys_response_message",
      {jsi::BigInt::fromUint64(*rt, kChannelId),
       property(*rt, extractedRequest, "request_proto_bytes")});
  std::vector<uint8_t> envelope =
      bytesOf(*rt, property(*rt, produced, "envelope_wire_bytes"));
  std::vector<uint8_t> secretKeyMaterial =
      bytesOf(*rt, property(*rt, produced, "secret_key_material"));
  expect(!envelope.empty(), "the NoKeys response envelope is non-empty");
  expect(!secretKeyMaterial.empty(), "the NoKeys secret key material is non-empty");

  jsi::Value extractedResponse =
      call(*rt, host, "extract_pre_pair_response", {arrayBuffer(*rt, envelope)});
  expect(property(*rt, extractedResponse, "channel_id").asBigInt(*rt).asUint64(*rt) ==
             kChannelId,
         "the response is routed to the contact's channel");

  jsi::Value processed = call(
      *rt, host, "process_pre_pair_no_keys_response_message",
      {jsi::Value(*rt, contactBytes),
       property(*rt, extractedResponse, "response_proto_bytes")});
  expect(!bytesOf(*rt, property(*rt, processed, "mlkem_encapsulation_key")).empty(),
         "the scanner receives the ML-KEM encapsulation key");
  expect(!bytesOf(*rt, property(*rt, processed, "ecies_public_key")).empty(),
         "the scanner receives the ECIES public key");
  expect(property(*rt, processed, "nonce").asBigInt(*rt).asUint64(*rt) == kNonce,
         "the contact's nonce is echoed");
}

/// The host `pairing_fingerprint` returns exactly what the C ABI derives, and
/// a malformed key surfaces as a structured `DeRecError`.
static void fingerprintMatchesTheCore() {
  auto rt = facebook::hermes::makeHermesRuntime();
  auto host = jsi::Object(*rt);
  derec::installPrimitives(*rt, host);

  std::vector<uint8_t> key(32, 7);
  jsi::Value fingerprint = call(*rt, host, "pairing_fingerprint", {arrayBuffer(*rt, key)});
  expect(fingerprint.isString(), "pairing_fingerprint returns a string");
  if (!fingerprint.isString()) {
    return;
  }
  std::string viaHost = fingerprint.asString(*rt).utf8(*rt);

  PairingFingerprintResult direct = pairing_fingerprint(key.data(), key.size());
  expect(direct.error.code == 0 && direct.fingerprint != nullptr,
         "the core derives a fingerprint for a 32-byte key");
  std::string viaCore = direct.fingerprint == nullptr ? std::string() : direct.fingerprint;
  derec_free_string(direct.fingerprint);

  expect(!viaHost.empty(), "the fingerprint is non-empty");
  expect(viaHost == viaCore, "the host returns the core's fingerprint: " + viaHost);

  bool refused = false;
  try {
    call(*rt, host, "pairing_fingerprint",
         {arrayBuffer(*rt, std::vector<uint8_t>(31, 7))});
  } catch (const jsi::JSError& error) {
    refused = error.value().isObject() &&
              error.value().asObject(*rt).getProperty(*rt, "code").isString();
  }
  expect(refused, "a 31-byte key is refused with a structured error");
}

int main() {
  derec::testing::run("noKeysPrePairRoundTrips", noKeysPrePairRoundTrips);
  derec::testing::run("fingerprintMatchesTheCore", fingerprintMatchesTheCore);
  return derec::testing::summary();
}
