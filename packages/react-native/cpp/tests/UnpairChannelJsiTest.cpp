#include <hermes/hermes.h>

#include <string>
#include <vector>

#include "../Primitives.h"
#include "TestMain.h"

using namespace facebook;
using derec::testing::expect;

namespace {

constexpr uint64_t kChannelId = 3;
constexpr uint64_t kLinkedChannelId = 18446744073709551615ULL;

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

/// The JSON mirror of an extracted message, decoded from its proto bytes.
std::string decodedJson(jsi::Runtime& rt,
                        jsi::Object& host,
                        int kind,
                        const jsi::Value& extracted,
                        const char* protoField) {
  jsi::Value proto = extracted.asObject(rt).getProperty(rt, protoField);
  std::vector<uint8_t> json =
      bytesOf(rt, call(rt, host, "decode_message_json", {jsi::Value(kind), jsi::Value(rt, proto)}));
  return std::string(json.begin(), json.end());
}

bool namesChannel(const std::string& json, uint64_t channelId) {
  return json.find("\"channel_id\":\"" + std::to_string(channelId) + "\"") != std::string::npos;
}

uint64_t envelopeChannel(jsi::Runtime& rt, const jsi::Value& extracted) {
  return extracted.asObject(rt).getProperty(rt, "channel_id").asBigInt(rt).asUint64(rt);
}

/// Produces and extracts an unpair request and response on `kChannelId`
/// naming `unpairChannelId`, and checks the named channel reaches both
/// decoded messages while the envelope keeps `kChannelId`.
void roundTrip(uint64_t unpairChannelId, const std::string& label) {
  auto rt = facebook::hermes::makeHermesRuntime();
  auto host = jsi::Object(*rt);
  derec::installPrimitives(*rt, host);

  std::vector<uint8_t> key(32, 7);
  std::string memo = "bye";
  std::vector<uint8_t> memoBytes(memo.begin(), memo.end());

  jsi::Value requestEnvelope = call(
      *rt, host, "produce_unpair_request_message",
      {jsi::BigInt::fromUint64(*rt, kChannelId), arrayBuffer(*rt, memoBytes),
       arrayBuffer(*rt, key), jsi::Value(0), jsi::Value::null(),
       jsi::BigInt::fromUint64(*rt, unpairChannelId)});
  jsi::Value request = call(*rt, host, "extract_unpair_request",
                            {jsi::Value(*rt, requestEnvelope), arrayBuffer(*rt, key)});
  expect(envelopeChannel(*rt, request) == kChannelId,
         label + ": the request travels on the envelope channel");
  expect(namesChannel(decodedJson(*rt, host, DEREC_MESSAGE_KIND_UNPAIR_REQUEST, request,
                                  "request_proto_bytes"),
                      unpairChannelId),
         label + ": the request names the channel to unpair");

  jsi::Value responseEnvelope = call(
      *rt, host, "produce_unpair_response_message",
      {jsi::BigInt::fromUint64(*rt, kChannelId), arrayBuffer(*rt, key), jsi::Value(0),
       jsi::BigInt::fromUint64(*rt, unpairChannelId)});
  jsi::Value response = call(*rt, host, "extract_unpair_response",
                             {jsi::Value(*rt, responseEnvelope), arrayBuffer(*rt, key)});
  expect(envelopeChannel(*rt, response) == kChannelId,
         label + ": the response travels on the envelope channel");
  expect(namesChannel(decodedJson(*rt, host, DEREC_MESSAGE_KIND_UNPAIR_RESPONSE, response,
                                  "response_proto_bytes"),
                      unpairChannelId),
         label + ": the response echoes the named channel");
}

}  // namespace

static void ordinaryUnpairNamesTheEnvelopeChannel() {
  roundTrip(kChannelId, "ordinary unpair");
}

static void linkedUnpairNamesTheLinkedChannel() {
  roundTrip(kLinkedChannelId, "linked unpair");
}

int main() {
  derec::testing::run("ordinaryUnpairNamesTheEnvelopeChannel",
                      ordinaryUnpairNamesTheEnvelopeChannel);
  derec::testing::run("linkedUnpairNamesTheLinkedChannel", linkedUnpairNamesTheLinkedChannel);
  return derec::testing::summary();
}
