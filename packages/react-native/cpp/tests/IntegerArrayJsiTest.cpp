// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.

#include <hermes/hermes.h>

#include <memory>
#include <string>

#include "../Primitives.h"
#include "TestMain.h"

using namespace facebook;
using derec::testing::expect;

namespace {

/// Calls `protect_secret` with the given aligned channel/weight arrays,
/// threshold and version, returning `"ok"` or the thrown error's message.
std::string protectWith(const std::string& channels,
                        const std::string& weights,
                        const std::string& threshold,
                        const std::string& version) {
  auto rt = facebook::hermes::makeHermesRuntime();
  auto host = jsi::Object(*rt);
  derec::installPrimitives(*rt, host);
  rt->global().setProperty(*rt, "host", host);
  std::string js =
      "(function () { try { host.protect_secret(7, new Uint8Array([1, 2, 3]).buffer, " +
      channels + ", " + weights + ", " + threshold + ", " + version +
      "); return 'ok'; } catch (e) { return String(e && e.message); } })()";
  jsi::Value result =
      rt->evaluateJavaScript(std::make_shared<jsi::StringBuffer>(js), "weights.js");
  return result.asString(*rt).utf8(*rt);
}

/// `protectWith` at threshold 3 and version 1.
std::string protectWithChannelsAndWeights(const std::string& channels, const std::string& weights) {
  return protectWith(channels, weights, "3", "1");
}

bool rejectedAsMarshalling(const std::string& message) {
  return message.find("protect_secret expects") == 0 ||
         message.find("protect_secret:") == 0;
}

}  // namespace

static void integralWeightsAreAccepted() {
  std::string result = protectWithChannelsAndWeights("[1, 2, 3]", "[2, 1, 1]");
  expect(result == "ok", "an integral weight crosses unchanged: " + result);
}

static void nonIntegralOrOutOfRangeWeightsAreRejected() {
  for (const char* values : {"[1.5]", "[-1]", "[4294967296]", "[5e9]", "[NaN]", "['1']"}) {
    std::string result = protectWithChannelsAndWeights("[1]", values);
    expect(rejectedAsMarshalling(result),
           std::string("weight values ") + values + " are rejected: " + result);
  }
}

static void nonIntegralOrOutOfRangeChannelsAreRejected() {
  for (const char* channels : {"[1.5]", "[-1]", "[18446744073709551616]", "[-1n]",
                               "[18446744073709551616n]", "['1']"}) {
    std::string result = protectWithChannelsAndWeights(channels, "[1]");
    expect(rejectedAsMarshalling(result),
           std::string("weight channels ") + channels + " are rejected: " + result);
  }
}

static void bigintChannelsAreAccepted() {
  std::string result = protectWithChannelsAndWeights("[1n, 2n, 3n]", "[2, 1, 1]");
  expect(result == "ok", "a bigint channel crosses unchanged: " + result);
}

static void mismatchedChannelAndWeightLengthsAreRejected() {
  std::string result = protectWithChannelsAndWeights("[1, 2, 3]", "[1, 1]");
  expect(result == "protect_secret: channels and weights must have the same length",
         "mismatched lengths are rejected: " + result);
}

static void nonIntegralOrOutOfRangeThresholdIsRejected() {
  for (const char* threshold : {"2.5", "-1", "18446744073709551616", "NaN", "'3'", "-1n"}) {
    std::string result = protectWith("[1, 2, 3]", "[1, 1, 1]", threshold, "1");
    expect(rejectedAsMarshalling(result),
           std::string("threshold ") + threshold + " is rejected: " + result);
  }
}

static void nonIntegralOrOutOfRangeVersionIsRejected() {
  for (const char* version : {"1.5", "-1", "4294967296", "NaN", "'1'", "4294967296n"}) {
    std::string result = protectWith("[1, 2, 3]", "[1, 1, 1]", "3", version);
    expect(rejectedAsMarshalling(result),
           std::string("version ") + version + " is rejected: " + result);
  }
}

static void bigintThresholdAndVersionAreAccepted() {
  std::string result = protectWith("[1, 2, 3]", "[1, 1, 1]", "3n", "4294967295n");
  expect(result == "ok", "a bigint threshold and version cross unchanged: " + result);
}

int main() {
  derec::testing::run("integralWeightsAreAccepted", integralWeightsAreAccepted);
  derec::testing::run("nonIntegralOrOutOfRangeWeightsAreRejected",
                      nonIntegralOrOutOfRangeWeightsAreRejected);
  derec::testing::run("nonIntegralOrOutOfRangeChannelsAreRejected",
                      nonIntegralOrOutOfRangeChannelsAreRejected);
  derec::testing::run("bigintChannelsAreAccepted", bigintChannelsAreAccepted);
  derec::testing::run("mismatchedChannelAndWeightLengthsAreRejected",
                      mismatchedChannelAndWeightLengthsAreRejected);
  derec::testing::run("nonIntegralOrOutOfRangeThresholdIsRejected",
                      nonIntegralOrOutOfRangeThresholdIsRejected);
  derec::testing::run("nonIntegralOrOutOfRangeVersionIsRejected",
                      nonIntegralOrOutOfRangeVersionIsRejected);
  derec::testing::run("bigintThresholdAndVersionAreAccepted",
                      bigintThresholdAndVersionAreAccepted);
  return derec::testing::summary();
}
