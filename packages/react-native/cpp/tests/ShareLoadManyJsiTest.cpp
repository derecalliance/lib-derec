// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.
//
// `ShareStoreCallbacks.load_many` must hand the library a JSON array of
// `[channel_id, share]` pairs: `channel_id` a decimal string, `share` the
// object `load` returns for the same JS share.

#include <hermes/hermes.h>

#include <functional>
#include <memory>
#include <string>

#include "../JsCallbackBridge.h"
#include "../StoreCallbacks.h"
#include "TestMain.h"

using namespace facebook;
using derec::testing::expect;

namespace {

class InlineInvoker : public derec::Invoker {
 public:
  void invokeAsync(std::function<void()> work) override { work(); }
};

const char* kStoresJs = R"JS(
var loadManyCalls = [];
var share = { secretId: "18446744073709551615", version: 3, bytes: new Uint8Array([0, 7, 255]), threshold: 2 };
var loadAnswer = function () { return [share]; };
var loadManyAnswer = function (ids) { return [[ids[1], share]]; };
var stores = {
  channelStore: {},
  secretStore: {},
  userSecretStore: {},
  stateStore: {},
  transport: {},
  shareStore: {
    load: function () { return loadAnswer(); },
    loadMany: function (secretId, channelIds, versions) {
      loadManyCalls.push({ secretId: secretId, channelIds: channelIds.slice(), versions: versions.slice() });
      return loadManyAnswer(channelIds);
    },
  },
};
)JS";

struct Harness {
  std::unique_ptr<jsi::Runtime> rt = facebook::hermes::makeHermesRuntime();
  InlineInvoker invoker;
  std::shared_ptr<derec::InstanceState> state = std::make_shared<derec::InstanceState>();
  derec::JsCallbackBridge bridge{invoker, state};
  std::shared_ptr<derec::StoreBindings> bindings;

  Harness() {
    rt->evaluateJavaScript(std::make_shared<jsi::StringBuffer>(kStoresJs), "stores.js");
    jsi::Object stores = rt->global().getPropertyAsObject(*rt, "stores");
    bindings = derec::StoreBindings::create(*rt, stores, bridge, state);
  }

  void answer(const char* js) {
    rt->evaluateJavaScript(std::make_shared<jsi::StringBuffer>(std::string("loadManyAnswer = ") + js),
                           "answer.js");
  }

  std::string calls() {
    jsi::Value json = rt->global()
                          .getPropertyAsObject(*rt, "JSON")
                          .getPropertyAsFunction(*rt, "stringify")
                          .call(*rt, rt->global().getProperty(*rt, "loadManyCalls"));
    return json.asString(*rt).utf8(*rt);
  }
};

std::pair<int32_t, std::string> takeOut(const ShareStoreCallbacks* cb, int32_t rc, uint8_t* out, size_t outLen) {
  std::string text(reinterpret_cast<const char*>(out), outLen);
  if (out != nullptr) {
    cb->free_buffer(cb->user_data, out, outLen);
  }
  return {rc, text};
}

/// Calls `load_many` exactly as the library does.
std::pair<int32_t, std::string> callLoadMany(Harness& h, uint64_t secretId, const std::string& idsJson,
                                             const std::string& versionsJson) {
  const ShareStoreCallbacks* cb = h.bindings->share();
  uint8_t* out = nullptr;
  size_t outLen = 0;
  int32_t rc = cb->load_many(cb->user_data, secretId, reinterpret_cast<const uint8_t*>(idsJson.data()),
                             idsJson.size(), reinterpret_cast<const uint8_t*>(versionsJson.data()),
                             versionsJson.size(), &out, &outLen);
  return takeOut(cb, rc, out, outLen);
}

std::pair<int32_t, std::string> callLoad(Harness& h, uint64_t secretId, uint64_t channelId) {
  const ShareStoreCallbacks* cb = h.bindings->share();
  std::string versionsJson = "[]";
  uint8_t* out = nullptr;
  size_t outLen = 0;
  int32_t rc = cb->load(cb->user_data, secretId, channelId, reinterpret_cast<const uint8_t*>(versionsJson.data()),
                        versionsJson.size(), &out, &outLen);
  return takeOut(cb, rc, out, outLen);
}

}  // namespace

static void entriesArePairsWithStringChannelIds() {
  Harness h;
  auto [rc, json] = callLoadMany(h, 18446744073709551615ULL, "[9,18446744073709551614]", "[3]");
  expect(rc == 0, "load_many succeeds");
  expect(json == R"([["18446744073709551614",{"secret_id":"18446744073709551615","version":3,"bytes":[0,7,255],"threshold":2}]])",
         "each entry is a [decimal-string channel_id, share] pair: " + json);
  expect(h.calls() ==
             R"([{"secretId":"18446744073709551615","channelIds":["9","18446744073709551614"],"versions":[3]}])",
         "the JS store sees decimal-string ids and numeric versions: " + h.calls());
}

static void shareIsEncodedAsLoadEncodesIt() {
  Harness h;
  auto [loadRc, loadJson] = callLoad(h, 1, 9);
  auto [manyRc, manyJson] = callLoadMany(h, 1, "[9,10]", "[]");
  expect(loadRc == 0 && manyRc == 0, "load and load_many succeed");
  // `load` returns `[share]`; `load_many` returns `[["10", share]]`.
  std::string share = loadJson.substr(1, loadJson.size() - 2);
  expect(manyJson == "[[\"10\"," + share + "]]",
         "the paired share is byte-for-byte the object load returns: " + manyJson + " vs " + loadJson);
}

static void emptyAnswerIsEmptyArray() {
  Harness h;
  h.answer("function () { return []; }");
  auto [rc, json] = callLoadMany(h, 1, "[7]", "[]");
  expect(rc == 0 && json == "[]", "no shares is an empty array: " + json);
}

static void bareShareIsBackendFailure() {
  Harness h;
  h.answer("function () { return [share]; }");
  auto [rc, json] = callLoadMany(h, 1, "[7]", "[]");
  expect(rc == derec::kBackendFailure, "a share without its channel is a backend failure");
  expect(json.empty(), "a failure carries no payload");
}

static void numericChannelIdIsBackendFailure() {
  Harness h;
  h.answer("function () { return [[7, share]]; }");
  auto [rc, json] = callLoadMany(h, 1, "[7]", "[]");
  expect(rc == derec::kBackendFailure, "a numeric channel id is a backend failure");
}

static void nonDecimalChannelIdIsBackendFailure() {
  Harness h;
  h.answer("function () { return [['-7', share]]; }");
  auto [rc, json] = callLoadMany(h, 1, "[7]", "[]");
  expect(rc == derec::kBackendFailure, "a non-decimal channel id is a backend failure");
}

static void wrongArityIsBackendFailure() {
  Harness h;
  h.answer("function () { return [['7', share, 'extra']]; }");
  auto [rc, json] = callLoadMany(h, 1, "[7]", "[]");
  expect(rc == derec::kBackendFailure, "an entry that is not a pair is a backend failure");
}

static void nonArrayIsBackendFailure() {
  Harness h;
  h.answer("function () { return 5; }");
  auto [rc, json] = callLoadMany(h, 1, "[7]", "[]");
  expect(rc == derec::kBackendFailure, "a non-array answer is a backend failure");
}

int main() {
  derec::testing::run("entriesArePairsWithStringChannelIds", entriesArePairsWithStringChannelIds);
  derec::testing::run("shareIsEncodedAsLoadEncodesIt", shareIsEncodedAsLoadEncodesIt);
  derec::testing::run("emptyAnswerIsEmptyArray", emptyAnswerIsEmptyArray);
  derec::testing::run("bareShareIsBackendFailure", bareShareIsBackendFailure);
  derec::testing::run("numericChannelIdIsBackendFailure", numericChannelIdIsBackendFailure);
  derec::testing::run("nonDecimalChannelIdIsBackendFailure", nonDecimalChannelIdIsBackendFailure);
  derec::testing::run("wrongArityIsBackendFailure", wrongArityIsBackendFailure);
  derec::testing::run("nonArrayIsBackendFailure", nonArrayIsBackendFailure);
  return derec::testing::summary();
}
