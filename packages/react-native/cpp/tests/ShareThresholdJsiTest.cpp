// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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

/// Runs scheduled work immediately, on the thread that owns the runtime.
class InlineInvoker : public derec::Invoker {
 public:
  void invokeAsync(std::function<void()> work) override { work(); }
};

/// A share store that records what `save` receives and answers `load` with
/// `loadAnswer`.
const char* kStoresJs = R"JS(
var saved = [];
var loadAnswer = [];
var stores = {
  channelStore: {},
  secretStore: {},
  userSecretStore: {},
  stateStore: {},
  transport: {},
  shareStore: {
    save: function (secretId, channelId, share) {
      saved.push({ hasThreshold: "threshold" in share, threshold: share.threshold });
    },
    load: function (secretId, channelId, versions) {
      return loadAnswer;
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

  void eval(const char* js) { rt->evaluateJavaScript(std::make_shared<jsi::StringBuffer>(js), "eval.js"); }

  std::string json(const char* global) {
    jsi::Value json = rt->global()
                          .getPropertyAsObject(*rt, "JSON")
                          .getPropertyAsFunction(*rt, "stringify")
                          .call(*rt, rt->global().getProperty(*rt, global));
    return json.asString(*rt).utf8(*rt);
  }
};

int32_t callSave(Harness& h, const std::string& record) {
  const ShareStoreCallbacks* cb = h.bindings->share();
  return cb->save(cb->user_data, 1, 2, reinterpret_cast<const uint8_t*>(record.data()), record.size());
}

struct LoadResult {
  int32_t rc;
  std::string json;
};

LoadResult callLoad(Harness& h) {
  const ShareStoreCallbacks* cb = h.bindings->share();
  const std::string versions = "[]";
  uint8_t* ptr = nullptr;
  size_t len = 0;
  int32_t rc = cb->load(cb->user_data, 1, 2, reinterpret_cast<const uint8_t*>(versions.data()), versions.size(),
                        &ptr, &len);
  std::string json(reinterpret_cast<const char*>(ptr), len);
  if (ptr != nullptr) {
    cb->free_buffer(cb->user_data, ptr, len);
  }
  return LoadResult{rc, json};
}

}  // namespace

static void saveForwardsTheThresholdOnlyWhenRecorded() {
  Harness h;
  expect(callSave(h, R"({"secret_id":"1","version":1,"bytes":[1],"subshares":1,"threshold":3})") == 0,
         "save succeeds");
  expect(callSave(h, R"({"secret_id":"1","version":1,"bytes":[1]})") == 0, "save succeeds");
  expect(h.json("saved") == R"([{"hasThreshold":true,"threshold":3},{"hasThreshold":false}])",
         "the JS store sees the threshold, and no property when there is none: " + h.json("saved"));
}

static void loadCarriesTheThresholdBackToRust() {
  Harness h;
  h.eval(R"(loadAnswer = [
    { secretId: "1", version: 1, bytes: new Uint8Array([1]), subshares: 1, threshold: 3 },
    { secretId: "1", version: 2, bytes: new Uint8Array([2]) },
    { secretId: "1", version: 3, bytes: new Uint8Array([3]), threshold: null },
  ];)");
  LoadResult result = callLoad(h);
  expect(result.rc == 0, "load succeeds");
  expect(result.json ==
             R"([{"secret_id":"1","version":1,"bytes":[1],"subshares":1,"threshold":3},)"
             R"({"secret_id":"1","version":2,"bytes":[2]},)"
             R"({"secret_id":"1","version":3,"bytes":[3]}])",
         "a threshold crosses as a number and none is omitted: " + result.json);
}

static void aMalformedThresholdIsABackendFailure() {
  for (const char* answer : {"threshold: 1.5", "threshold: -1", "threshold: '2'", "threshold: 4294967296"}) {
    Harness h;
    std::string js = std::string("loadAnswer = [{ secretId: '1', version: 1, bytes: new Uint8Array([1]), ") +
                     answer + " }];";
    h.eval(js.c_str());
    expect(callLoad(h).rc == derec::kBackendFailure, std::string("rejected: ") + answer);
  }
}

int main() {
  derec::testing::run("saveForwardsTheThresholdOnlyWhenRecorded", saveForwardsTheThresholdOnlyWhenRecorded);
  derec::testing::run("loadCarriesTheThresholdBackToRust", loadCarriesTheThresholdBackToRust);
  derec::testing::run("aMalformedThresholdIsABackendFailure", aMalformedThresholdIsABackendFailure);
  return derec::testing::summary();
}
