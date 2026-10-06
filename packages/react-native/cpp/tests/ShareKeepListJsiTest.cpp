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

/// A share store whose `keepList` answers `keepAnswer` and records each call.
const char* kStoresJs = R"JS(
var keepListCalls = [];
var keepAnswer = null;
var keepListFails = false;
var stores = {
  channelStore: {},
  secretStore: {},
  userSecretStore: {},
  stateStore: {},
  transport: {},
  shareStore: {
    keepList: function (secretId, version) {
      if (keepListFails) { throw new Error("backend down"); }
      keepListCalls.push({ secretId: secretId, version: version });
      return keepAnswer;
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

  std::string calls() {
    jsi::Value json = rt->global()
                          .getPropertyAsObject(*rt, "JSON")
                          .getPropertyAsFunction(*rt, "stringify")
                          .call(*rt, rt->global().getProperty(*rt, "keepListCalls"));
    return json.asString(*rt).utf8(*rt);
  }
};

/// The status `keep_list` returns and the JSON it hands back to Rust.
struct KeepListResult {
  int32_t rc;
  std::string json;
};

KeepListResult callKeepList(Harness& h, uint64_t secretId, uint32_t version) {
  const ShareStoreCallbacks* cb = h.bindings->share();
  uint8_t* ptr = nullptr;
  size_t len = 0;
  int32_t rc = cb->keep_list(cb->user_data, secretId, version, &ptr, &len);
  std::string json(reinterpret_cast<const char*>(ptr), len);
  if (ptr != nullptr) {
    cb->free_buffer(cb->user_data, ptr, len);
  }
  return KeepListResult{rc, json};
}

}  // namespace

static void forwardsTheSecretIdAndVersion() {
  Harness h;
  callKeepList(h, 18446744073709551615ULL, 5);
  expect(h.calls() == R"([{"secretId":"18446744073709551615","version":5}])",
         "the JS store sees a decimal-string secret id and a numeric version: " + h.calls());
}

static void aListCrossesAsAJsonArray() {
  Harness h;
  h.eval("keepAnswer = [1, 3];");
  KeepListResult result = callKeepList(h, 1, 4);
  expect(result.rc == 0, "keep_list succeeds");
  expect(result.json == "[1,3]", "the list reaches Rust as a JSON array: " + result.json);
}

static void anEmptyListStaysAList() {
  Harness h;
  h.eval("keepAnswer = [];");
  KeepListResult result = callKeepList(h, 1, 4);
  expect(result.rc == 0 && result.json == "[]", "an empty list is not null: " + result.json);
}

static void nullAndUndefinedCrossAsNull() {
  Harness h;
  KeepListResult fromNull = callKeepList(h, 1, 4);
  expect(fromNull.rc == 0 && fromNull.json == "null", "null crosses as JSON null: " + fromNull.json);
  h.eval("keepAnswer = undefined;");
  KeepListResult fromUndefined = callKeepList(h, 1, 4);
  expect(fromUndefined.rc == 0 && fromUndefined.json == "null",
         "undefined crosses as JSON null: " + fromUndefined.json);
}

static void malformedAnswersAreBackendFailures() {
  for (const char* answer : {"keepAnswer = 3;", "keepAnswer = [1.5];", "keepAnswer = [-1];", "keepAnswer = ['1'];",
                             "keepAnswer = [4294967296];"}) {
    Harness h;
    h.eval(answer);
    expect(callKeepList(h, 1, 4).rc == derec::kBackendFailure, std::string("rejected: ") + answer);
  }
}

static void throwingStoreIsBackendFailure() {
  Harness h;
  h.eval("keepListFails = true;");
  expect(callKeepList(h, 1, 4).rc == derec::kBackendFailure, "a throwing store is a backend failure");
}

int main() {
  derec::testing::run("forwardsTheSecretIdAndVersion", forwardsTheSecretIdAndVersion);
  derec::testing::run("aListCrossesAsAJsonArray", aListCrossesAsAJsonArray);
  derec::testing::run("anEmptyListStaysAList", anEmptyListStaysAList);
  derec::testing::run("nullAndUndefinedCrossAsNull", nullAndUndefinedCrossAsNull);
  derec::testing::run("malformedAnswersAreBackendFailures", malformedAnswersAreBackendFailures);
  derec::testing::run("throwingStoreIsBackendFailure", throwingStoreIsBackendFailure);
  return derec::testing::summary();
}
