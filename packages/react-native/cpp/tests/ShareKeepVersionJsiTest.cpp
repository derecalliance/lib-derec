// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.
//
// `ShareStoreCallbacks.keep_version` is how an owner chooses the
// `StoreShareRequestMessage.keepVersion` of a sharing round. It is driven
// here exactly as the library calls it, so the arguments the JS
// `ShareStore.keepVersion` receives, the version written back and the status
// a malformed or failing store reports are all checked.

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
var keepVersionCalls = [];
var keepAnswer = 0;
var keepVersionFails = false;
var stores = {
  channelStore: {},
  secretStore: {},
  userSecretStore: {},
  stateStore: {},
  transport: {},
  shareStore: {
    keepVersion: function (secretId, version) {
      if (keepVersionFails) { throw new Error("backend down"); }
      keepVersionCalls.push({ secretId: secretId, version: version });
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
                          .call(*rt, rt->global().getProperty(*rt, "keepVersionCalls"));
    return json.asString(*rt).utf8(*rt);
  }
};

struct KeepVersionResult {
  int32_t rc;
  uint32_t version;
};

KeepVersionResult callKeepVersion(Harness& h, uint64_t secretId, uint32_t version) {
  const ShareStoreCallbacks* cb = h.bindings->share();
  uint32_t out = 0xFFFFFFFFu;
  int32_t rc = cb->keep_version(cb->user_data, secretId, version, &out);
  return KeepVersionResult{rc, out};
}

}  // namespace

static void forwardsTheSecretIdAndVersion() {
  Harness h;
  callKeepVersion(h, 18446744073709551615ULL, 5);
  expect(h.calls() == R"([{"secretId":"18446744073709551615","version":5}])",
         "the JS store sees a decimal-string secret id and a numeric version: " + h.calls());
}

static void theAnswerIsWrittenBack() {
  Harness h;
  h.eval("keepAnswer = 3;");
  KeepVersionResult result = callKeepVersion(h, 1, 4);
  expect(result.rc == 0, "keep_version succeeds");
  expect(result.version == 3, "the answer reaches Rust: " + std::to_string(result.version));
}

static void zeroCrossesAsZero() {
  Harness h;
  KeepVersionResult result = callKeepVersion(h, 1, 4);
  expect(result.rc == 0 && result.version == 0, "0 crosses as 0: " + std::to_string(result.version));
}

static void theFullU32RangeCrosses() {
  Harness h;
  h.eval("keepAnswer = 4294967295;");
  KeepVersionResult result = callKeepVersion(h, 1, 4);
  expect(result.rc == 0 && result.version == 4294967295u,
         "the largest u32 crosses unchanged: " + std::to_string(result.version));
}

static void malformedAnswersAreBackendFailures() {
  for (const char* answer : {"keepAnswer = null;", "keepAnswer = undefined;", "keepAnswer = [1];",
                             "keepAnswer = 1.5;", "keepAnswer = -1;", "keepAnswer = '1';",
                             "keepAnswer = 4294967296;"}) {
    Harness h;
    h.eval(answer);
    KeepVersionResult result = callKeepVersion(h, 1, 4);
    expect(result.rc == derec::kBackendFailure, std::string("rejected: ") + answer);
    expect(result.version == 0, std::string("a rejected answer writes 0: ") + answer);
  }
}

static void throwingStoreIsBackendFailure() {
  Harness h;
  h.eval("keepVersionFails = true;");
  expect(callKeepVersion(h, 1, 4).rc == derec::kBackendFailure, "a throwing store is a backend failure");
}

int main() {
  derec::testing::run("forwardsTheSecretIdAndVersion", forwardsTheSecretIdAndVersion);
  derec::testing::run("theAnswerIsWrittenBack", theAnswerIsWrittenBack);
  derec::testing::run("zeroCrossesAsZero", zeroCrossesAsZero);
  derec::testing::run("theFullU32RangeCrosses", theFullU32RangeCrosses);
  derec::testing::run("malformedAnswersAreBackendFailures", malformedAnswersAreBackendFailures);
  derec::testing::run("throwingStoreIsBackendFailure", throwingStoreIsBackendFailure);
  return derec::testing::summary();
}
