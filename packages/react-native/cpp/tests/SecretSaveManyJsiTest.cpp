// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.
//
// `SecretStoreCallbacks.save_many` is how the library saves several secrets
// at once. It is driven here exactly as the library calls it, so the
// arguments the JS `SecretStore.saveMany` receives and the status a failing
// store reports are both checked.

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

/// Runs scheduled work immediately. Every call in this test starts from C++
/// on the thread that owns the runtime, outside any JS frame, so running the
/// store body inline is equivalent to the JS thread picking it up.
class InlineInvoker : public derec::Invoker {
 public:
  void invokeAsync(std::function<void()> work) override { work(); }
};

// Each value is recorded as its byte numbers, alongside whether it arrived as
// a `Uint8Array` — the type `save` hands JavaScript.
const char* kStoresJs = R"JS(
var saveManyCalls = [];
var saveManyFails = false;
var stores = {
  channelStore: {},
  secretStore: {
    saveMany: function (secretId, entries) {
      if (saveManyFails) { throw new Error("backend down"); }
      saveManyCalls.push({
        secretId: secretId,
        entries: entries.map(function (e) {
          return [e[0], e[1], e[2] instanceof Uint8Array, Array.from(e[2])];
        }),
      });
    },
  },
  shareStore: {},
  userSecretStore: {},
  stateStore: {},
  transport: {},
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
                          .call(*rt, rt->global().getProperty(*rt, "saveManyCalls"));
    return json.asString(*rt).utf8(*rt);
  }
};

int32_t callSaveMany(Harness& h, uint64_t secretId, const std::string& entriesJson) {
  const SecretStoreCallbacks* cb = h.bindings->secret();
  return cb->save_many(cb->user_data, secretId,
                       reinterpret_cast<const uint8_t*>(entriesJson.data()), entriesJson.size());
}

}  // namespace

static void forwardsIdsKindsAndValues() {
  Harness h;
  int32_t rc = callSaveMany(
      h, 18446744073709551615ULL,
      R"([["12",0,"{\"kind\":0,\"bytes\":[1,2,255]}"],["18446744073709551615",3,"{\"kind\":3,\"bytes\":[]}"]])");
  expect(rc == 0, "save_many succeeds");
  expect(h.calls() ==
             R"([{"secretId":"18446744073709551615","entries":[["12",0,true,[1,2,255]],)"
             R"(["18446744073709551615",3,true,[]]]}])",
         "the JS store sees a decimal-string channel id, the kind, and the value bytes save receives: " +
             h.calls());
}

static void emptyBufferIsEmptyArray() {
  Harness h;
  int32_t rc = callSaveMany(h, 1, "");
  expect(rc == 0, "an empty buffer succeeds");
  expect(h.calls() == R"([{"secretId":"1","entries":[]}])",
         "an empty buffer reaches JS as an empty array: " + h.calls());
}

static void throwingStoreIsBackendFailure() {
  Harness h;
  h.eval("saveManyFails = true;");
  int32_t rc = callSaveMany(h, 1, R"([["2",1,"{\"kind\":1,\"bytes\":[9]}"]])");
  expect(rc == derec::kBackendFailure, "a throwing store is a backend failure");
}

int main() {
  derec::testing::run("forwardsIdsKindsAndValues", forwardsIdsKindsAndValues);
  derec::testing::run("emptyBufferIsEmptyArray", emptyBufferIsEmptyArray);
  derec::testing::run("throwingStoreIsBackendFailure", throwingStoreIsBackendFailure);
  return derec::testing::summary();
}
