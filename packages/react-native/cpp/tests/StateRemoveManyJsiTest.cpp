// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.
//
// `StateStoreCallbacks.remove_many` is how the library removes several
// in-flight state rows at once. It is driven here exactly as the library calls
// it, so the arguments the JS `StateStore.removeMany` receives and the status a
// failing store reports are both checked.

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

const char* kStoresJs = R"JS(
var removeManyCalls = [];
var removeManyFails = false;
var stores = {
  channelStore: {},
  secretStore: {},
  shareStore: {},
  userSecretStore: {},
  stateStore: {
    removeMany: function (secretId, keysJson) {
      if (removeManyFails) { throw new Error("backend down"); }
      var text = "";
      for (var i = 0; i < keysJson.length; i++) { text += String.fromCharCode(keysJson[i]); }
      removeManyCalls.push({
        secretId: secretId,
        isUint8Array: keysJson instanceof Uint8Array,
        keysJson: text,
      });
    },
  },
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
                          .call(*rt, rt->global().getProperty(*rt, "removeManyCalls"));
    return json.asString(*rt).utf8(*rt);
  }
};

int32_t callRemoveMany(Harness& h, uint64_t secretId, const std::string& keysJson) {
  const StateStoreCallbacks* cb = h.bindings->state();
  return cb->remove_many(cb->user_data, secretId,
                         reinterpret_cast<const uint8_t*>(keysJson.data()), keysJson.size());
}

}  // namespace

static void forwardsKeysAsBytes() {
  Harness h;
  const std::string keys = R"([{"kind":0,"channel_id":"12"},{"kind":3,"version":4}])";
  int32_t rc = callRemoveMany(h, 18446744073709551615ULL, keys);
  expect(rc == 0, "remove_many succeeds");
  expect(h.calls() ==
             R"([{"secretId":"18446744073709551615","isUint8Array":true,"keysJson":"[{\"kind\":0,\"channel_id\":\"12\"},{\"kind\":3,\"version\":4}]"}])",
         "the JS store sees a decimal-string secret id and the key array as unchanged bytes: " + h.calls());
}

static void throwingStoreIsBackendFailure() {
  Harness h;
  h.eval("removeManyFails = true;");
  int32_t rc = callRemoveMany(h, 1, R"([{"kind":1}])");
  expect(rc == derec::kBackendFailure, "a throwing store is a backend failure");
}

int main() {
  derec::testing::run("forwardsKeysAsBytes", forwardsKeysAsBytes);
  derec::testing::run("throwingStoreIsBackendFailure", throwingStoreIsBackendFailure);
  return derec::testing::summary();
}
