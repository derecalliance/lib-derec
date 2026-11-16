// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.
//
// `StateStoreCallbacks.save_many` is how the library saves several
// in-flight state rows at once. It is driven here exactly as the library calls
// it, so the arguments the JS `StateStore.saveMany` receives and the status a
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
var saveManyCalls = [];
var saveManyFails = false;
var stores = {
  channelStore: {},
  secretStore: {},
  shareStore: {},
  userSecretStore: {},
  stateStore: {
    saveMany: function (secretId, itemsJson) {
      if (saveManyFails) { throw new Error("backend down"); }
      var text = "";
      for (var i = 0; i < itemsJson.length; i++) { text += String.fromCharCode(itemsJson[i]); }
      saveManyCalls.push({
        secretId: secretId,
        isUint8Array: itemsJson instanceof Uint8Array,
        itemsJson: text,
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
                          .call(*rt, rt->global().getProperty(*rt, "saveManyCalls"));
    return json.asString(*rt).utf8(*rt);
  }
};

int32_t callSaveMany(Harness& h, uint64_t secretId, const std::string& itemsJson) {
  const StateStoreCallbacks* cb = h.bindings->state();
  return cb->save_many(cb->user_data, secretId,
                       reinterpret_cast<const uint8_t*>(itemsJson.data()), itemsJson.size());
}

}  // namespace

static void forwardsItemsAsBytes() {
  Harness h;
  const std::string items =
      R"([{"kind":0,"channel_id":"12","started_at":"1"},{"kind":3,"version":4,"started_at":"2"}])";
  int32_t rc = callSaveMany(h, 18446744073709551615ULL, items);
  expect(rc == 0, "save_many succeeds");
  expect(h.calls() ==
             R"([{"secretId":"18446744073709551615","isUint8Array":true,"itemsJson":"[{\"kind\":0,\"channel_id\":\"12\",\"started_at\":\"1\"},{\"kind\":3,\"version\":4,\"started_at\":\"2\"}]"}])",
         "the JS store sees a decimal-string secret id and the item array as unchanged bytes: " + h.calls());
}

static void throwingStoreIsBackendFailure() {
  Harness h;
  h.eval("saveManyFails = true;");
  int32_t rc = callSaveMany(h, 1, R"([{"kind":1}])");
  expect(rc == derec::kBackendFailure, "a throwing store is a backend failure");
}

int main() {
  derec::testing::run("forwardsItemsAsBytes", forwardsItemsAsBytes);
  derec::testing::run("throwingStoreIsBackendFailure", throwingStoreIsBackendFailure);
  return derec::testing::summary();
}
