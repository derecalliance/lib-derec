// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.
//
// `ShareStoreCallbacks.remove_versions` is how a helper applies a
// `StoreShareRequestMessage.keepList`. It is driven here exactly as the
// library calls it, so the arguments the JS `ShareStore.removeVersions`
// receives and the status a failing store reports are both checked.

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
var removeVersionsCalls = [];
var removeVersionsFails = false;
var stores = {
  channelStore: {},
  secretStore: {},
  userSecretStore: {},
  stateStore: {},
  transport: {},
  shareStore: {
    removeVersions: function (secretId, channelId, versions) {
      if (removeVersionsFails) { throw new Error("backend down"); }
      removeVersionsCalls.push({ secretId: secretId, channelId: channelId, versions: versions.slice() });
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
                          .call(*rt, rt->global().getProperty(*rt, "removeVersionsCalls"));
    return json.asString(*rt).utf8(*rt);
  }
};

int32_t callRemoveVersions(Harness& h, uint64_t secretId, uint64_t channelId, const std::string& versionsJson) {
  const ShareStoreCallbacks* cb = h.bindings->share();
  return cb->remove_versions(cb->user_data, secretId, channelId,
                             reinterpret_cast<const uint8_t*>(versionsJson.data()), versionsJson.size());
}

}  // namespace

static void forwardsIdsAndVersions() {
  Harness h;
  int32_t rc = callRemoveVersions(h, 18446744073709551615ULL, 6, "[1,3]");
  expect(rc == 0, "remove_versions succeeds");
  expect(h.calls() == R"([{"secretId":"18446744073709551615","channelId":"6","versions":[1,3]}])",
         "the JS store sees decimal-string ids and numeric versions: " + h.calls());
}

static void throwingStoreIsBackendFailure() {
  Harness h;
  h.eval("removeVersionsFails = true;");
  int32_t rc = callRemoveVersions(h, 1, 2, "[1]");
  expect(rc == derec::kBackendFailure, "a throwing store is a backend failure");
}

int main() {
  derec::testing::run("forwardsIdsAndVersions", forwardsIdsAndVersions);
  derec::testing::run("throwingStoreIsBackendFailure", throwingStoreIsBackendFailure);
  return derec::testing::summary();
}
