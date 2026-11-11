// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.
//
// `ChannelStoreCallbacks.save_many` is how the library saves several records
// at once. It is driven here exactly as the library calls it, so the
// arguments the JS `ChannelStore.saveMany` receives and the status a failing
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

// Each record's bytes are recorded as the text they spell, alongside whether
// they arrived as a `Uint8Array` — the type `save` hands JavaScript.
const char* kStoresJs = R"JS(
var saveManyCalls = [];
var saveManyFails = false;
var stores = {
  channelStore: {
    saveMany: function (secretId, records) {
      if (saveManyFails) { throw new Error("backend down"); }
      saveManyCalls.push({
        secretId: secretId,
        records: records.map(function (r) {
          return [r[0], r[1], r[2] instanceof Uint8Array, String.fromCharCode.apply(null, Array.from(r[2]))];
        }),
      });
    },
  },
  secretStore: {},
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

int32_t callSaveMany(Harness& h, uint64_t secretId, const std::string& recordsJson) {
  const ChannelStoreCallbacks* cb = h.bindings->channel();
  return cb->save_many(cb->user_data, secretId,
                       reinterpret_cast<const uint8_t*>(recordsJson.data()), recordsJson.size());
}

}  // namespace

static void forwardsIdsAndRecordBytes() {
  Harness h;
  int32_t rc = callSaveMany(
      h, 18446744073709551615ULL,
      R"([["12","0","{\"Helper\":{\"channel_id\":12}}"],["7","18446744073709551615","{\"Replica\":{}}"]])");
  expect(rc == 0, "save_many succeeds");
  expect(h.calls() ==
             R"([{"secretId":"18446744073709551615","records":[["12","0",true,"{\"Helper\":{\"channel_id\":12}}"],)"
             R"(["7","18446744073709551615",true,"{\"Replica\":{}}"]]}])",
         "the JS store sees decimal-string ids and each record's text as Uint8Array bytes: " + h.calls());
}

static void emptyBufferIsEmptyArray() {
  Harness h;
  int32_t rc = callSaveMany(h, 1, "");
  expect(rc == 0, "an empty buffer succeeds");
  expect(h.calls() == R"([{"secretId":"1","records":[]}])",
         "an empty buffer reaches JS as an empty array: " + h.calls());
}

static void throwingStoreIsBackendFailure() {
  Harness h;
  h.eval("saveManyFails = true;");
  int32_t rc = callSaveMany(h, 1, R"([["2","0","{}"]])");
  expect(rc == derec::kBackendFailure, "a throwing store is a backend failure");
}

int main() {
  derec::testing::run("forwardsIdsAndRecordBytes", forwardsIdsAndRecordBytes);
  derec::testing::run("emptyBufferIsEmptyArray", emptyBufferIsEmptyArray);
  derec::testing::run("throwingStoreIsBackendFailure", throwingStoreIsBackendFailure);
  return derec::testing::summary();
}
