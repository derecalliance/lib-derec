// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.
//
// `ShareStoreCallbacks.save_many` is how the library saves several shares at
// once. It is driven here exactly as the library calls it, so the arguments
// the JS `ShareStore.saveMany` receives, the refusal mapping it shares with
// `save`, and the status a failing store reports are all checked.

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

// `saveManyMode` selects the outcome:
//   "ok"              — returns normally.
//   "plain_error"     — throws a plain `Error` (no `refusal` property).
//   "reject_plain"    — rejects its promise with a plain `Error`.
//   "<reason>"        — throws a `shareStoreRefusal(reason)`-shaped `Error`.
//   "reject_<reason>" — rejects its promise with that same shaped `Error`.
const char* kStoresJs = R"JS(
// Hermes's `Promise.prototype.then` schedules its reaction job through
// `setImmediate`, which the React Native runtime installs as a JS global;
// this bare Hermes instance has no such global.
if (typeof setImmediate === "undefined") {
  globalThis.setImmediate = function (fn) { fn(); };
}
var saveManyMode = "ok";
var saveManyCalls = [];
function makeRefusal(reason) {
  var e = new Error("share store refused: " + reason);
  e.refusal = reason;
  return e;
}
function outcome(mode) {
  if (mode === "ok") { return undefined; }
  if (mode === "plain_error") { throw new Error("backend down"); }
  if (mode === "reject_plain") { return Promise.reject(new Error("backend down")); }
  if (mode.indexOf("reject_") === 0) { return Promise.reject(makeRefusal(mode.slice(7))); }
  throw makeRefusal(mode);
}
var stores = {
  channelStore: {},
  secretStore: {},
  userSecretStore: {},
  stateStore: {},
  transport: {},
  shareStore: {
    saveMany: function (secretId, entries) {
      saveManyCalls.push({
        secretId: secretId,
        entries: entries.map(function (e) {
          return [e[0], {
            secretId: e[1].secretId,
            version: e[1].version,
            isUint8Array: e[1].bytes instanceof Uint8Array,
            bytes: Array.prototype.slice.call(e[1].bytes),
            subshares: e[1].subshares,
            threshold: e[1].threshold,
          }];
        }),
      });
      return outcome(saveManyMode);
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

  void eval(const std::string& js) {
    rt->evaluateJavaScript(std::make_shared<jsi::StringBuffer>(js), "eval.js");
  }

  std::string calls() {
    jsi::Value json = rt->global()
                          .getPropertyAsObject(*rt, "JSON")
                          .getPropertyAsFunction(*rt, "stringify")
                          .call(*rt, rt->global().getProperty(*rt, "saveManyCalls"));
    return json.asString(*rt).utf8(*rt);
  }
};

int32_t callSaveMany(Harness& h, uint64_t secretId, const std::string& entriesJson) {
  const ShareStoreCallbacks* cb = h.bindings->share();
  return cb->save_many(cb->user_data, secretId,
                       reinterpret_cast<const uint8_t*>(entriesJson.data()), entriesJson.size());
}

const char* kOneEntry = R"([["2",{"secret_id":"1","version":1,"bytes":[1,2,3]}]])";

}  // namespace

static void forwardsIdsAndShares() {
  Harness h;
  int32_t rc = callSaveMany(
      h, 18446744073709551615ULL,
      R"([["12",{"secret_id":"18446744073709551615","version":3,"bytes":[1,2,255],"subshares":5,"threshold":2}],)"
      R"(["18446744073709551615",{"secret_id":"7","version":4,"bytes":[],"subshares":null}]])");
  expect(rc == 0, "save_many succeeds");
  expect(h.calls() ==
             R"([{"secretId":"18446744073709551615","entries":[)"
             R"(["12",{"secretId":"18446744073709551615","version":3,"isUint8Array":true,"bytes":[1,2,255],"subshares":5,"threshold":2}],)"
             R"(["18446744073709551615",{"secretId":"7","version":4,"isUint8Array":true,"bytes":[]}]]}])",
         "the JS store sees decimal-string ids and each record as the Share `save` receives: " + h.calls());
}

static void emptyBufferIsEmptyArray() {
  Harness h;
  int32_t rc = callSaveMany(h, 1, "");
  expect(rc == 0, "an empty buffer succeeds");
  expect(h.calls() == R"([{"secretId":"1","entries":[]}])",
         "an empty buffer reaches JS as an empty array: " + h.calls());
}

static void malformedRecordIsBackendFailure() {
  Harness h;
  int32_t rc = callSaveMany(h, 1, R"([["2",{"version":1,"bytes":[1]}]])");
  expect(rc == derec::kBackendFailure, "a record without secret_id is a backend failure");
  expect(h.calls() == "[]", "the store is not called for a malformed record: " + h.calls());
}

static void refusalMapsToFfiCode() {
  struct Case {
    const char* mode;
    int32_t expected;
  };
  const Case cases[] = {
      {"too_frequent", 4},
      {"size_limit_exceeded", 3},
      {"rejected", 10},
      {"reject_too_frequent", 4},
      {"reject_size_limit_exceeded", 3},
      {"reject_rejected", 10},
  };
  for (const Case& c : cases) {
    Harness h;
    h.eval(std::string("saveManyMode = \"") + c.mode + "\";");
    expect(callSaveMany(h, 1, kOneEntry) == c.expected,
           std::string("saveMany refused with \"") + c.mode + "\" maps to " + std::to_string(c.expected));
  }
}

static void plainFailureIsBackendFailure() {
  for (const char* mode : {"plain_error", "reject_plain"}) {
    Harness h;
    h.eval(std::string("saveManyMode = \"") + mode + "\";");
    expect(callSaveMany(h, 1, kOneEntry) == derec::kBackendFailure,
           std::string("a plain failure (") + mode + ") is a backend failure, not a refusal");
  }
}

int main() {
  derec::testing::run("forwardsIdsAndShares", forwardsIdsAndShares);
  derec::testing::run("emptyBufferIsEmptyArray", emptyBufferIsEmptyArray);
  derec::testing::run("malformedRecordIsBackendFailure", malformedRecordIsBackendFailure);
  derec::testing::run("refusalMapsToFfiCode", refusalMapsToFfiCode);
  derec::testing::run("plainFailureIsBackendFailure", plainFailureIsBackendFailure);
  return derec::testing::summary();
}
