// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.
//
// Exercises `ShareStoreCallbacks.save`/`record_verification`'s refusal
// mapping: a JS store that throws, or rejects its promise with, a
// `shareStoreRefusal(reason)`-shaped `Error` (one carrying a `refusal`
// property) must answer with the matching FFI code; any other failure is an
// ordinary backend failure.

#include <hermes/hermes.h>

#include <cstring>
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

// The JS application's `shareStore`. `saveMode`/`recordVerificationMode`
// select the outcome:
//   "ok"          — resolves/returns normally.
//   "plain_error" — throws a plain `Error` (no `refusal` property).
//   "reject_plain" — rejects its promise with a plain `Error`.
//   "<reason>"     — throws `shareStoreRefusal(reason)`-shaped `Error`.
//   "reject_<reason>" — rejects its promise with that same shaped `Error`.
// Only `shareStore` is reached through `StoreBindings`; the other structs
// below are C stubs, so the other JS stores only need to exist.
const char* kStoresJs = R"JS(
// Hermes's `Promise.prototype.then` schedules its reaction job through
// `setImmediate`, which the React Native runtime installs as a JS global;
// this bare Hermes instance has no such global, so a test that rejects a
// real promise (rather than throwing synchronously) needs one. Synchronous
// is fine here: `InlineInvoker` already runs every scheduled callback
// immediately, on the calling thread.
if (typeof setImmediate === "undefined") {
  globalThis.setImmediate = function (fn) { fn(); };
}
var saveMode = "ok";
var recordVerificationMode = "ok";
var saveCalls = [];
var recordVerificationCalls = [];
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
    save: function (secretId, channelId, share) {
      saveCalls.push({ secretId: secretId, channelId: channelId });
      return outcome(saveMode);
    },
    recordVerification: function (secretId, channelId, version) {
      recordVerificationCalls.push({ secretId: secretId, channelId: channelId, version: version });
      return outcome(recordVerificationMode);
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

  void setMode(const char* which, const char* mode) {
    std::string js = std::string(which) + "Mode = " + "\"" + mode + "\";";
    rt->evaluateJavaScript(std::make_shared<jsi::StringBuffer>(js), "mode.js");
  }
};

/// Calls `ShareStoreCallbacks.save` exactly as the library does: a wire
/// `ShareRecord` JSON buffer, not a decoded `Share`.
int32_t callSave(Harness& h, uint64_t secretId, uint64_t channelId) {
  const ShareStoreCallbacks* cb = h.bindings->share();
  std::string shareJson = R"({"secret_id":"1","version":1,"bytes":[1,2,3]})";
  return cb->save(cb->user_data, secretId, channelId,
                  reinterpret_cast<const uint8_t*>(shareJson.data()), shareJson.size());
}

int32_t callRecordVerification(Harness& h, uint64_t secretId, uint64_t channelId, uint32_t version) {
  const ShareStoreCallbacks* cb = h.bindings->share();
  return cb->record_verification(cb->user_data, secretId, channelId, version);
}

}  // namespace

static void saveOkSucceeds() {
  Harness h;
  expect(callSave(h, 1, 2) == 0, "save resolving normally is rc 0");
}

static void saveRefusalMapsToFfiCode() {
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
    h.setMode("save", c.mode);
    expect(callSave(h, 1, 2) == c.expected,
           std::string("save refused with \"") + c.mode + "\" maps to " + std::to_string(c.expected));
  }
}

static void savePlainFailureIsBackendFailure() {
  for (const char* mode : {"plain_error", "reject_plain"}) {
    Harness h;
    h.setMode("save", mode);
    expect(callSave(h, 1, 2) == derec::kBackendFailure,
           std::string("a plain failure (") + mode + ") is a backend failure, not a refusal");
  }
}

static void recordVerificationOkSucceeds() {
  Harness h;
  expect(callRecordVerification(h, 1, 2, 5) == 0, "recordVerification resolving normally is rc 0");
}

static void recordVerificationRefusalMapsToFfiCode() {
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
    h.setMode("recordVerification", c.mode);
    expect(callRecordVerification(h, 1, 2, 5) == c.expected,
           std::string("recordVerification refused with \"") + c.mode + "\" maps to " +
               std::to_string(c.expected));
  }
}

static void recordVerificationPlainFailureIsBackendFailure() {
  for (const char* mode : {"plain_error", "reject_plain"}) {
    Harness h;
    h.setMode("recordVerification", mode);
    expect(callRecordVerification(h, 1, 2, 5) == derec::kBackendFailure,
           std::string("a plain failure (") + mode + ") is a backend failure, not a refusal");
  }
}

int main() {
  derec::testing::run("saveOkSucceeds", saveOkSucceeds);
  derec::testing::run("saveRefusalMapsToFfiCode", saveRefusalMapsToFfiCode);
  derec::testing::run("savePlainFailureIsBackendFailure", savePlainFailureIsBackendFailure);
  derec::testing::run("recordVerificationOkSucceeds", recordVerificationOkSucceeds);
  derec::testing::run("recordVerificationRefusalMapsToFfiCode", recordVerificationRefusalMapsToFfiCode);
  derec::testing::run("recordVerificationPlainFailureIsBackendFailure",
                      recordVerificationPlainFailureIsBackendFailure);
  return derec::testing::summary();
}
