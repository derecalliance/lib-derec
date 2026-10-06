// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Runs against a real JSI runtime (Hermes), so `run_tests.sh` builds it only
// when a host Hermes build is available.
//
// `SecretStoreCallbacks.load_many` is driven both directly and through a real
// `derec_protocol_new` handle whose secret store is the JS object, so the
// batch method's arguments and the JSON it hands back are checked against
// what the library actually sends and accepts.

#include <hermes/hermes.h>

#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

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

// The JS application's stores. Only `secretStore` is reached through
// `StoreBindings`; the other structs below are C stubs, so the other JS
// stores only need to exist.
const char* kStoresJs = R"JS(
var loadManyCalls = [];
var loadManyAnswer = function (ids) { return ids.map(function () { return null; }); };
var stores = {
  channelStore: {},
  shareStore: {},
  userSecretStore: {},
  stateStore: {},
  transport: {},
  secretStore: {
    load: function () { return null; },
    loadMany: function (secretId, channelIds, kind) {
      loadManyCalls.push({ secretId: secretId, channelIds: channelIds.slice(), kind: kind });
      return loadManyAnswer(channelIds);
    },
    save: function () {},
    remove: function () {},
  },
};
)JS";

int32_t giveBytes(const std::string& text, uint8_t** outPtr, size_t* outLen) {
  auto* ptr = static_cast<uint8_t*>(std::malloc(text.size()));
  std::memcpy(ptr, text.data(), text.size());
  *outPtr = ptr;
  *outLen = text.size();
  return 0;
}

void freeBytes(void*, uint8_t* ptr, size_t) { std::free(ptr); }

std::string helperRow(const char* channelId) {
  return std::string(R"({"channel_id":)") + channelId +
         R"(,"transports":[{"uri":"https://helper.example.com","protocol":0}],"peer_role":"Helper"})";
}

const std::string kHelpers = "[" + helperRow("11") + "," + helperRow("22") + "]";

int32_t chLoad(void*, uint64_t, uint64_t channelId, uint64_t, uint8_t** p, size_t* l) {
  if (channelId != 11 && channelId != 22) {
    return 1;
  }
  return giveBytes(R"({"Helper":)" + helperRow(std::to_string(channelId).c_str()) + "}", p, l);
}
int32_t chSave(void*, uint64_t, uint64_t, uint64_t, const uint8_t*, size_t) { return 0; }
int32_t chRemove(void*, uint64_t, uint64_t, uint64_t, uint32_t* existed) {
  *existed = 0;
  return 0;
}
int32_t chListHelpers(void*, uint64_t, const uint8_t*, size_t, uint8_t** p, size_t* l) {
  return giveBytes(kHelpers, p, l);
}
int32_t chListReplicas(void*, uint64_t, const uint8_t*, size_t, uint8_t** p, size_t* l) {
  return giveBytes("[]", p, l);
}
int32_t chLink(void*, uint64_t, uint64_t, uint64_t) { return 0; }
int32_t chLinked(void*, uint64_t, uint64_t, uint8_t** p, size_t* l) { return giveBytes("[]", p, l); }

int32_t shLoad(void*, uint64_t, uint64_t, const uint8_t*, size_t, uint8_t**, size_t*) { return 1; }
int32_t shLoadMany(void*, uint64_t, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t** p,
                   size_t* l) {
  return giveBytes("[]", p, l);
}
int32_t shLoadAll(void*, uint64_t, const uint8_t*, size_t, uint8_t** p, size_t* l) {
  return giveBytes("[]", p, l);
}
int32_t shLatest(void*, uint64_t, uint32_t* has, uint32_t* version) {
  *has = 0;
  *version = 0;
  return 0;
}
int32_t shSave(void*, uint64_t, uint64_t, const uint8_t*, size_t) { return 0; }
int32_t shRemove(void*, uint64_t, uint64_t) { return 0; }
int32_t shRemoveVersions(void*, uint64_t, uint64_t, const uint8_t*, size_t) { return 0; }

int32_t usLoad(void*, uint64_t, uint8_t**, size_t*) { return 1; }
int32_t usSave(void*, uint64_t, const uint8_t*, size_t) { return 0; }
int32_t usRemove(void*, uint64_t) { return 0; }

int32_t stSave(void*, uint64_t, const uint8_t*, size_t) { return 0; }
int32_t stLoad(void*, uint64_t, const uint8_t*, size_t, uint8_t**, size_t*) { return 1; }
int32_t stRemove(void*, uint64_t, const uint8_t*, size_t, uint32_t* removed) {
  *removed = 0;
  return 0;
}
int32_t stLoadAll(void*, uint64_t, uint32_t, uint8_t** p, size_t* l) { return giveBytes("[]", p, l); }

int32_t trSend(void*, const uint8_t*, size_t, const uint8_t*, size_t) { return 0; }

ChannelStoreCallbacks channelStore{nullptr, chLoad, chSave, chRemove, chListHelpers,
                                   chListReplicas, chLink, chLinked, freeBytes};
ShareStoreCallbacks shareStore{nullptr,  shLoad,   shLoadMany,       shLoadAll, shLatest,
                               shSave,   shRemove, shRemoveVersions, freeBytes};
UserSecretStoreCallbacks userSecretStore{nullptr, usLoad, usSave, usRemove, freeBytes};
StateStoreCallbacks stateStore{nullptr, stSave, stLoad, stRemove, stLoadAll, freeBytes};
TransportCallbacks transport{nullptr, trSend};

/// A Hermes runtime holding `kStoresJs`, plus the `StoreBindings` built over
/// its `stores` object.
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

  void answer(const char* js) {
    rt->evaluateJavaScript(std::make_shared<jsi::StringBuffer>(std::string("loadManyAnswer = ") + js),
                           "answer.js");
  }

  std::string calls() {
    jsi::Value json = rt->global()
                          .getPropertyAsObject(*rt, "JSON")
                          .getPropertyAsFunction(*rt, "stringify")
                          .call(*rt, rt->global().getProperty(*rt, "loadManyCalls"));
    return json.asString(*rt).utf8(*rt);
  }
};

/// Calls `load_many` exactly as the library does.
std::pair<int32_t, std::string> callLoadMany(Harness& h, uint64_t secretId, const std::string& idsJson,
                                             uint32_t kind) {
  const SecretStoreCallbacks* cb = h.bindings->secret();
  uint8_t* out = nullptr;
  size_t outLen = 0;
  int32_t rc = cb->load_many(cb->user_data, secretId, reinterpret_cast<const uint8_t*>(idsJson.data()),
                             idsJson.size(), kind, &out, &outLen);
  std::string text(reinterpret_cast<const char*>(out), outLen);
  if (out != nullptr) {
    cb->free_buffer(cb->user_data, out, outLen);
  }
  return {rc, text};
}

/// Starts a Discovery broadcast to helpers 11 and 22 on a protocol whose
/// secret store is the JS object.
DeRecProtocolEventsResult startDiscovery(Harness& h) {
  std::string config =
      R"({"secret_id":"1","own_transports":[{"uri":"https://owner.example.com","protocol":0}]})";
  DeRecProtocolNewResult created = derec_protocol_new(
      reinterpret_cast<const uint8_t*>(config.data()), config.size(), nullptr, 0, &channelStore,
      h.bindings->secret(), &shareStore, &userSecretStore, &stateStore, &transport);
  expect(created.error.code == DEREC_CODE_OK, "derec_protocol_new succeeds");
  std::string params = R"({"target":["11","22"]})";
  DeRecProtocolEventsResult result =
      derec_protocol_start(created.handle, FLOW_KIND_DISCOVERY,
                           reinterpret_cast<const uint8_t*>(params.data()), params.size());
  derec_protocol_free(created.handle);
  return result;
}

void release(DeRecProtocolEventsResult& result) {
  if (result.error.code != DEREC_CODE_OK) {
    derec_free_error(&result.error);
  }
  if (result.events_json.ptr != nullptr) {
    derec_free_buffer(result.events_json.ptr, result.events_json.len);
  }
}

}  // namespace

static void entriesKeepRequestOrderAndNulls() {
  Harness h;
  h.answer("function (ids) { return [new Uint8Array([1, 2]), null, undefined]; }");
  auto [rc, json] = callLoadMany(h, 18446744073709551615ULL, "[9,18446744073709551614,7]", 0);
  expect(rc == 0, "load_many succeeds");
  expect(json == R"([{"kind":0,"bytes":[1,2]},null,null])",
         "each entry is the load record or null, in request order: " + json);
  expect(h.calls() ==
             R"([{"secretId":"18446744073709551615","channelIds":["9","18446744073709551614","7"],"kind":0}])",
         "the JS store sees one call with decimal-string ids: " + h.calls());
}

static void answerIsNotReshaped() {
  Harness h;
  h.answer("function (ids) { return [null]; }");
  auto [rc, json] = callLoadMany(h, 1, "[7,9]", 0);
  expect(rc == 0 && json == "[null]",
         "a short answer is passed through for the library to judge: " + json);
}

static void nonArrayIsBackendFailure() {
  Harness h;
  h.answer("function (ids) { return 5; }");
  auto [rc, json] = callLoadMany(h, 1, "[7]", 0);
  expect(rc == derec::kBackendFailure, "a non-array answer is a backend failure");
  expect(json.empty(), "a failure carries no payload");
}

static void broadcastCallsLoadManyOnce() {
  Harness h;
  h.answer(
      "function (ids) { return ids.map(function () { return new Uint8Array(32).fill(7); }); }");
  DeRecProtocolEventsResult result = startDiscovery(h);
  expect(result.error.code == DEREC_CODE_OK,
         std::string("discovery with every key present succeeds: ") +
             (result.error.message == nullptr ? "" : result.error.message));
  expect(h.calls() == R"([{"secretId":"1","channelIds":["11","22"],"kind":0}])",
         "the broadcast reads both keys through one loadMany call: " + h.calls());
  release(result);
}

static void nullEntryFollowsTheLibraryPolicy() {
  Harness h;
  h.answer(
      "function (ids) { return ids.map(function (id) {"
      " return id === '22' ? null : new Uint8Array(32).fill(7); }); }");
  DeRecProtocolEventsResult result = startDiscovery(h);
  std::string message = result.error.message == nullptr ? "" : result.error.message;
  expect(result.error.code == DEREC_CODE_MISSING_SHARED_KEY,
         "a null entry for a channel the broadcast needs is missing_shared_key (got " +
             std::to_string(result.error.code) + ": " + message + ")");
  expect(message.find("22") != std::string::npos, "the error names channel 22: " + message);
  expect(h.calls() == R"([{"secretId":"1","channelIds":["11","22"],"kind":0}])",
         "still one loadMany call: " + h.calls());
  release(result);
}

int main() {
  derec::testing::run("entriesKeepRequestOrderAndNulls", entriesKeepRequestOrderAndNulls);
  derec::testing::run("answerIsNotReshaped", answerIsNotReshaped);
  derec::testing::run("nonArrayIsBackendFailure", nonArrayIsBackendFailure);
  derec::testing::run("broadcastCallsLoadManyOnce", broadcastCallsLoadManyOnce);
  derec::testing::run("nullEntryFollowsTheLibraryPolicy", nullEntryFollowsTheLibraryPolicy);
  return derec::testing::summary();
}
