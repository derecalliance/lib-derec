// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "DeRecInstaller.h"

#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "Convert.h"
#include "JsCallbackBridge.h"
#include "Primitives.h"
#include "ProtocolHost.h"
#include "StoreCallbacks.h"

using namespace facebook;

namespace derec {

namespace {

std::mutex& registryMutex() {
  static std::mutex m;
  return m;
}

std::vector<std::weak_ptr<InstanceState>>& registry() {
  static std::vector<std::weak_ptr<InstanceState>> instances;
  return instances;
}

void requireArgs(jsi::Runtime& rt, const char* name, size_t count, size_t required) {
  if (count < required) {
    throw jsi::JSError(rt, std::string(name) + " expects " +
                                std::to_string(required) + " arguments");
  }
}

/// `secret_id` travels through `configJson` as a quoted decimal string (the
/// same field `DeRecProtocolBuilder.build()` always writes first).
/// `derec_protocol_new`'s result carries only the opaque handle, not the id,
/// so `ProtocolHost::secretId()` — which has no FFI accessor of its own —
/// needs this recovered independently. `JSON.stringify` emits no internal
/// whitespace, so a direct scan for the field is sufficient; this mirrors
/// the bare-JSON-integer scanning `StoreCallbacks.cpp` already relies on for
/// the wire's other compact JSON payloads.
uint64_t parseSecretIdFromConfigJson(const std::string& json) {
  static const std::string needle = "\"secret_id\":\"";
  size_t pos = json.find(needle);
  if (pos == std::string::npos) {
    return 0;
  }
  pos += needle.size();
  uint64_t value = 0;
  while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') {
    value = value * 10 + static_cast<uint64_t>(json[pos] - '0');
    ++pos;
  }
  return value;
}

/// `protocol_new(configJson: string, communicationInfo: ArrayBuffer, stores:
/// object) -> HostObject`. The one place that constructs a `ProtocolHost`:
/// builds the per-instance `InstanceState` and `JsCallbackBridge`, resolves
/// the six store/transport callback structs via `StoreBindings::create`, and
/// hands them to `derec_protocol_new` in the FFI's own declared parameter
/// order — channel, secret, share, user_secret, state, transport, which is
/// neither alphabetical nor the order the six `with*Store` builder methods
/// appear in (see `library/src/interop/ffi/protocol/handle/mod.rs`'s
/// `derec_protocol_new` declaration).
jsi::Value protocolNew(jsi::Runtime& rt,
                       const std::shared_ptr<Invoker>& invoker,
                       const jsi::Value&,
                       const jsi::Value* args,
                       size_t count) {
  requireArgs(rt, "protocol_new", count, 3);
  std::string configJson = args[0].asString(rt).utf8(rt);
  ByteView info = asBytes(rt, args[1]);
  jsi::Object storesObj = args[2].asObject(rt);

  auto state = std::make_shared<InstanceState>();
  auto bridge = std::make_shared<JsCallbackBridge>(*invoker, state);
  std::shared_ptr<StoreBindings> stores = StoreBindings::create(rt, storesObj, *bridge, state);

  DeRecProtocolNewResult result = derec_protocol_new(
      reinterpret_cast<const uint8_t*>(configJson.data()), configJson.size(), info.ptr, info.len,
      stores->channel(), stores->secret(), stores->share(), stores->userSecret(), stores->state(),
      stores->transport());
  if (result.error.code != DEREC_CODE_OK) {
    throwDeRecError(rt, result.error);
  }

  uint64_t secretId = parseSecretIdFromConfigJson(configJson);

  // Ownership: `stores` (a `StoreBindings`) holds `bridge`'s referent as a
  // plain `JsCallbackBridge&` (see `StoreBindings.h`), not a `shared_ptr` —
  // and a store-callback trampoline can keep `StoreBindings` alive via
  // `shared_from_this()` on the JavaScript `CallInvoker`'s queue after this
  // `ProtocolHost` itself has been fully destroyed. `bridge` therefore must
  // not be scoped to die *with* `ProtocolHost` in the ordinary sense of "a
  // member that is destroyed inside its owner's destructor" — it must
  // outlive `ProtocolHost`'s own destruction, not merely coincide with it.
  //
  // The custom deleter below achieves that without adding a member to
  // `ProtocolHost` (its constructor is fixed): it ties `bridge`'s release to
  // the *same* `shared_ptr` control block that owns the `ProtocolHost`
  // object, but strictly *after* that control block's normal deletion step.
  // A `shared_ptr`'s custom deleter call (`delete p`, which runs
  // `~ProtocolHost` to completion — invalidate, drain the worker, free the
  // handle) always finishes before the control block releases whatever the
  // deleter closure itself captured. So `bridge` is released only once
  // `ProtocolHost`'s entire teardown has already run, which is later than
  // any point at which a worker-thread trampoline could still call
  // `StoreBindings::bridge()` — that call only ever happens synchronously,
  // from inside a `derec_protocol_*` call on the worker thread, and
  // `drainAndJoin` (part of that same teardown) does not return until every
  // such call has finished.
  std::shared_ptr<ProtocolHost> host(
      new ProtocolHost(result.handle, secretId, invoker, state, std::move(stores)),
      [bridge](ProtocolHost* p) mutable {
        delete p;
        // `bridge` (captured by value) is released only after the `delete`
        // above returns, i.e. only after `~ProtocolHost` has fully run.
      });

  return jsi::Object::createFromHostObject(rt, std::move(host));
}

}  // namespace

void registerInstance(const std::shared_ptr<InstanceState>& state) {
  std::lock_guard<std::mutex> lock(registryMutex());
  registry().push_back(state);
}

void invalidateAll() {
  std::lock_guard<std::mutex> lock(registryMutex());
  for (auto& weak : registry()) {
    if (auto state = weak.lock()) {
      // The runtime itself is going away, not just one protocol instance:
      // work already queued onto the JavaScript thread must be abandoned
      // rather than run, and the JavaScript values it retains must be leaked
      // rather than released.
      state->invalidateRuntime();
    }
  }
  registry().clear();
}

void install(jsi::Runtime& rt, std::shared_ptr<Invoker> invoker) {
  // `install` runs on the JavaScript thread by construction, so this is the
  // one place that can record which thread that is. `JsCallbackBridge::
  // callSync` asserts against it in debug builds.
  noteJsThread();

  auto host = jsi::Object(rt);

  host.setProperty(
      rt, "version",
      jsi::Function::createFromHostFunction(
          rt, jsi::PropNameID::forAscii(rt, "version"), 0,
          [](jsi::Runtime& rt, const jsi::Value&, const jsi::Value*, size_t)
              -> jsi::Value {
            DeRecProtocolVersion version = derec_protocol_version();
            std::string text = std::to_string(version.major) + "." +
                               std::to_string(version.minor);
            return jsi::String::createFromUtf8(rt, text);
          }));

  installPrimitives(rt, host);

  host.setProperty(
      rt, "protocol_new",
      jsi::Function::createFromHostFunction(
          rt, jsi::PropNameID::forAscii(rt, "protocol_new"), 3,
          [invoker](jsi::Runtime& rt2, const jsi::Value& thisVal, const jsi::Value* args,
                    size_t count) -> jsi::Value {
            return protocolNew(rt2, invoker, thisVal, args, count);
          }));

  rt.global().setProperty(rt, "__DeRec", std::move(host));
}

}  // namespace derec
