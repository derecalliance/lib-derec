// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <jsi/jsi.h>

#include <memory>
#include <string>

#include "Invoker.h"
#include "JsCallbackBridge.h"
#include "StoreCallbacks.h"
#include "WorkerThread.h"

extern "C" {
#include "derec_ffi.h"
}

namespace derec {

/// One `DeRecProtocol` instance exposed to JavaScript.
///
/// All `derec_protocol_*` calls run on `worker_`, never on the JavaScript
/// thread: store callbacks re-enter JavaScript and block the calling thread
/// until they settle, so running them on the JavaScript thread would deadlock.
///
/// `~ProtocolHost` is not guaranteed to run on the JavaScript thread: JSI's
/// own contract for `HostObject` says finalization "may be as late as when
/// the Runtime is shut down" and gives "no control over which thread it is
/// called on." The destructor therefore touches no `jsi::Runtime` and makes
/// no JSI call — `invalidate`, `drainAndJoin` and `derec_protocol_free` are
/// all plain native calls. Destroying `stores_` (dropping its
/// `shared_ptr<jsi::Object>` references to the application's JS stores) is
/// safe under the same contract, which explicitly permits "calling the dtor
/// on a jsi object" from any thread.
class ProtocolHost : public facebook::jsi::HostObject {
 public:
  ProtocolHost(DeRecProtocolHandle* handle,
               uint64_t secretId,
               std::shared_ptr<Invoker> invoker,
               std::shared_ptr<InstanceState> state,
               std::shared_ptr<StoreBindings> stores);

  ~ProtocolHost() override;

  facebook::jsi::Value get(facebook::jsi::Runtime& rt,
                           const facebook::jsi::PropNameID& name) override;

  std::vector<facebook::jsi::PropNameID> getPropertyNames(
      facebook::jsi::Runtime& rt) override;

 private:
  /// Run `body` on the worker thread and resolve a JavaScript Promise with
  /// its result. `body` returns the raw bytes or JSON the JavaScript side
  /// converts; it must not touch the runtime. Throws synchronously — before
  /// any Promise is created — if this instance has been freed, or if the
  /// calling thread is itself executing a store callback body, since
  /// enqueuing onto the worker in that case would deadlock against the very
  /// callback whose completion the worker is blocked waiting on.
  facebook::jsi::Value runAsync(
      facebook::jsi::Runtime& rt,
      std::function<std::vector<uint8_t>()> body,
      std::function<facebook::jsi::Value(facebook::jsi::Runtime&,
                                         std::vector<uint8_t>&)> convert);

  /// Release the handle in the order the FFI's safety contract requires.
  /// Every step is individually idempotent (`invalidate`, `drainAndJoin` and
  /// `derec_protocol_free` all tolerate repeat calls), so this may run once
  /// from an explicit `free()` and again from the destructor.
  void teardown();

  DeRecProtocolHandle* handle_;
  uint64_t secretId_;
  std::shared_ptr<Invoker> invoker_;
  std::shared_ptr<InstanceState> state_;
  // `shared_ptr`, not `unique_ptr`: each store trampoline in `StoreCallbacks.cpp`
  // captures `shared_from_this()` into the lambda it hands to
  // `JsCallbackBridge::callSync`, which the JavaScript `CallInvoker`'s own
  // queue may still be holding after `worker_.drainAndJoin()` returns and this
  // object is torn down. `stores_` merely being an owning reference is what
  // lets that queued task keep `StoreBindings` (and the JS store objects it
  // retains) alive until it actually runs.
  std::shared_ptr<StoreBindings> stores_;
  WorkerThread worker_;
};

}  // namespace derec
