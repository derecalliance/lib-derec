// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "Invoker.h"

namespace derec {

/// Store-callback return code for a backend failure. `0` means success and
/// `1` means "not found" (load-family only); every other value is a backend
/// failure, so any value >= 2 is equivalent here.
constexpr int32_t kBackendFailure = 2;

/// Liveness backstop for a JavaScript store that never settles. Generous
/// enough for disk and keychain access. Not application-configurable: it is a
/// binding-level guard, not a protocol parameter.
constexpr std::chrono::seconds kStoreTimeout{30};

struct CallResult {
  int32_t code;
  std::vector<uint8_t> bytes;
};

/// Shared per-protocol-instance liveness flag. Set when the JavaScript
/// runtime goes away so blocked workers can unwind instead of hanging.
///
/// The instance also owns the synchronisation primitives that every in-flight
/// callback for that instance waits on. Keeping the mutex and condition
/// variable here — rather than on the individual call — is what lets
/// `invalidate` wake a worker that is blocked inside `JsCallbackBridge::
/// callSync`: a waiter and the invalidator must share one condition variable
/// for the notification to reach the waiter at all.
///
/// Held by `shared_ptr` because a settlement scheduled onto the JavaScript
/// thread may arrive after the bridge that started it is gone, and that
/// settlement still needs the mutex.
struct InstanceState {
  std::atomic<bool> invalidated{false};

  /// Set only when the JavaScript runtime itself is going away (the React
  /// Native reload / bridge-invalidate path), never by an ordinary
  /// `free()`/destructor teardown of a single protocol instance.
  ///
  /// The distinction matters because the two cases demand opposite
  /// behaviour from work already scheduled onto the JavaScript thread. After
  /// a plain instance teardown the runtime is still alive, so a settlement
  /// that is already queued must still run — otherwise the Promise a caller
  /// is awaiting never settles. Once the runtime is gone, that same
  /// settlement must not run at all, and the JavaScript values it retains
  /// must not be released either, because both would call back into a
  /// runtime that is being torn down.
  std::atomic<bool> runtimeInvalidated{false};

  std::mutex m;
  std::condition_variable cv;

  /// Mark the instance dead and wake every blocked waiter. The flag is set
  /// under `m` so a waiter cannot evaluate its predicate between the store and
  /// the notification and then sleep through the wake-up.
  void invalidate();

  /// `invalidate`, plus the stronger statement that the JavaScript runtime is
  /// going away. Both flags are set under `m` in one critical section so a
  /// waiter that wakes on `invalidated` can never observe it without also
  /// observing `runtimeInvalidated`.
  void invalidateRuntime();
};

/// Record the calling thread as the JavaScript thread. Called once from
/// `install`, which by construction runs on it.
void noteJsThread();

/// True when the calling thread is the one `noteJsThread` recorded. False
/// until `install` has run, so a caller must treat it as advisory.
bool isJsThread();

/// True while this thread is executing the synchronous body of a store
/// callback — that is, the JavaScript call into an application store, up to
/// the point that call returns (typically a pending Promise).
///
/// This is deliberately narrower than "the worker is parked in a callback".
/// A protocol call issued from ordinary JavaScript-thread work that merely
/// happens to overlap a parked worker is safe: the serial worker runs it
/// after the current call finishes. Only a call issued from inside the store
/// body itself can deadlock, because that body's own completion is what the
/// worker is waiting for.
bool isInsideStoreCallback();

/// Raises `isInsideStoreCallback` for the calling thread over its lifetime.
/// Nests, so a store body that legitimately drives another one is counted
/// correctly.
class StoreCallbackScope {
 public:
  StoreCallbackScope();
  ~StoreCallbackScope();

  StoreCallbackScope(const StoreCallbackScope&) = delete;
  StoreCallbackScope& operator=(const StoreCallbackScope&) = delete;
};

/// Adapts Rust's synchronous store/transport callbacks to the SDK's
/// asynchronous JavaScript store interfaces.
///
/// Called from the protocol worker thread, never from the JavaScript thread —
/// blocking the JavaScript thread here would deadlock, since the settlement
/// that unblocks the wait is itself scheduled onto that thread. `callSync`
/// asserts this in debug builds against the thread `noteJsThread` recorded.
class JsCallbackBridge {
 public:
  JsCallbackBridge(Invoker& invoker,
                   std::shared_ptr<InstanceState> state,
                   std::chrono::milliseconds timeout =
                       std::chrono::duration_cast<std::chrono::milliseconds>(kStoreTimeout));

  /// Run `body` on the JavaScript thread and block until it settles.
  ///
  /// `body` receives a settle function it must invoke exactly once, from any
  /// thread. Returns a backend failure if the instance is invalidated or the
  /// timeout elapses — never `1`, because a fabricated "not found" would make
  /// a stored share look absent and corrupt a recovery outcome.
  ///
  /// `body` must capture everything it touches by value or by `shared_ptr`,
  /// never by reference to the caller's stack. Giving up on a call does not
  /// cancel it: on timeout or invalidation `callSync` returns while `body` is
  /// still queued on the JavaScript thread, so `body` and its captures must
  /// stay valid after `callSync` has returned and the caller's frame is gone.
  /// The same applies to the settle function, which may be invoked after the
  /// return; a late settlement is discarded, but it still runs.
  CallResult callSync(std::function<void(std::function<void(CallResult)>)> body);

 private:
  Invoker& invoker_;
  std::shared_ptr<InstanceState> state_;
  std::chrono::milliseconds timeout_;
};

}  // namespace derec
