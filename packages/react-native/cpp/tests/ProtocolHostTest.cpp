// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "../JsCallbackBridge.h"
#include "../WorkerThread.h"
#include "TestMain.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>

// NOTE ON SCOPE: nothing in this file links or executes `ProtocolHost.cpp`
// or `StoreCallbacks.cpp` — there is no `jsi::Runtime` available to this
// standalone harness. `handleIsFreedOnlyAfterWorkerDrains`,
// `invalidationPrecedesDrain`, `storeCallbackScopeIsPerThread` and
// `runtimeInvalidationIsDistinctFromInstanceTeardown` exercise the real
// `InstanceState`, `StoreCallbackScope` and `WorkerThread` classes directly.
// `unknownExceptionsStillSettle` also drives a real `WorkerThread`, but the
// `body`/`FfiFailureMarker`/settle plumbing around it is a model of
// `ProtocolHost::runAsync`'s shape, not the real code.
// `storeBindingsSurvivesQueuedCallbackAfterOwnerReleases` models the
// `enable_shared_from_this` fix for Finding B against a stand-in type — it
// does not construct a real `StoreBindings`, which requires a `jsi::Runtime`
// to build.

using namespace derec;
using derec::testing::expect;

/// Mirrors ProtocolHost's teardown ordering without requiring a JSI runtime:
/// invalidate, drain the worker, then release the handle.
struct TeardownHarness {
  std::shared_ptr<InstanceState> state = std::make_shared<InstanceState>();
  WorkerThread worker{"derec-teardown"};
  std::atomic<bool> handleFreed{false};
  std::atomic<bool> workerTouchedHandleAfterFree{false};

  void teardown() {
    state->invalidate();
    worker.drainAndJoin();
    handleFreed = true;
  }
};

static void handleIsFreedOnlyAfterWorkerDrains() {
  TeardownHarness h;
  std::atomic<int> ran{0};

  for (int i = 0; i < 5; ++i) {
    h.worker.post([&] {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      if (h.handleFreed.load()) {
        h.workerTouchedHandleAfterFree = true;
      }
      ++ran;
    });
  }

  h.teardown();

  expect(ran == 5, "every queued call completed before teardown finished");
  expect(!h.workerTouchedHandleAfterFree.load(),
         "no worker task ran after the handle was freed");
}

static void invalidationPrecedesDrain() {
  TeardownHarness h;
  std::atomic<bool> sawInvalidated{false};

  h.worker.post([&] {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    sawInvalidated = h.state->invalidated.load();
  });

  h.teardown();

  expect(sawInvalidated.load(),
         "in-flight work observes invalidation before the drain completes");
}

/// The re-entrancy gate `ProtocolHost::runAsync` and `free()` consult is
/// exactly `isInsideStoreCallback()`, which is per-thread and scoped to a
/// store callback body. Asserts both that a raised scope is visible to the
/// thread inside it and that it is invisible to every other thread — the
/// property that stops an unrelated concurrent call from being rejected.
static void storeCallbackScopeIsPerThread() {
  expect(!isInsideStoreCallback(), "no scope is raised by default");

  std::atomic<bool> otherThreadSawScope{true};
  {
    StoreCallbackScope scope;
    expect(isInsideStoreCallback(), "the scope is visible on the thread that raised it");

    std::thread other([&] { otherThreadSawScope = isInsideStoreCallback(); });
    other.join();

    {
      StoreCallbackScope nested;
      expect(isInsideStoreCallback(), "nesting keeps the scope raised");
    }
    expect(isInsideStoreCallback(), "leaving a nested scope does not clear the outer one");
  }

  expect(!otherThreadSawScope.load(),
         "a concurrent thread is not treated as being inside the callback");
  expect(!isInsideStoreCallback(), "the scope clears when the callback body returns");
}

/// `invalidateRuntime` is what `invalidateAll` calls on the React Native
/// reload path; an ordinary instance teardown calls `invalidate`. The
/// settlement lambda in `ProtocolHost::runAsync` keys off the stronger flag,
/// so a plain teardown must not raise it — otherwise a Promise already owed
/// to a caller would never settle.
static void runtimeInvalidationIsDistinctFromInstanceTeardown() {
  auto state = std::make_shared<InstanceState>();
  state->invalidate();
  expect(state->invalidated.load(), "instance teardown marks the instance dead");
  expect(!state->runtimeInvalidated.load(),
         "instance teardown does not claim the runtime is gone");

  auto reloaded = std::make_shared<InstanceState>();
  reloaded->invalidateRuntime();
  expect(reloaded->runtimeInvalidated.load(), "the reload path marks the runtime gone");
  expect(reloaded->invalidated.load(),
         "marking the runtime gone also marks the instance dead");
}

/// Stand-in for `ProtocolHost.cpp`'s internal `FfiFailure` marker, used only
/// to distinguish "a recognised failure shape" from "something else entirely"
/// in the model below.
struct FfiFailureMarker {};

/// MODELS Finding D.1's fix; does not execute `ProtocolHost.cpp`.
///
/// `runAsync`'s worker-thread step must catch more than its `FfiFailure`
/// marker: anything else escaping `body()` (a `std::bad_alloc` from
/// `takeBuffer`, or any other exception) would otherwise propagate into
/// `WorkerThread::loop`'s own catch-all — added specifically to stop
/// `std::terminate` — which discards it silently before the settlement hop
/// ever runs. That leaves the awaiting Promise pending forever. This test
/// reproduces the same try/catch/settle shape against a real `WorkerThread`
/// with a `body` that throws something other than the recognised failure
/// marker, and asserts the settlement path still reports a failure instead
/// of never running.
static void unknownExceptionsStillSettle() {
  WorkerThread worker("derec-unknown-exception");
  std::mutex m;
  std::condition_variable cv;
  bool settled = false;
  bool succeeded = false;
  bool sawUnknownFailure = false;

  std::function<void()> body = [] { throw std::runtime_error("not an FfiFailure"); };

  bool accepted = worker.post([&] {
    bool failed = false;
    bool unknownFailure = false;
    try {
      body();
    } catch (const FfiFailureMarker&) {
      failed = true;
    } catch (...) {
      unknownFailure = true;
    }
    std::lock_guard<std::mutex> lock(m);
    succeeded = !failed && !unknownFailure;
    sawUnknownFailure = unknownFailure;
    settled = true;
    cv.notify_all();
  });
  expect(accepted, "post is accepted before the worker is drained");

  std::unique_lock<std::mutex> lock(m);
  cv.wait_for(lock, std::chrono::seconds(5), [&] { return settled; });
  worker.drainAndJoin();

  expect(settled, "the settlement runs even when body() throws something other than "
                  "the recognised failure marker");
  expect(!succeeded, "an unknown exception must never be reported as success");
  expect(sawUnknownFailure, "an unknown exception is classified distinctly from a "
                            "recognised failure, so it can be reported instead of "
                            "silently discarded");
}

/// Stand-in for `StoreBindings` — has an `enable_shared_from_this` base and
/// nothing else, since exercising the real class needs a `jsi::Runtime` this
/// harness does not have.
struct FakeStoreBindings : public std::enable_shared_from_this<FakeStoreBindings> {
  explicit FakeStoreBindings(std::atomic<bool>& destroyedFlag) : destroyedFlag_(destroyedFlag) {}
  ~FakeStoreBindings() { destroyedFlag_ = true; }
  std::atomic<bool>& destroyedFlag_;
};

/// MODELS Finding B's fix; does not construct a real `StoreBindings` or run
/// any `StoreCallbacks.cpp` trampoline.
///
/// Reproduces the exact hazard and its fix: a "trampoline" recovers
/// `shared_from_this()` and captures THAT (not a raw pointer) into a task
/// handed to a stand-in for the JavaScript `CallInvoker`'s queue. The owning
/// `shared_ptr` is then released — mirroring `ProtocolHost::teardown`
/// destroying `stores_` once `drainAndJoin` returns — while the queued task
/// still holds its own reference. The object must survive until the queued
/// task actually runs and drops that reference, which in the real fix is the
/// point at which the retained `shared_ptr<jsi::Object>` JS stores are
/// released, on the JavaScript thread.
static void storeBindingsSurvivesQueuedCallbackAfterOwnerReleases() {
  std::atomic<bool> destroyed{false};
  auto owner = std::make_shared<FakeStoreBindings>(destroyed);

  std::function<void()> queuedOnCallInvoker;
  {
    auto keepAlive = owner->shared_from_this();
    expect(owner.use_count() == 2, "shared_from_this adds a reference the trampoline holds");
    queuedOnCallInvoker = [keepAlive] {
      // Runs later, once the JS CallInvoker's queue gets to it.
    };
  }
  expect(owner.use_count() == 2,
         "the queued task's own captured shared_ptr keeps the refcount up "
         "after the trampoline's local copy goes out of scope");

  owner.reset();
  expect(!destroyed.load(),
         "the object is not destroyed while the CallInvoker's queue still "
         "holds a shared_from_this() reference to it");

  queuedOnCallInvoker();
  queuedOnCallInvoker = nullptr;
  expect(destroyed.load(),
         "the object is destroyed once the last queued reference to it is released");
}

int main() {
  derec::testing::run("handleIsFreedOnlyAfterWorkerDrains",
                      handleIsFreedOnlyAfterWorkerDrains);
  derec::testing::run("invalidationPrecedesDrain", invalidationPrecedesDrain);
  derec::testing::run("storeCallbackScopeIsPerThread", storeCallbackScopeIsPerThread);
  derec::testing::run("runtimeInvalidationIsDistinctFromInstanceTeardown",
                      runtimeInvalidationIsDistinctFromInstanceTeardown);
  derec::testing::run("unknownExceptionsStillSettle", unknownExceptionsStillSettle);
  derec::testing::run("storeBindingsSurvivesQueuedCallbackAfterOwnerReleases",
                      storeBindingsSurvivesQueuedCallbackAfterOwnerReleases);
  return derec::testing::summary();
}
