// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "JsCallbackBridge.h"

#include <cassert>
#include <mutex>
#include <utility>

namespace derec {

namespace {

/// One in-flight callback. Heap-allocated and shared so a settlement arriving
/// after a timeout writes into live memory rather than a dead stack frame.
///
/// Both fields are guarded by the owning `InstanceState`'s mutex; the slot
/// carries no lock of its own so that a waiter and `InstanceState::invalidate`
/// synchronise on the same condition variable.
struct CallSlot {
  bool done = false;
  CallResult result{kBackendFailure, {}};
};

/// Written once, from `noteJsThread`, and published by the release store to
/// `jsThreadKnown` below; readers acquire it. Not a `thread::id` atomic
/// because `std::thread::id` is not guaranteed lock-free.
std::thread::id& jsThreadId() {
  static std::thread::id id;
  return id;
}

std::atomic<bool>& jsThreadKnown() {
  static std::atomic<bool> known{false};
  return known;
}

int& storeCallbackDepth() {
  static thread_local int depth = 0;
  return depth;
}

}  // namespace

void InstanceState::invalidate() {
  {
    std::lock_guard<std::mutex> lock(m);
    invalidated.store(true);
  }
  cv.notify_all();
}

void InstanceState::invalidateRuntime() {
  {
    std::lock_guard<std::mutex> lock(m);
    runtimeInvalidated.store(true);
    invalidated.store(true);
  }
  cv.notify_all();
}

void noteJsThread() {
  jsThreadId() = std::this_thread::get_id();
  jsThreadKnown().store(true, std::memory_order_release);
}

bool isJsThread() {
  if (!jsThreadKnown().load(std::memory_order_acquire)) {
    return false;
  }
  return std::this_thread::get_id() == jsThreadId();
}

bool isInsideStoreCallback() { return storeCallbackDepth() > 0; }

StoreCallbackScope::StoreCallbackScope() { ++storeCallbackDepth(); }

StoreCallbackScope::~StoreCallbackScope() { --storeCallbackDepth(); }

JsCallbackBridge::JsCallbackBridge(Invoker& invoker,
                                   std::shared_ptr<InstanceState> state,
                                   std::chrono::milliseconds timeout)
    : invoker_(invoker), state_(std::move(state)), timeout_(timeout) {}

CallResult JsCallbackBridge::callSync(
    std::function<void(std::function<void(CallResult)>)> body) {
  // Blocking here on the JavaScript thread would wait for a settlement that
  // only the JavaScript thread can produce. Debug-only: a release build must
  // not pay for the check, and there is no correct recovery anyway.
  assert(!isJsThread() &&
         "JsCallbackBridge::callSync must not run on the JavaScript thread");

  if (state_->invalidated.load()) {
    return CallResult{kBackendFailure, {}};
  }

  auto slot = std::make_shared<CallSlot>();
  // The scheduled work owns a reference to the instance state: it must be able
  // to take the mutex even if the bridge and its owner are already gone.
  auto state = state_;

  invoker_.invokeAsync([slot, state, body = std::move(body)]() mutable {
    auto settle = [slot, state](CallResult result) {
      {
        std::lock_guard<std::mutex> lock(state->m);
        if (slot->done) {
          return;  // a timeout or an invalidation already resolved this slot
        }
        slot->result = std::move(result);
        slot->done = true;
      }
      state->cv.notify_all();
    };

    // A JavaScript store that throws synchronously must not escape into the
    // runtime's dispatch loop; report it as a backend failure instead.
    try {
      // Marks exactly the window in which a protocol call made from this
      // thread would be genuinely re-entrant: the store body's own execution.
      // It ends when `body` returns, even though the worker stays parked
      // until the Promise the store handed back settles.
      StoreCallbackScope scope;
      body(settle);
    } catch (...) {
      settle(CallResult{kBackendFailure, {}});
    }
  });

  std::unique_lock<std::mutex> lock(state_->m);
  state_->cv.wait_for(lock, timeout_, [this, &slot] {
    return slot->done || state_->invalidated.load();
  });

  if (!slot->done) {
    // Timed out or invalidated. Mark the slot resolved under the same lock so
    // a late settlement becomes a no-op, and report a backend failure — never
    // `1`, which would tell the protocol a stored share is absent.
    slot->done = true;
    return CallResult{kBackendFailure, {}};
  }
  return std::move(slot->result);
}

}  // namespace derec
