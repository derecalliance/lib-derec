// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "../JsCallbackBridge.h"
#include "../WorkerThread.h"
#include "TestMain.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <thread>

using namespace derec;
using derec::testing::expect;

/// Stands in for RN's CallInvoker: runs work on a dedicated "JS" thread.
class FakeInvoker : public Invoker {
 public:
  FakeInvoker() : running_(true), thread_([this] { loop(); }) {}

  ~FakeInvoker() override {
    {
      std::lock_guard<std::mutex> lock(m_);
      running_ = false;
    }
    cv_.notify_all();
    thread_.join();
  }

  void invokeAsync(std::function<void()> work) override {
    {
      std::lock_guard<std::mutex> lock(m_);
      queue_.push_back(std::move(work));
    }
    cv_.notify_one();
  }

  /// Stop servicing work, simulating a destroyed runtime.
  void stall() {
    std::lock_guard<std::mutex> lock(m_);
    stalled_ = true;
  }

 private:
  void loop() {
    for (;;) {
      std::function<void()> work;
      {
        std::unique_lock<std::mutex> lock(m_);
        cv_.wait(lock, [this] { return !running_ || (!queue_.empty() && !stalled_); });
        if (!running_) return;
        if (stalled_ || queue_.empty()) continue;
        work = std::move(queue_.front());
        queue_.pop_front();
      }
      work();
    }
  }

  std::mutex m_;
  std::condition_variable cv_;
  std::deque<std::function<void()>> queue_;
  bool running_;
  bool stalled_ = false;
  std::thread thread_;
};

static void resolvesWithBytes() {
  FakeInvoker invoker;
  auto state = std::make_shared<InstanceState>();
  JsCallbackBridge bridge(invoker, state);

  CallResult result = bridge.callSync([](std::function<void(CallResult)> settle) {
    settle(CallResult{0, {1, 2, 3}});
  });

  expect(result.code == 0, "success code propagates");
  expect(result.bytes.size() == 3, "payload length propagates");
  expect(result.bytes[2] == 3, "payload contents propagate");
}

static void propagatesRejection() {
  FakeInvoker invoker;
  auto state = std::make_shared<InstanceState>();
  JsCallbackBridge bridge(invoker, state);

  CallResult result = bridge.callSync([](std::function<void(CallResult)> settle) {
    settle(CallResult{kBackendFailure, {}});
  });

  expect(result.code == kBackendFailure, "rejection maps to backend failure");
}

static void notFoundIsPreserved() {
  FakeInvoker invoker;
  auto state = std::make_shared<InstanceState>();
  JsCallbackBridge bridge(invoker, state);

  CallResult result = bridge.callSync([](std::function<void(CallResult)> settle) {
    settle(CallResult{1, {}});
  });

  expect(result.code == 1, "an explicit not-found is passed through untouched");
}

static void invalidationWakesABlockedWorker() {
  FakeInvoker invoker;
  auto state = std::make_shared<InstanceState>();
  JsCallbackBridge bridge(invoker, state);

  invoker.stall();  // the JS thread will never run our lambda

  std::thread waker([state] {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    state->invalidate();
  });

  auto began = std::chrono::steady_clock::now();
  CallResult result = bridge.callSync([](std::function<void(CallResult)> settle) {
    settle(CallResult{0, {9}});
  });
  auto elapsed = std::chrono::steady_clock::now() - began;
  waker.join();

  expect(result.code == kBackendFailure, "invalidation yields a backend failure");
  expect(result.code != 1, "invalidation must never be reported as not-found");
  expect(elapsed < std::chrono::seconds(5), "invalidation wakes the worker promptly");
}

static void timeoutYieldsBackendFailureNotNotFound() {
  FakeInvoker invoker;
  auto state = std::make_shared<InstanceState>();
  // A deliberately short timeout keeps the test fast; production uses
  // kStoreTimeout.
  JsCallbackBridge bridge(invoker, state, std::chrono::milliseconds(100));

  invoker.stall();

  CallResult result = bridge.callSync([](std::function<void(CallResult)> settle) {
    settle(CallResult{0, {7}});
  });

  expect(result.code == kBackendFailure, "timeout yields a backend failure");
  expect(result.code != 1, "timeout must never be reported as not-found");
}

/// The re-entrancy gate must be raised for the store body itself and for
/// nothing else. Drives a real `JsCallbackBridge` against a real "JS" thread
/// and samples `isInsideStoreCallback()` at the three points that matter:
/// inside the body, on later JavaScript-thread work that runs while the
/// caller is still parked in `callSync`, and on the calling (worker) thread.
/// Only the first may be true — the second is precisely the case the broad
/// instance-wide gate used to reject.
static void reentrancyGateCoversOnlyTheStoreBody() {
  FakeInvoker invoker;
  auto state = std::make_shared<InstanceState>();
  JsCallbackBridge bridge(invoker, state);

  std::atomic<bool> insideBody{false};
  std::atomic<bool> insideLaterJsWork{true};

  CallResult result = bridge.callSync(
      [&invoker, &insideBody, &insideLaterJsWork](std::function<void(CallResult)> settle) {
        insideBody = isInsideStoreCallback();
        // Stands in for an application store that returns a pending Promise
        // and settles it from a later turn: the JavaScript thread goes on to
        // run unrelated work while the caller stays parked in `callSync`.
        invoker.invokeAsync([&insideLaterJsWork, settle] {
          insideLaterJsWork = isInsideStoreCallback();
          settle(CallResult{0, {5}});
        });
      });

  expect(result.code == 0, "the deferred settlement still reaches the caller");
  expect(insideBody.load(), "the gate is raised while the store body runs");
  expect(!insideLaterJsWork.load(),
         "JavaScript-thread work running after the store body returns is not "
         "treated as re-entrant, even though the caller is still parked");
  expect(!isInsideStoreCallback(),
         "the thread blocked in callSync is never inside a callback body");
}

static void workerRunsOffTheInvokerThread() {
  WorkerThread worker("derec-test");
  std::thread::id workerId;
  std::atomic<bool> done{false};
  worker.post([&] {
    workerId = std::this_thread::get_id();
    done = true;
  });
  while (!done) std::this_thread::yield();
  worker.drainAndJoin();

  expect(workerId != std::this_thread::get_id(),
         "worker executes on its own thread");
}

static void drainRunsQueuedWorkBeforeJoining() {
  WorkerThread worker("derec-test");
  std::atomic<int> counter{0};
  for (int i = 0; i < 10; ++i) {
    bool accepted = worker.post([&counter] { ++counter; });
    expect(accepted, "post before draining is accepted");
  }
  worker.drainAndJoin();
  expect(counter == 10, "every queued task ran before join");

  // Draining twice must be safe, and work posted afterwards is dropped rather
  // than crashing on a joined thread.
  worker.drainAndJoin();
  bool acceptedAfterDrain = worker.post([&counter] { ++counter; });
  expect(!acceptedAfterDrain, "post after draining is refused");
  expect(counter == 10, "post after draining is a no-op");
}

static void workerSurvivesAThrowingTask() {
  WorkerThread worker("derec-test");
  std::atomic<int> ran{0};

  // A posted task reaches into JSI, where a thrown `jsi::JSError` is a live
  // possibility. Letting it escape the thread function would call
  // std::terminate and kill the application.
  worker.post([] { throw std::runtime_error("a store callback blew up"); });
  worker.post([&ran] { ++ran; });
  worker.post([] { throw 42; });  // a non-std exception must not terminate either
  worker.post([&ran] { ++ran; });
  worker.drainAndJoin();

  expect(ran == 2, "the worker keeps servicing the queue after a task throws");
}

int main() {
  derec::testing::run("resolvesWithBytes", resolvesWithBytes);
  derec::testing::run("propagatesRejection", propagatesRejection);
  derec::testing::run("notFoundIsPreserved", notFoundIsPreserved);
  derec::testing::run("invalidationWakesABlockedWorker", invalidationWakesABlockedWorker);
  derec::testing::run("timeoutYieldsBackendFailureNotNotFound",
                      timeoutYieldsBackendFailureNotNotFound);
  derec::testing::run("reentrancyGateCoversOnlyTheStoreBody",
                      reentrancyGateCoversOnlyTheStoreBody);
  derec::testing::run("workerRunsOffTheInvokerThread", workerRunsOffTheInvokerThread);
  derec::testing::run("drainRunsQueuedWorkBeforeJoining", drainRunsQueuedWorkBeforeJoining);
  derec::testing::run("workerSurvivesAThrowingTask", workerSurvivesAThrowingTask);
  return derec::testing::summary();
}
