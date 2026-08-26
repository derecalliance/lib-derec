// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace derec {

/// A single serial thread owning all `derec_protocol_*` calls for one
/// protocol instance.
///
/// Serialization is required by the protocol: `tick` mutates the same round
/// state an inbound `process` does, so the two must not interleave for a given
/// `secret_id`. Running them on one serial queue satisfies that structurally.
class WorkerThread {
 public:
  explicit WorkerThread(std::string name);
  ~WorkerThread();

  WorkerThread(const WorkerThread&) = delete;
  WorkerThread& operator=(const WorkerThread&) = delete;

  /// Enqueue work. Returns `true` if it was accepted, `false` if
  /// `drainAndJoin` has already been called — in which case `work` is
  /// dropped rather than run. Callers that need the caller to learn about a
  /// refused task (rather than silently never hearing from it again, as a
  /// dropped store-callback task would) must check this.
  bool post(std::function<void()> work);

  /// Run everything already queued, then stop and join. Idempotent.
  void drainAndJoin();

  /// True when called from this worker's own thread.
  bool isCurrentThread() const;

 private:
  void loop();

  std::string name_;
  mutable std::mutex m_;
  std::condition_variable cv_;
  std::deque<std::function<void()>> queue_;
  bool accepting_ = true;
  bool joined_ = false;
  std::thread thread_;
};

}  // namespace derec
