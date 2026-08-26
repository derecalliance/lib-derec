// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "WorkerThread.h"

namespace derec {

WorkerThread::WorkerThread(std::string name) : name_(std::move(name)) {
  thread_ = std::thread([this] { loop(); });
}

WorkerThread::~WorkerThread() { drainAndJoin(); }

bool WorkerThread::post(std::function<void()> work) {
  {
    std::lock_guard<std::mutex> lock(m_);
    if (!accepting_) {
      return false;
    }
    queue_.push_back(std::move(work));
  }
  cv_.notify_one();
  return true;
}

void WorkerThread::drainAndJoin() {
  {
    std::lock_guard<std::mutex> lock(m_);
    if (joined_) {
      return;
    }
    accepting_ = false;
    joined_ = true;
  }
  cv_.notify_all();
  if (thread_.joinable()) {
    thread_.join();
  }
}

bool WorkerThread::isCurrentThread() const {
  return std::this_thread::get_id() == thread_.get_id();
}

void WorkerThread::loop() {
  for (;;) {
    std::function<void()> work;
    {
      std::unique_lock<std::mutex> lock(m_);
      cv_.wait(lock, [this] { return !queue_.empty() || !accepting_; });
      if (queue_.empty()) {
        // Only exit once the queue is drained, so shutdown never discards
        // work that was accepted before `drainAndJoin`.
        return;
      }
      work = std::move(queue_.front());
      queue_.pop_front();
    }
    // An exception escaping the thread function would call std::terminate and
    // take the whole application down, so nothing may propagate past here.
    // Posted work reaches into JSI, where a `jsi::JSError` is a live
    // possibility. There is no channel to report on at this point: the caller
    // that posted the task has already moved on, and any result the task was
    // meant to settle is settled by the callback bridge's own timeout as a
    // backend failure. Dropping the exception and continuing to service the
    // queue is therefore the only behaviour that keeps the instance usable.
    try {
      work();
    } catch (...) {
    }
  }
}

}  // namespace derec
