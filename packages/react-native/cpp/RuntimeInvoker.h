// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <ReactCommon/CallInvoker.h>

#include <memory>
#include <utility>

#include "Invoker.h"

namespace derec {

/// Adapts React Native's `CallInvoker` to the binding's `Invoker` seam.
class RuntimeInvoker : public Invoker {
 public:
  explicit RuntimeInvoker(std::shared_ptr<facebook::react::CallInvoker> inner)
      : inner_(std::move(inner)) {}

  void invokeAsync(std::function<void()> work) override {
    inner_->invokeAsync(std::move(work));
  }

 private:
  std::shared_ptr<facebook::react::CallInvoker> inner_;
};

}  // namespace derec
