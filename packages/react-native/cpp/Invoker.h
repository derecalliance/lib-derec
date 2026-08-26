// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <functional>

namespace derec {

/// Abstraction over React Native's `CallInvoker`. Declared as an interface so
/// the callback bridge can be exercised on the host with no JSI runtime.
class Invoker {
 public:
  virtual ~Invoker() = default;

  /// Schedule `work` to run on the JavaScript thread. Must not block.
  virtual void invokeAsync(std::function<void()> work) = 0;
};

}  // namespace derec
