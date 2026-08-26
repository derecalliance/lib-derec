// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <jsi/jsi.h>

#include <memory>

#include "Invoker.h"
#include "JsCallbackBridge.h"

namespace derec {

/// Install the `__DeRec` host object into `rt`.
///
/// `invoker` must schedule work on the same JavaScript thread that owns `rt`.
void install(facebook::jsi::Runtime& rt, std::shared_ptr<Invoker> invoker);

/// Signal that the JavaScript runtime is going away. Wakes every protocol
/// instance blocked in a store callback so their workers can unwind instead
/// of hanging.
void invalidateAll();

/// Track a protocol instance so `invalidateAll` can reach it at teardown.
void registerInstance(const std::shared_ptr<InstanceState>& state);

}  // namespace derec
