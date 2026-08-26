// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#import "DeRec.h"

#import "DeRecInstaller.h"
#import "RuntimeInvoker.h"

@implementation DeRec

RCT_EXPORT_MODULE()

+ (BOOL)requiresMainQueueSetup {
  return YES;
}

// No methods are exported: JavaScript reaches the SDK through the `__DeRec`
// host object, not through this module. The bare `ObjCTurboModule` exists so
// the manager takes the TurboModule path, which is the only path that calls
// `installJSIBindingsWithRuntime:callInvoker:`.
- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params {
  return std::make_shared<facebook::react::ObjCTurboModule>(params);
}

- (void)installJSIBindingsWithRuntime:(facebook::jsi::Runtime &)runtime
                          callInvoker:
                              (const std::shared_ptr<facebook::react::CallInvoker> &)callInvoker {
  auto invoker = std::make_shared<derec::RuntimeInvoker>(callInvoker);
  derec::install(runtime, invoker);
}

- (void)invalidate {
  // The runtime is going away: wake every worker blocked in a store callback
  // so it unwinds rather than hanging on a condition variable forever.
  derec::invalidateAll();
}

@end
