// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#import <React/RCTBridgeModule.h>
#import <React/RCTInvalidating.h>
#import <ReactCommon/RCTTurboModule.h>
#import <ReactCommon/RCTTurboModuleWithJSIBindings.h>

/// Minimal TurboModule whose only job is to install the `__DeRec` JSI host
/// object into the JavaScript runtime.
///
/// It conforms to `RCTTurboModule` — and so implements `getTurboModule:` —
/// even though it exports no methods. `RCTTurboModuleManager` invokes
/// `installJSIBindingsWithRuntime:callInvoker:` only inside the branch guarded
/// by `respondsToSelector:@selector(getTurboModule:)`; a module registered
/// with `RCT_EXPORT_MODULE()` alone takes the legacy interop path instead and
/// never receives the hook, leaving `globalThis.__DeRec` undefined.
///
/// The pre-0.76 route — casting the bridge to `RCTCxxBridge` and reading its
/// `runtime` property — is not an alternative: there is no `RCTCxxBridge` in a
/// bridgeless app, which is the default from React Native 0.76 onward.
@interface DeRec : NSObject <RCTBridgeModule, RCTTurboModule, RCTTurboModuleWithJSIBindings, RCTInvalidating>
@end
