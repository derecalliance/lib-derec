// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#pragma once

#include <jsi/jsi.h>

#include <functional>
#include <memory>

#include "JsCallbackBridge.h"

extern "C" {
#include "derec_ffi.h"
}

namespace derec {

/// Converts a settled callback's resolved value (or a plain, non-thenable
/// return) into the opaque payload the blocked protocol worker decodes once
/// `JsCallbackBridge::callSync` returns. Each callback defines its own
/// encoding for this payload — raw bytes for a byte-returning store method,
/// a single flag byte for a boolean, four little-endian bytes for a version
/// — since `CallResult` itself has no opinion on what "bytes" means.
using ResultConverter =
    std::function<CallResult(facebook::jsi::Runtime&, const facebook::jsi::Value&)>;

/// Owns the six `#[repr(C)]` store/transport callback structs the protocol
/// invokes synchronously, and retains the JavaScript objects those callbacks
/// dispatch to so they outlive the protocol handle.
///
/// Every function-pointer field across the six structs is `user_data ==
/// this`; every struct that has a `free_buffer` field points it at
/// `storeFreeBuffer`, the sole releaser for buffers this binding allocates
/// via `allocBytes`.
///
/// Inherits `enable_shared_from_this` because a store callback's body is
/// captured by value into `JsCallbackBridge::callSync`'s argument, which in
/// turn is captured into the JavaScript `CallInvoker`'s own queue — a queue
/// this binding does not control and that can still hold a scheduled task
/// after `ProtocolHost::teardown` has drained its own worker and destroyed
/// its `StoreBindings`. Each trampoline captures `shared_from_this()` rather
/// than the raw `this` recovered from `user_data`, so the queued task keeps
/// this object (and the `shared_ptr<jsi::Object>` stores it holds) alive
/// until the task actually runs and releases its own copy — on the
/// JavaScript thread, which is where those references need to be dropped.
class StoreBindings : public std::enable_shared_from_this<StoreBindings> {
 public:
  /// `stores` must carry one property per store — `channelStore`,
  /// `shareStore`, `secretStore`, `userSecretStore`, `stateStore`,
  /// `transport` — each a JS object implementing the corresponding
  /// interface from `src/types.ts`. Throws a `jsi::JSError` naming the first
  /// missing store, and again if any callback struct ends up with an unset
  /// member (a build-time contract violation, not a caller error, but
  /// reported the same way since both are equally fatal to the handle).
  static std::shared_ptr<StoreBindings> create(facebook::jsi::Runtime& rt,
                                                facebook::jsi::Object& stores,
                                                JsCallbackBridge& bridge,
                                                std::shared_ptr<InstanceState> state);

  const ChannelStoreCallbacks* channel() const { return &channelCallbacks_; }
  const SecretStoreCallbacks* secret() const { return &secretCallbacks_; }
  const ShareStoreCallbacks* share() const { return &shareCallbacks_; }
  const UserSecretStoreCallbacks* userSecret() const { return &userSecretCallbacks_; }
  const StateStoreCallbacks* state() const { return &stateCallbacks_; }
  const TransportCallbacks* transport() const { return &transportCallbacks_; }

  facebook::jsi::Runtime& runtime() const { return rt_; }
  JsCallbackBridge& bridge() const { return bridge_; }
  const std::shared_ptr<InstanceState>& instanceState() const { return instanceState_; }

  const std::shared_ptr<facebook::jsi::Object>& channelStore() const { return channelStore_; }
  const std::shared_ptr<facebook::jsi::Object>& secretStore() const { return secretStore_; }
  const std::shared_ptr<facebook::jsi::Object>& shareStore() const { return shareStore_; }
  const std::shared_ptr<facebook::jsi::Object>& userSecretStore() const {
    return userSecretStore_;
  }
  const std::shared_ptr<facebook::jsi::Object>& stateStore() const { return stateStore_; }
  const std::shared_ptr<facebook::jsi::Object>& transportStore() const { return transport_; }

  /// Settle a callback body's promise (or plain, non-thenable return value)
  /// through `convert`, dispatching via `then` only when the value is
  /// actually thenable. `convert` runs on the JavaScript thread, with `rt`
  /// live, before `settle` is invoked — never after.
  void settleFromPromise(facebook::jsi::Runtime& rt, facebook::jsi::Value value,
                          std::function<void(CallResult)> settle, ResultConverter convert);

 private:
  StoreBindings(facebook::jsi::Runtime& rt, JsCallbackBridge& bridge,
                std::shared_ptr<InstanceState> state);

  facebook::jsi::Runtime& rt_;
  JsCallbackBridge& bridge_;
  std::shared_ptr<InstanceState> instanceState_;

  std::shared_ptr<facebook::jsi::Object> channelStore_;
  std::shared_ptr<facebook::jsi::Object> secretStore_;
  std::shared_ptr<facebook::jsi::Object> shareStore_;
  std::shared_ptr<facebook::jsi::Object> userSecretStore_;
  std::shared_ptr<facebook::jsi::Object> stateStore_;
  std::shared_ptr<facebook::jsi::Object> transport_;

  ChannelStoreCallbacks channelCallbacks_{};
  SecretStoreCallbacks secretCallbacks_{};
  ShareStoreCallbacks shareCallbacks_{};
  UserSecretStoreCallbacks userSecretCallbacks_{};
  StateStoreCallbacks stateCallbacks_{};
  TransportCallbacks transportCallbacks_{};
};

}  // namespace derec
