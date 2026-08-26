// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include "ProtocolHost.h"

#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "Convert.h"
#include "DeRecInstaller.h"
#include "Primitives.h"

using namespace facebook;

namespace derec {

namespace {

/// Carries a Rust `DeRecError` out of a `runAsync` body running on the
/// worker thread, where no `jsi::Runtime` is available to build the
/// JavaScript exception `throwDeRecError` throws. Rebuilt into that exact
/// shape once execution hops back to the JavaScript thread, so a caller
/// never sees a second error shape depending on which thread noticed the
/// failure.
struct FfiFailure {
  explicit FfiFailure(DeRecError e) : error(e) {}
  DeRecError error;
};

constexpr const char* kReentrancyMessage =
    "DeRec: protocol methods cannot be called from inside a store callback";

/// Keeps a JavaScript value alive across a hop to the worker thread and back.
///
/// A bare `jsi::Value` cannot be used for that: its destructor calls into the
/// runtime, and the whole point of retaining one here is that it may outlive
/// the moment the runtime is torn down (React Native reload / bridge
/// invalidate). This wrapper releases the value only while the runtime is
/// known to be alive; once `runtimeInvalidated` is set it deliberately leaks
/// the handle instead. Leaking costs nothing real — the runtime owns the
/// referenced object and frees its entire heap as it shuts down — whereas
/// releasing would call into a runtime that is already gone.
///
/// Note this keys off `runtimeInvalidated`, not `invalidated`: an ordinary
/// `free()` leaves the runtime perfectly alive, and a Promise settlement
/// still owed to a caller must run in that case.
class RetainedJsValue {
 public:
  RetainedJsValue(jsi::Runtime& rt,
                  const jsi::Value& value,
                  std::shared_ptr<InstanceState> state)
      : value_(new jsi::Value(rt, value)), state_(std::move(state)) {}

  RetainedJsValue(const RetainedJsValue&) = delete;
  RetainedJsValue& operator=(const RetainedJsValue&) = delete;

  ~RetainedJsValue() {
    if (state_->runtimeInvalidated.load()) {
      return;  // intentionally not freed; see the class comment
    }
    delete value_;
  }

  const jsi::Value& get() const { return *value_; }

 private:
  jsi::Value* value_;
  std::shared_ptr<InstanceState> state_;
};

void requireArgs(jsi::Runtime& rt, const char* name, size_t count, size_t required) {
  if (count < required) {
    throw jsi::JSError(rt, std::string(name) + " expects " +
                                std::to_string(required) + " arguments");
  }
}

/// Copy a `convert` for the common case: the body's raw bytes are already
/// the exact wire payload the JavaScript side wants, verbatim.
jsi::Value bytesToArrayBuffer(jsi::Runtime& rt, std::vector<uint8_t>& bytes) {
  return toArrayBuffer(rt, bytes.data(), bytes.size());
}

}  // namespace

ProtocolHost::ProtocolHost(DeRecProtocolHandle* handle,
                           uint64_t secretId,
                           std::shared_ptr<Invoker> invoker,
                           std::shared_ptr<InstanceState> state,
                           std::shared_ptr<StoreBindings> stores)
    : handle_(handle),
      secretId_(secretId),
      invoker_(std::move(invoker)),
      state_(std::move(state)),
      stores_(std::move(stores)),
      worker_("derec-protocol-" + std::to_string(secretId)) {
  registerInstance(state_);
}

ProtocolHost::~ProtocolHost() {
  // Order matters. Invalidate first so any worker blocked in a store callback
  // wakes and unwinds; drain so no task can still be inside a
  // `derec_protocol_*` call; only then release the handle. Freeing earlier
  // would let a live worker read freed memory, which the FFI's safety
  // contract explicitly makes the host binding's responsibility to prevent.
  teardown();
}

void ProtocolHost::teardown() {
  state_->invalidate();
  worker_.drainAndJoin();
  derec_protocol_free(handle_);
  handle_ = nullptr;
}

jsi::Value ProtocolHost::runAsync(
    jsi::Runtime& rt,
    std::function<std::vector<uint8_t>()> body,
    std::function<jsi::Value(jsi::Runtime&, std::vector<uint8_t>&)> convert) {
  // A protocol call issued from inside a store callback's own body would
  // enqueue onto the very worker that is blocked waiting for that body's
  // Promise — the worker cannot reach the new task until the store settles,
  // and the store cannot settle if it is waiting on the new task.
  //
  // The gate is deliberately no wider than that. A call made from unrelated
  // JavaScript-thread work that merely overlaps a parked worker is safe:
  // the worker is serial, so the call simply runs after the current one
  // finishes. Rejecting those too would fail ordinary concurrent calls
  // nondeterministically, purely because a flow happened to be in a store
  // callback at that instant.
  if (isInsideStoreCallback()) {
    throw jsi::JSError(rt, kReentrancyMessage);
  }
  if (handle_ == nullptr) {
    throw jsi::JSError(rt, "DeRec: protocol instance has been freed");
  }

  // Everything captured past this point must survive `runAsync` returning
  // and must not depend on this `ProtocolHost` outliving the call: the
  // worker-thread step and the JavaScript-thread settlement both run later,
  // potentially after `free()` or the destructor has already run. Only
  // `invoker_` and `state_` (both `shared_ptr`) and `&rt` (the runtime, whose
  // lifetime is independent of this object) cross that boundary; nothing here
  // reaches back into `this`.
  auto invoker = invoker_;
  auto state = state_;
  jsi::Runtime* runtime = &rt;

  auto executor = jsi::Function::createFromHostFunction(
      rt, jsi::PropNameID::forAscii(rt, "derecProtocolExecutor"), 2,
      [&worker = worker_, invoker, state, runtime, body = std::move(body),
       convert = std::move(convert)](jsi::Runtime& execRt, const jsi::Value&,
                                     const jsi::Value* args,
                                     size_t) mutable -> jsi::Value {
        // Copy the executor's resolve/reject into handles that survive past
        // this call: `Value`'s copy-with-runtime constructor bumps the
        // underlying reference count, unlike a bare reference to `args`,
        // which is only valid for this call. `RetainedJsValue` additionally
        // makes dropping that reference safe on a torn-down runtime, whichever
        // thread ends up dropping it.
        auto resolve = std::make_shared<RetainedJsValue>(execRt, args[0], state);
        auto reject = std::make_shared<RetainedJsValue>(execRt, args[1], state);

        bool accepted =
            worker.post([invoker, state, runtime, resolve, reject, body,
                         convert]() mutable {
              std::vector<uint8_t> bytes;
              bool failed = false;
              bool unknownFailure = false;
              DeRecError capturedError{};
              try {
                bytes = body();
              } catch (const FfiFailure& failure) {
                capturedError = failure.error;
                failed = true;
              } catch (...) {
                // Anything other than `FfiFailure` — `std::bad_alloc` from
                // `takeBuffer`, or any other exception a body's bookkeeping
                // might throw — must still settle the Promise. Left
                // uncaught here, it would propagate into
                // `WorkerThread::loop`'s own catch-all (there specifically
                // to stop `std::terminate`), which discards it silently:
                // the Promise would then never settle and the caller would
                // hang forever instead of seeing a failure.
                unknownFailure = true;
              }

              if (state->runtimeInvalidated.load()) {
                // The runtime is gone: there is nothing to settle into, and
                // scheduling onto its invoker would only queue a lambda whose
                // captures must never be released against it either. Returning
                // here drops `resolve`/`reject` on this thread, which
                // `RetainedJsValue` handles without touching the runtime.
                return;
              }

              invoker->invokeAsync([state, runtime, resolve, reject, convert,
                                    bytes = std::move(bytes), failed,
                                    unknownFailure, capturedError]() mutable {
                if (state->runtimeInvalidated.load()) {
                  // Queued before the runtime was torn down, reached only
                  // afterwards. Every JSI call below — including the ones the
                  // settlement itself makes — would run against a dead
                  // runtime.
                  return;
                }
                jsi::Runtime& jsRt = *runtime;
                try {
                  if (failed) {
                    // Reuses the exact error shape every synchronous FFI
                    // wrapper throws, rather than inventing a second one for
                    // the asynchronous path.
                    throwDeRecError(jsRt, capturedError);
                  }
                  if (unknownFailure) {
                    throw jsi::JSError(jsRt, "DeRec: an unexpected native error occurred");
                  }
                  jsi::Value result = convert(jsRt, bytes);
                  resolve->get().asObject(jsRt).asFunction(jsRt).call(jsRt, result);
                } catch (jsi::JSError& error) {
                  reject->get().asObject(jsRt).asFunction(jsRt).call(
                      jsRt, jsi::Value(jsRt, error.value()));
                }
              });
            });

        if (!accepted) {
          // The worker has already been drained (teardown ran, concurrently
          // with this call, on whatever thread finalized the previous
          // `ProtocolHost`). Nothing will ever run the posted task, so
          // settle the Promise immediately instead of leaving it pending
          // forever. Rejects with a real `Error` (not a bare string) so
          // `.catch(e => e.message)` behaves the same here as for every
          // other rejection in this file.
          jsi::JSError releasedError(execRt, "DeRec: protocol instance has been released");
          reject->get()
              .asObject(execRt)
              .asFunction(execRt)
              .call(execRt, jsi::Value(execRt, releasedError.value()));
        }

        return jsi::Value::undefined();
      });

  auto promiseCtor = rt.global().getPropertyAsFunction(rt, "Promise");
  return promiseCtor.callAsConstructor(rt, executor);
}

namespace {

/// `secretId(): bigint` — no FFI call. The protocol handle carries no
/// accessor for it, so the value supplied at construction is the only
/// source of truth.
jsi::Value hostSecretId(jsi::Runtime& rt, uint64_t secretId) {
  return jsi::Value(rt, jsi::BigInt::fromUint64(rt, secretId));
}

}  // namespace

jsi::Value ProtocolHost::get(jsi::Runtime& rt, const jsi::PropNameID& name) {
  std::string prop = name.utf8(rt);

  if (prop == "secretId") {
    return jsi::Function::createFromHostFunction(
        rt, name, 0,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value*,
               size_t) -> jsi::Value { return hostSecretId(rt2, secretId_); });
  }

  // `setCommunicationInfo` and `setOwnTransport` return a Promise, unlike
  // `@derec-alliance/nodejs` where both are synchronous. They must not run on
  // the JavaScript thread: `derec_protocol_set_*` takes the same handle mutex
  // that `derec_protocol_process`/`start`/`restore` hold for the whole
  // duration of a flow, including across store callbacks that park the worker
  // waiting on the JavaScript thread. Calling the setter synchronously would
  // block the JavaScript thread on that mutex, so the callback's continuation
  // could never run, so the worker could never resume and release it — broken
  // only by the store timeout, which additionally corrupts the in-flight
  // callback into a backend failure. The nodejs SDK is WASM and
  // single-threaded, so the hazard cannot arise there. Queuing onto the
  // serial worker instead orders the setter behind any in-flight flow, and
  // returning a Promise keeps a caller that ignores the result — which is how
  // nodejs code calls these — source-compatible, while letting a failure
  // surface as a rejection rather than being swallowed.
  if (prop == "setCommunicationInfo") {
    return jsi::Function::createFromHostFunction(
        rt, name, 1,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "setCommunicationInfo", count, 1);
          ByteView view = asBytes(rt2, args[0]);
          std::vector<uint8_t> info(view.ptr, view.ptr + view.len);
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle, info = std::move(info)]() -> std::vector<uint8_t> {
            DeRecError error = derec_protocol_set_communication_info(
                handle, info.data(), info.size());
            if (error.code != DEREC_CODE_OK) {
              throw FfiFailure(error);
            }
            return {};
          };
          auto convert = [](jsi::Runtime&, std::vector<uint8_t>&) {
            return jsi::Value::undefined();
          };
          return runAsync(rt2, std::move(body), std::move(convert));
        });
  }

  if (prop == "setOwnTransport") {
    return jsi::Function::createFromHostFunction(
        rt, name, 2,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "setOwnTransport", count, 2);
          std::string uri = args[0].asString(rt2).utf8(rt2);
          auto protocol = static_cast<int32_t>(args[1].asNumber());
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle, uri, protocol]() -> std::vector<uint8_t> {
            DeRecError error = derec_protocol_set_own_transport(
                handle, reinterpret_cast<const uint8_t*>(uri.data()), uri.size(),
                protocol);
            if (error.code != DEREC_CODE_OK) {
              throw FfiFailure(error);
            }
            return {};
          };
          auto convert = [](jsi::Runtime&, std::vector<uint8_t>&) {
            return jsi::Value::undefined();
          };
          return runAsync(rt2, std::move(body), std::move(convert));
        });
  }

  if (prop == "createContact") {
    return jsi::Function::createFromHostFunction(
        rt, name, 5,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "createContact", count, 5);
          auto hasChannelId = static_cast<uint32_t>(args[0].asNumber());
          uint64_t channelId = asU64(rt2, args[1]);
          auto contactMode = static_cast<int32_t>(args[2].asNumber());
          auto hasNonce = static_cast<uint32_t>(args[3].asNumber());
          uint64_t nonce = asU64(rt2, args[4]);
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle, hasChannelId, channelId, contactMode, hasNonce,
                      nonce]() -> std::vector<uint8_t> {
            DeRecProtocolCreateContactResult result = derec_protocol_create_contact(
                handle, hasChannelId, channelId, contactMode, hasNonce, nonce);
            if (result.error.code != DEREC_CODE_OK) {
              throw FfiFailure(result.error);
            }
            return takeBuffer(result.contact_wire_bytes);
          };
          return runAsync(rt2, std::move(body), bytesToArrayBuffer);
        });
  }

  if (prop == "start") {
    return jsi::Function::createFromHostFunction(
        rt, name, 2,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "start", count, 2);
          auto flowKind = static_cast<uint32_t>(args[0].asNumber());
          ByteView view = asBytes(rt2, args[1]);
          std::vector<uint8_t> params(view.ptr, view.ptr + view.len);
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle, flowKind,
                      params = std::move(params)]() -> std::vector<uint8_t> {
            DeRecProtocolEventsResult result =
                derec_protocol_start(handle, flowKind, params.data(), params.size());
            if (result.error.code != DEREC_CODE_OK) {
              throw FfiFailure(result.error);
            }
            return takeBuffer(result.events_json);
          };
          return runAsync(rt2, std::move(body), bytesToArrayBuffer);
        });
  }

  if (prop == "process") {
    return jsi::Function::createFromHostFunction(
        rt, name, 1,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "process", count, 1);
          ByteView view = asBytes(rt2, args[0]);
          std::vector<uint8_t> message(view.ptr, view.ptr + view.len);
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle,
                      message = std::move(message)]() -> std::vector<uint8_t> {
            DeRecProtocolEventsResult result =
                derec_protocol_process(handle, message.data(), message.size());
            if (result.error.code != DEREC_CODE_OK) {
              throw FfiFailure(result.error);
            }
            return takeBuffer(result.events_json);
          };
          return runAsync(rt2, std::move(body), bytesToArrayBuffer);
        });
  }

  if (prop == "tick") {
    return jsi::Function::createFromHostFunction(
        rt, name, 0,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value*,
               size_t) -> jsi::Value {
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle]() -> std::vector<uint8_t> {
            DeRecProtocolEventsResult result = derec_protocol_tick(handle);
            if (result.error.code != DEREC_CODE_OK) {
              throw FfiFailure(result.error);
            }
            return takeBuffer(result.events_json);
          };
          return runAsync(rt2, std::move(body), bytesToArrayBuffer);
        });
  }

  if (prop == "accept") {
    return jsi::Function::createFromHostFunction(
        rt, name, 1,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "accept", count, 1);
          ByteView view = asBytes(rt2, args[0]);
          std::vector<uint8_t> action(view.ptr, view.ptr + view.len);
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle,
                      action = std::move(action)]() -> std::vector<uint8_t> {
            DeRecProtocolEventsResult result =
                derec_protocol_accept(handle, action.data(), action.size());
            if (result.error.code != DEREC_CODE_OK) {
              throw FfiFailure(result.error);
            }
            return takeBuffer(result.events_json);
          };
          return runAsync(rt2, std::move(body), bytesToArrayBuffer);
        });
  }

  if (prop == "reject") {
    return jsi::Function::createFromHostFunction(
        rt, name, 3,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "reject", count, 3);
          ByteView view = asBytes(rt2, args[0]);
          std::vector<uint8_t> action(view.ptr, view.ptr + view.len);
          auto status = static_cast<int32_t>(args[1].asNumber());
          std::string memo = args[2].asString(rt2).utf8(rt2);
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle, action = std::move(action), status,
                      memo]() -> std::vector<uint8_t> {
            DeRecError error = derec_protocol_reject(
                handle, action.data(), action.size(), status,
                reinterpret_cast<const uint8_t*>(memo.data()), memo.size());
            if (error.code != DEREC_CODE_OK) {
              throw FfiFailure(error);
            }
            return {};
          };
          auto convert = [](jsi::Runtime&, std::vector<uint8_t>&) {
            return jsi::Value::undefined();
          };
          return runAsync(rt2, std::move(body), std::move(convert));
        });
  }

  if (prop == "getFingerprint") {
    return jsi::Function::createFromHostFunction(
        rt, name, 1,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "getFingerprint", count, 1);
          uint64_t channelId = asU64(rt2, args[0]);
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle, channelId]() -> std::vector<uint8_t> {
            DeRecProtocolFingerprintResult result =
                derec_protocol_get_fingerprint(handle, channelId);
            if (result.error.code != DEREC_CODE_OK) {
              throw FfiFailure(result.error);
            }
            std::string fingerprint = takeString(result.fingerprint);
            return std::vector<uint8_t>(fingerprint.begin(), fingerprint.end());
          };
          auto convert = [](jsi::Runtime& rt3, std::vector<uint8_t>& bytes) {
            return jsi::Value(
                jsi::String::createFromUtf8(rt3, bytes.data(), bytes.size()));
          };
          return runAsync(rt2, std::move(body), std::move(convert));
        });
  }

  if (prop == "verifyFingerprint") {
    return jsi::Function::createFromHostFunction(
        rt, name, 2,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "verifyFingerprint", count, 2);
          uint64_t channelId = asU64(rt2, args[0]);
          std::string fingerprint = args[1].asString(rt2).utf8(rt2);
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle, channelId, fingerprint]() -> std::vector<uint8_t> {
            uint32_t matched = 0;
            DeRecError error = derec_protocol_verify_fingerprint(
                handle, channelId, fingerprint.c_str(), &matched);
            if (error.code != DEREC_CODE_OK) {
              throw FfiFailure(error);
            }
            return std::vector<uint8_t>{static_cast<uint8_t>(matched != 0 ? 1 : 0)};
          };
          auto convert = [](jsi::Runtime&, std::vector<uint8_t>& bytes) {
            return jsi::Value(!bytes.empty() && bytes[0] != 0);
          };
          return runAsync(rt2, std::move(body), std::move(convert));
        });
  }

  if (prop == "removeExpiredChannels") {
    return jsi::Function::createFromHostFunction(
        rt, name, 1,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "removeExpiredChannels", count, 1);
          uint64_t olderThanSecs = asU64(rt2, args[0]);
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle, olderThanSecs]() -> std::vector<uint8_t> {
            DeRecRemovedChannelsResult result =
                derec_protocol_remove_expired_channels(handle, olderThanSecs);
            if (result.error.code != DEREC_CODE_OK) {
              throw FfiFailure(result.error);
            }
            return takeBuffer(result.channels);
          };
          return runAsync(rt2, std::move(body), bytesToArrayBuffer);
        });
  }

  if (prop == "restore") {
    return jsi::Function::createFromHostFunction(
        rt, name, 1,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value* args,
               size_t count) -> jsi::Value {
          requireArgs(rt2, "restore", count, 1);
          ByteView view = asBytes(rt2, args[0]);
          std::vector<uint8_t> params(view.ptr, view.ptr + view.len);
          DeRecProtocolHandle* handle = handle_;

          auto body = [handle,
                      params = std::move(params)]() -> std::vector<uint8_t> {
            DeRecProtocolEventsResult result =
                derec_protocol_restore(handle, params.data(), params.size());
            if (result.error.code != DEREC_CODE_OK) {
              throw FfiFailure(result.error);
            }
            return takeBuffer(result.events_json);
          };
          return runAsync(rt2, std::move(body), bytesToArrayBuffer);
        });
  }

  if (prop == "free") {
    return jsi::Function::createFromHostFunction(
        rt, name, 0,
        [this](jsi::Runtime& rt2, const jsi::Value&, const jsi::Value*,
               size_t) -> jsi::Value {
          // `teardown` drains the worker, which would deadlock if called
          // from inside a store callback body that same worker is blocked
          // waiting on — the same hazard `runAsync` guards against, with the
          // same narrow scope.
          if (isInsideStoreCallback()) {
            throw jsi::JSError(rt2, kReentrancyMessage);
          }
          teardown();
          return jsi::Value::undefined();
        });
  }

  return jsi::Value::undefined();
}

std::vector<jsi::PropNameID> ProtocolHost::getPropertyNames(jsi::Runtime& rt) {
  const char* names[] = {
      "secretId",       "setCommunicationInfo",  "setOwnTransport",
      "createContact",  "start",                 "process",
      "tick",           "accept",                "reject",
      "getFingerprint", "verifyFingerprint",     "removeExpiredChannels",
      "restore",        "free",
  };
  std::vector<jsi::PropNameID> result;
  result.reserve(sizeof(names) / sizeof(names[0]));
  for (const char* name : names) {
    result.push_back(jsi::PropNameID::forAscii(rt, name));
  }
  return result;
}

}  // namespace derec
