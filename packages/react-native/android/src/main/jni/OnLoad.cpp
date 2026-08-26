// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#include <fbjni/fbjni.h>
#include <jni.h>
#include <jsi/jsi.h>
#include <ReactCommon/CallInvokerHolder.h>

#include <memory>

#include "DeRecInstaller.h"
#include "RuntimeInvoker.h"

extern "C" JNIEXPORT void JNICALL
Java_org_derec_DeRecModule_nativeInstall(JNIEnv* env,
                                         jobject /*thiz*/,
                                         jlong runtimePtr,
                                         jobject callInvokerHolder) {
  auto* runtime = reinterpret_cast<facebook::jsi::Runtime*>(runtimePtr);
  if (runtime == nullptr) {
    return;
  }
  auto holder = facebook::jni::alias_ref<
      facebook::react::CallInvokerHolder::javaobject>{
      static_cast<facebook::react::CallInvokerHolder::javaobject>(
          callInvokerHolder)};
  auto invoker = std::make_shared<derec::RuntimeInvoker>(
      holder->cthis()->getCallInvoker());
  derec::install(*runtime, invoker);
}

extern "C" JNIEXPORT void JNICALL
Java_org_derec_DeRecModule_nativeInvalidate(JNIEnv*, jobject) {
  derec::invalidateAll();
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return facebook::jni::initialize(vm, [] {});
}
