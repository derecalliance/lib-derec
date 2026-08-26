package org.derec

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.common.annotations.FrameworkAPI
import com.facebook.react.turbomodule.core.CallInvokerHolderImpl

/**
 * Minimal module whose only job is to install the `__DeRec` JSI host object.
 *
 * iOS reaches the runtime through `RCTTurboModuleWithJSIBindings`, which the
 * platform calls on its own. Android has no equivalent hook for a module that
 * is not code-generated, so JavaScript calls [install] once, synchronously,
 * before the first use of the SDK — see `src/native.ts`.
 */
class DeRecModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName() = NAME

  // `jsCallInvokerHolder` is annotated `@FrameworkAPI`: React Native reserves
  // it for framework authors and may change it in a minor release. There is no
  // stable alternative for reaching the CallInvoker from a module that is not
  // code-generated, so the opt-in is deliberate and the risk is a compile
  // failure on upgrade — not a silent behaviour change.
  @OptIn(FrameworkAPI::class)
  @ReactMethod(isBlockingSynchronousMethod = true)
  fun install(): Boolean {
    val context = reactApplicationContext
    val runtimePtr = context.javaScriptContextHolder?.get() ?: return false
    // `jsCallInvokerHolder` on the context, not `catalystInstance` — there is
    // no catalyst instance in a bridgeless app, which is the default from
    // React Native 0.76 onward, and touching it throws there.
    val holder = context.jsCallInvokerHolder as? CallInvokerHolderImpl ?: return false
    nativeInstall(runtimePtr, holder)
    return true
  }

  override fun invalidate() {
    nativeInvalidate()
    super.invalidate()
  }

  private external fun nativeInstall(runtimePtr: Long, callInvokerHolder: Any)

  private external fun nativeInvalidate()

  companion object {
    const val NAME = "DeRec"

    init {
      System.loadLibrary("derec_jsi")
    }
  }
}
