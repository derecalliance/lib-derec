package org.derec

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

/**
 * Registers [DeRecModule] with the host app.
 *
 * React Native's Android autolinking discovers a library by finding a
 * `ReactPackage` implementation in its sources; without one the module is
 * never instantiated and `install()` is unreachable from JavaScript, so the
 * `__DeRec` host object never appears. iOS needs no equivalent — there,
 * `RCT_EXPORT_MODULE()` registers the module at load time.
 */
class DeRecPackage : ReactPackage {
  override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> =
    listOf(DeRecModule(reactContext))

  override fun createViewManagers(
    reactContext: ReactApplicationContext,
  ): List<ViewManager<*, *>> = emptyList()
}
