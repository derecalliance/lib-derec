/**
 * Accessor for the JSI host object installed by the native module.
 *
 * The host object is installed directly into the runtime's global scope
 * rather than exposed through React Native's codegen, because the data
 * surface passes `ArrayBuffer`s that TurboModule specs cannot express.
 */
export interface DeRecNative {
  version(): string;
}

/**
 * Asks the native module to install the host object.
 *
 * iOS needs this only as a fallback: the module implements
 * `RCTTurboModuleWithJSIBindings`, so the platform installs the host object
 * before any JavaScript runs. Android has no equivalent hook for a module that
 * is not code-generated, so the install has to be triggered from here — a
 * blocking synchronous `@ReactMethod`, which is why the host object is present
 * by the time this returns.
 *
 * Everything is behind a lazy `require` and a `try`: this module is imported by
 * unit tests running under plain Node, where `react-native` cannot resolve, and
 * a missing native module must still surface as the explanatory error below
 * rather than a resolution failure from a dependency the caller never named.
 */
function requestInstall(): void {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { NativeModules } = require('react-native') as {
      NativeModules: Record<string, { install?: () => boolean } | undefined>;
    };
    NativeModules.DeRec?.install?.();
  } catch {
    // Left to the caller: the check below reports the actionable message.
  }
}

export function getNative(): DeRecNative {
  let installed = (globalThis as Record<string, unknown>).__DeRec;
  if (installed === undefined || installed === null) {
    requestInstall();
    installed = (globalThis as Record<string, unknown>).__DeRec;
  }
  if (installed === undefined || installed === null) {
    throw new Error(
      'DeRec native module is not installed. Rebuild the app after adding ' +
        '@derec-alliance/react-native (pod install on iOS, Gradle sync on Android).',
    );
  }
  return installed as DeRecNative;
}
