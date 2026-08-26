// Autolinking configuration.
//
// `sourceDir` must be RELATIVE to the package root: the CLI does
// `path.join(root, sourceDir)` (`cli-config-android/build/config/index.js`),
// so an absolute path is appended to the package root and resolves to a
// directory that does not exist. The Android config then returns null and the
// module is dropped from the generated `PackageList` — silently, with no build
// error and no autolinking warning.
//
// iOS needs no entry at all: CocoaPods discovers `DeRec.podspec` at the package
// root by convention, and naming it explicitly under `dependency.platforms.ios`
// fails the CLI's config schema ("podspecPath is not allowed").
module.exports = {
  dependency: {
    platforms: {
      android: { sourceDir: 'android' },
    },
  },
};
