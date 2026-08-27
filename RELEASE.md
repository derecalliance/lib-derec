# Release Process

This repository contains multiple crates. The publish order must respect
crate dependencies.

## Dependency Structure

The dependency structure is:
This order reflects the dependency hierarchy:

```text
derec-proto   derec-cryptography
      \             /
       \           /
        \         /
       derec-library
```

`derec-proto` and `derec-cryptography` can be published independently.

`derec-library` depends on both and must be published only after the
required versions of those crates are available on crates.io.

## Recommended Publish Sequence

A typical release sequence is:
1. derec-proto
2. derec-cryptography
3. derec-library

> [!INFO]
> Steps 1 and 2 may be performed in either order.

## Release checklist

Before publishing:

1. Update crate versions in the corresponding `Cargo.toml` files.
2. Update internal dependency versions between crates.
3. Ensure the workspace builds successfully:

```bash
cargo build --workspace
cargo test --workspace
```

4. Verify the packages to be uploaded:

```bash
cargo publish --workspace --dry-run
```

This step ensures the packages compile correctly once packaged. Because the
crates depend on each other by `version` + `path`, a whole-workspace dry run
resolves the not-yet-published versions against a temporary local registry;
dry-running `derec-library` on its own fails until its dependencies are on
crates.io.

---

## Publishing Rust SDK

Publish all three crates in dependency order:

```bash
cargo publish --workspace
```

`derec-rust-binding-smoke-test` is marked `publish = false` and is skipped.

> [!INFO]
> Each publish may take a few seconds before the crate becomes available for dependency resolution.

### Verify release

After publishing, confirm the new versions are available:

* https://crates.io/crates/derec-proto
* https://crates.io/crates/derec-cryptography
* https://crates.io/crates/derec-library

You can also verify using:

```bash
cargo search derec
```

---

## Publishing Node.js SDK

Build the Node.js WebAssembly package:

```bash
cd library
make nodejs
```

This generates the npm package in:

```
library/target/pkg-nodejs
```

Review the package contents before publishing:

```
cd library/target/pkg-nodejs
npm pack
```

This creates a `.tgz` archive showing exactly what will be published.

Publish the package to npm:

```
npm publish --access public
```

> [!INFO]
> The --access public flag is required for scoped packages such as
> @derec-alliance/nodejs.

### Verify Node.js release

After publishing, confirm the new version is available:
* https://www.npmjs.com/package/@derec-alliance/nodejs

You can also verify using:

```bash
npm view @derec-alliance/nodejs
```

Or install it in a test project:

```bash
npm install @derec-alliance/nodejs
```

---

## Publishing Web SDK

Build the Browser WebAssembly package:

```bash
cd library
make web
```

This generates the npm package in:

```
library/target/pkg-web
```

Review the package contents before publishing:

```
cd library/target/pkg-web
npm pack
```

This creates a `.tgz` archive showing exactly what will be published.

Publish the package to npm:

```
npm publish --access public
```

> [!INFO]
> The --access public flag is required for scoped packages such as
> @derec-alliance/web.

### Verify Node.js release

After publishing, confirm the new version is available:
* https://www.npmjs.com/package/@derec-alliance/web

You can also verify using:

```bash
npm view @derec-alliance/web
```

Or install it in a test project:

```bash
npm install @derec-alliance/web
```

---

## Publishing .NET SDK

### Prerequisites

Before building the .NET package, ensure the following tools are installed:

| Tool | Purpose |
|-----|-----|
| Rust | Build the native library |
| rustup | Manage Rust targets |
| cargo-zigbuild | Cross-compile native targets |
| zig | Cross-linker used by cargo-zigbuild |
| .NET SDK (10+) | Build and publish the NuGet package |

Install required tools:

```bash
# Rust toolchain
curl https://sh.rustup.rs -sSf | sh

# Rust targets for cross compilation
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu

# Zig compiler (required by cargo-zigbuild)
brew install zig

# cargo-zigbuild
cargo install cargo-zigbuild
```

Verify installation:

```bash
rustc --version
cargo --version
zig version
cargo zigbuild --version
dotnet --version
```

### Build the .NET package

Build the multi-runtime NuGet package:

```bash
cd library
make dotnet
```

The build process performs the following steps automatically:

1. Builds the native Rust library.
2. Cross-compiles the library for multiple targets:
  * osx-arm64
  * osx-x64
  * linux-x64
  * linux-arm64
3. Stages the compiled artifacts into the NuGet runtime layout:
```
packages/dotnet/DeRec.Library/runtimes/
  osx-arm64/native/libderec_library.dylib
  osx-x64/native/libderec_library.dylib
  linux-x64/native/libderec_library.so
  linux-arm64/native/libderec_library.so
```

4. Packs the NuGet package.

The resulting package is generated at:

```bash
packages/dotnet/DeRec.Library/bin/Release/
```

### Review the package before publishing

Inspect the package contents:

```bash
cd packages/dotnet/DeRec.Library/bin/Release
unzip -l DeRec.Library.*.nupkg
```

Verify that the package contains:

```bash
runtimes/osx-arm64/native/libderec_library.dylib
runtimes/osx-x64/native/libderec_library.dylib
runtimes/linux-x64/native/libderec_library.so
runtimes/linux-arm64/native/libderec_library.so
```

### Publish the package to NuGet

Authenticate with NuGet:

```bash
dotnet nuget add \
  source https://api.nuget.org/v3/index.json \
  --name nuget
```

Publish the package:

```bash
dotnet nuget push DeRec.Library.<version>.nupkg \
  --api-key <YOUR_API_KEY> \
  --source https://api.nuget.org/v3/index.json
```

### Verify the release

After publishing, confirm the new version is available:
* https://www.nuget.org/packages/DeRec.Library

You can also verify using:

```bash
dotnet nuget search DeRec.Library
```

Or install it in a test project:

```bash
dotnet add package DeRec.Library
```

### Validate runtime loading

Create a minimal test project:

```bash
dotnet new console -n derec-test
cd derec-test
dotnet add package DeRec.Library
```

Then run a simple pairing test to ensure the native runtime loads correctly.

This confirms that the correct native library is resolved for the host platform.

---

## Publishing Go SDK

The Go SDK lives at `packages/go` (module
`github.com/derecalliance/lib-derec/packages/go`). It is a `purego`-based,
no-cgo binding over the C ABI. **Go has no binary package registry** — the
module is published by pushing a git tag, and consumers fetch the source via
`go get`. Because of that, the per-platform native libraries are **embedded
in the module and committed to the repository** (unlike the .NET/npm packages,
whose native artifacts are built at pack time).

### Build and stage the native libraries

```bash
cd library
make go
```

`make go` runs `scripts/prepare-go-package.sh`, which cross-compiles the native
library (with `--features ffi`) for all four supported platforms and stages
each into the Go embed tree:

```
packages/go/internal/native/lib/darwin_arm64/libderec_library.dylib
packages/go/internal/native/lib/darwin_amd64/libderec_library.dylib
packages/go/internal/native/lib/linux_amd64/libderec_library.so
packages/go/internal/native/lib/linux_arm64/libderec_library.so
```

The same cross-compilation prerequisites as the .NET build apply
(`cargo-zigbuild`, `zig`, the four rustup targets).

### Verify before tagging

```bash
cd packages/go && CGO_ENABLED=0 go test ./...
cd ../smoke-tests/go && CGO_ENABLED=0 go run .
```

Both must pass. Confirm each staged lib exports the FFI surface, e.g.
`nm -gU packages/go/internal/native/lib/darwin_arm64/libderec_library.dylib | grep derec_protocol_new`.

### Commit and tag

Commit the SDK **including the regenerated native libs**, then push a
module-scoped tag. Go modules in a subdirectory use the
`<subdir>/vX.Y.Z` tag format (semver, prerelease suffixes allowed):

```bash
git tag packages/go/vX.Y.Z
git push origin packages/go/vX.Y.Z
```

Replace `X.Y.Z` with the released version (e.g. `packages/go/v0.0.1-alpha.9`).
This is distinct from the repository-wide `vX.Y.Z` tag in the Git Tagging
section below.

### Verify the release

```bash
go install github.com/derecalliance/lib-derec/packages/go/...@vX.Y.Z
```

Or in a test project:

```bash
go get github.com/derecalliance/lib-derec/packages/go@vX.Y.Z
```

`pkg.go.dev` indexes the module on its first fetch; the README renders there.

---

## Publishing React Native SDK

### Prerequisites

Building the React Native package requires macOS, since the iOS
`XCFramework` cannot be cross-built from Linux:

| Tool | Purpose |
|-----|-----|
| Rust | Build the native library |
| rustup | Manage Rust targets |
| Xcode | Build the iOS static libraries and assemble the XCFramework |
| Android NDK | Cross-compile the Android static libraries |
| cbindgen | Regenerate the C header consumed by the JSI native module |
| Node.js | Compile the TypeScript sources and stage `package.json` |

Install the Rust targets used by the build:

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
```

Set `ANDROID_NDK_HOME` to an installed NDK before building:

```bash
export ANDROID_NDK_HOME=/path/to/Android/sdk/ndk/<version>
```

### Build the React Native package

```bash
cd library
make react-native
```

`make react-native` runs `scripts/prepare-react-native-package.sh`, which:

1. Regenerates `packages/react-native/cpp/derec_ffi.h` with cbindgen.
2. Builds the Rust static library for the iOS device and simulator targets,
   combines the simulator slices with `lipo`, and assembles
   `packages/react-native/ios/DeRecFFI.xcframework` with `xcodebuild`.
3. Builds the Rust static library for each Android ABI and stages it into
   `packages/react-native/android/src/main/jniLibs/<abi>/`.
4. Compiles the package's TypeScript sources into `lib/`.
5. Writes `package.json` from `package.override.json` plus the resolved
   version, and copies in `LICENSE`.

This must run on macOS with Xcode installed and `ANDROID_NDK_HOME` set — the
XCFramework step has no Linux or cross-compilation equivalent.

> [!IMPORTANT]
> Step 5 overwrites the tracked `packages/react-native/package.json`. Unlike
> the other packages, this one keeps a development manifest in git, because
> its in-tree Jest suite needs `devDependencies` and `scripts` and the
> lockfile is resolved against them — neither of which belongs in a published
> tarball. Restore it once publishing is done:
>
> ```bash
> git checkout packages/react-native/package.json
> ```

### Review the package before publishing

```bash
cd packages/react-native
npm pack --dry-run
```

Verify the file list matches `package.override.json`'s `files` array and
that the `ios/DeRecFFI.xcframework` and `android/src/main/jniLibs/*` native
artifacts staged by the build are present.

### Publish the package to npm

```bash
npm publish --access public
```

> [!INFO]
> The --access public flag is required for scoped packages such as
> @derec-alliance/react-native.

### Verify the release

After publishing, confirm the new version is available:
* https://www.npmjs.com/package/@derec-alliance/react-native

You can also verify using:

```bash
npm view @derec-alliance/react-native
```

Or install it in a test Expo dev-build project:

```bash
npx expo install @derec-alliance/react-native
npx expo run:ios   # or: npx expo run:android
```

`@derec-alliance/react-native` ships custom native code and cannot run in
Expo Go — a dev build (or a plain React Native build) is required.

---

## Release Checklist

Before publishing a release:

- [ ] Version updated in `library/Cargo.toml` (everything else derives from it
      via `scripts/get-version.sh` — do not edit package manifests individually)
- [ ] Release notes written, including any **breaking** changes
- [ ] `make all` succeeds — run it **last**, immediately before publishing
- [ ] Test installation of all SDKs

---

## Git Tagging

After publishing, tag the release in git:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

Replace X.Y.Z with the released version.
