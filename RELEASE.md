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

4. Verify each packages to be uploaded independently:

```bash
cargo publish --dry-run -p derec-proto
cargo publish --dry-run -p derec-cryptography
cargo publish --dry-run -p derec-library
```

This step ensures the packages compile correctly once packaged.

---

## Publishing Rust SDK

Publish the crates required by `derec-library` first:

```bash
cargo publish -p derec-proto
cargo publish -p derec-cryptography
```

Then publish the SDK crate:

```bash
cargo publish -p derec-library
```

If both dependency crates are being released together, they may be published
in either order.

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

## Release Checklist

Before publishing a release:

- [ ] Version updated in Cargo.toml
- [ ] Changelog updated
- [ ] `make all` succeeds
- [ ] Test installation of all SDKs

---

## Git Tagging

After publishing, tag the release in git:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

Replace X.Y.Z with the released version.
