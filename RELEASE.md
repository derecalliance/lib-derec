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

## Publish Crates

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

---

## Verify release

After publishing, confirm the new versions are available:

* https://crates.io/crates/derec-proto
* https://crates.io/crates/derec-cryptography
* https://crates.io/crates/derec-library

You can also verify using:

```bash
cargo search derec
```

---

## Git Tagging

After publishing, tag the release in git:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

Replace X.Y.Z with the released version.
