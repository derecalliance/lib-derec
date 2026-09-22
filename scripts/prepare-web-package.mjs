import { readFile, writeFile, copyFile, cp, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import os from "node:os";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// repo-root/scripts -> repo-root
const repoRoot = path.resolve(__dirname, "..");
const libraryRoot = path.join(repoRoot, "library");

const pkgDir = path.join(libraryRoot, "target", "pkg-web");
const generatedPackageJsonPath = path.join(pkgDir, "package.json");
const overridePackageJsonPath = path.join(
  repoRoot,
  "packages",
  "web",
  "package.override.json",
);
const sourceReadmePath = path.join(
  repoRoot,
  "packages",
  "web",
  "README.md",
);
const targetReadmePath = path.join(pkgDir, "README.md");

const webDir = path.join(repoRoot, "packages", "web");
const indexFiles = ["index.js", "index.d.ts"];
const schemaBundleDir = path.join(pkgDir, "__schema");

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function mergeDeep(base, override) {
  const result = { ...base };

  for (const [key, overrideValue] of Object.entries(override)) {
    const baseValue = result[key];

    if (isPlainObject(baseValue) && isPlainObject(overrideValue)) {
      result[key] = mergeDeep(baseValue, overrideValue);
    } else {
      // Scalars and arrays fully replace the generated value.
      result[key] = overrideValue;
    }
  }

  return result;
}

// The wasm-pack output this script assembles is a build artifact under
// library/target/, so a stale or absent one would otherwise be packaged
// silently. Build it here, the way the Go and .NET packaging scripts build
// their native libraries, so `prepare` always reflects current source.
/// Path remapping for the shipped `.wasm`, matching what
/// `scripts/lib/build-env.sh` gives the native packaging scripts.
///
/// `panic!` and friends compile their source location into the binary as
/// read-only data, so without this every published bundle carries absolute
/// paths from the release machine's `~/.cargo` and `~/.rustup`. Stripping
/// cannot remove them — they are not debug info — so they have to be rewritten
/// at compile time.
function buildRustFlags() {
  const home = os.homedir();
  const parts = [`--remap-path-prefix=${home}=/derec-build`];
  // Listed last so it wins for a checkout that lives outside the home
  // directory: when several prefixes match, rustc applies the last one.
  parts.push(`--remap-path-prefix=${repoRoot}=/derec`);
  const existing = process.env.RUSTFLAGS;
  return existing ? `${existing} ${parts.join(" ")}` : parts.join(" ");
}

function buildWasm(target, outDir) {
  console.log(`Building wasm with wasm-pack --target ${target}`);
  execFileSync(
    "wasm-pack",
    ["build", "--release", "--out-dir", path.join("target", outDir), "--target", target],
    { cwd: libraryRoot, stdio: "inherit", env: { ...process.env, RUSTFLAGS: buildRustFlags() } }
  );
}

async function main() {
  buildWasm("web", "pkg-web");

  const [generatedPackageJsonRaw, overridePackageJsonRaw] = await Promise.all([
    readFile(generatedPackageJsonPath, "utf8"),
    readFile(overridePackageJsonPath, "utf8"),
  ]);

  const generatedPackageJson = JSON.parse(generatedPackageJsonRaw);
  const overridePackageJson = JSON.parse(overridePackageJsonRaw);

  const mergedPackageJson = mergeDeep(
    generatedPackageJson,
    overridePackageJson,
  );

  await writeFile(
    generatedPackageJsonPath,
    `${JSON.stringify(mergedPackageJson, null, 2)}\n`,
    "utf8",
  );

  await copyFile(sourceReadmePath, targetReadmePath);

  await Promise.all(
    indexFiles.map((f) =>
      copyFile(path.join(webDir, f), path.join(pkgDir, f)),
    ),
  );

  // The schema ships with the package so consumers can generate their own
  // code from it without a lib-derec checkout.
  execFileSync(
    "bash",
    [path.join(repoRoot, "scripts", "sync-schema.sh"), schemaBundleDir],
    { stdio: "inherit" }
  );
  // Replace rather than merge. `fs.cp` with `recursive` overwrites files that
  // exist in both trees but never removes destination files absent from the
  // source, and `pkgDir` survives between runs — so without this, a `.proto`
  // renamed or deleted upstream would keep shipping from a stale copy.
  await rm(path.join(pkgDir, "proto"), { recursive: true, force: true });
  await cp(path.join(schemaBundleDir, "proto"), path.join(pkgDir, "proto"), {
    recursive: true,
  });
  await copyFile(
    path.join(schemaBundleDir, "derec_descriptor.bin"),
    path.join(pkgDir, "derec_descriptor.bin"),
  );
  await rm(schemaBundleDir, { recursive: true, force: true });

  console.log(`Prepared Web package at ${pkgDir}`);
}

main().catch((error) => {
  console.error("Failed to prepare Web package:", error);
  process.exit(1);
});
