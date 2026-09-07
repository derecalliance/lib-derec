import { readFile, writeFile, copyFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

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
function buildWasm(target, outDir) {
  console.log(`Building wasm with wasm-pack --target ${target}`);
  execFileSync(
    "wasm-pack",
    ["build", "--release", "--out-dir", path.join("target", outDir), "--target", target],
    { cwd: libraryRoot, stdio: "inherit" }
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

  console.log(`Prepared Web package at ${pkgDir}`);
}

main().catch((error) => {
  console.error("Failed to prepare Web package:", error);
  process.exit(1);
});
