import { readFile, writeFile, copyFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

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

async function main() {
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

  console.log(`Prepared Web package at ${pkgDir}`);
}

main().catch((error) => {
  console.error("Failed to prepare Web package:", error);
  process.exit(1);
});
