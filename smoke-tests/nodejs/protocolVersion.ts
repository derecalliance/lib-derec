// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
// `protocol_version()` must report exactly the version the core writes into
// envelopes, so it is checked against the core's own constant rather than a
// value copied here.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { protocol_version } from "@derec-alliance/nodejs";

function coreVersion(): { major: number; minor: number } {
  const source = readFileSync(
    join(import.meta.dirname, "..", "..", "library", "src", "protocol_version.rs"),
    "utf8",
  );
  const m = /pub const CURRENT: ProtocolVersion = ProtocolVersion \{ major: (\d+), minor: (\d+) \}/.exec(
    source,
  );
  if (!m) {
    throw new Error("protocol_version.rs: could not find the CURRENT constant");
  }
  return { major: Number(m[1]), minor: Number(m[2]) };
}

export function runProtocolVersionSmoke(): void {
  console.log("=== Protocol version ===");
  const actual = protocol_version();
  const expected = coreVersion();
  if (!Number.isInteger(actual.major) || !Number.isInteger(actual.minor)) {
    throw new Error(`protocol_version() must return integers, got ${JSON.stringify(actual)}`);
  }
  if (actual.major !== expected.major || actual.minor !== expected.minor) {
    throw new Error(
      `protocol_version() = ${actual.major}.${actual.minor}, core CURRENT = ${expected.major}.${expected.minor}`,
    );
  }
  console.log(`  protocol_version() = ${actual.major}.${actual.minor} matches the core  ✓\n`);
}
