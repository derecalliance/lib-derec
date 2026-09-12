// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.
//
// Drives library/tests/fixtures/channel_filter.json against
// `channelFilterMatches`.
//
// A channel store may push the filter into its query rather than returning
// every row. That is an optimization and it is the store's to verify: the core
// re-applies the filter to whatever a listing returns, which drops rows the
// filter excludes but cannot recover a row that was never returned. An
// over-selecting pushdown costs bandwidth; an under-selecting one is
// undetectable at runtime.
//
// TypeScript is where this matters most. A function of fewer parameters
// satisfies a signature declaring more, so a store written before the filter
// parameter existed still compiles clean under `--strict` — the type system
// cannot see the gap, and this table is the check that can.
//
// The same table drives the Rust, Go, .NET and React Native suites. When two
// bindings disagree, the fixture says which is wrong.

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { channelFilterMatches } from "@derec-alliance/nodejs";
import type {
  ChannelStatusName,
  HelperFilter,
  ReplicaFilter,
  ReplicaRoleName,
  SenderKindName,
} from "@derec-alliance/nodejs";

interface FilterCase {
  name: string;
  why?: string;
  filter: {
    ids: string[];
    status: ChannelStatusName[];
    role: string | null;
    exclude: string[];
  };
  expected: string[];
}

interface Section {
  records: Array<{ id: string; status: ChannelStatusName; role: string }>;
  cases: FilterCase[];
}

function survivors(section: Section, c: FilterCase): string[] {
  const filter = {
    ids: c.filter.ids,
    status: c.filter.status,
    role: c.filter.role,
    exclude: c.filter.exclude,
  } as HelperFilter | ReplicaFilter;

  return section.records
    .filter((r) =>
      channelFilterMatches(
        filter,
        r.id,
        r.status,
        r.role as SenderKindName | ReplicaRoleName,
      ),
    )
    .map((r) => r.id);
}

function runSection(label: string, section: Section): void {
  for (const c of section.cases) {
    const got = survivors(section, c);
    const want = c.expected;

    if (got.length !== want.length || got.some((id, i) => id !== want[i])) {
      throw new Error(
        `${label} case \`${c.name}\` disagrees with channelFilterMatches:\n` +
          `  got:  [${got.join(", ")}]\n` +
          `  want: [${want.join(", ")}]\n` +
          `  why this case exists: ${c.why ?? "(not stated)"}`,
      );
    }
  }
}

// Read at run time rather than imported: a JSON import is a compile input, and
// one living outside this directory widens tsc's inferred `rootDir` to the
// repository root, which relocates every emitted file.
function loadFixture(): { helpers: Section; replicas: Section } {
  const path = join(
    import.meta.dirname,
    "..",
    "..",
    "library",
    "tests",
    "fixtures",
    "channel_filter.json",
  );
  return JSON.parse(readFileSync(path, "utf8")) as {
    helpers: Section;
    replicas: Section;
  };
}

export function runChannelFilterConformance(): void {
  console.log("=== Channel filter conformance ===");

  const vectors = loadFixture();

  runSection("helpers", vectors.helpers);
  runSection("replicas", vectors.replicas);

  console.log("Channel filter conformance passed.\n");
}
