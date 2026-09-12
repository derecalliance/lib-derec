import { readFileSync } from 'fs';
import { join } from 'path';

import { channelFilterMatches } from '../src/types';
import type {
  ChannelStatusName,
  HelperFilter,
  ReplicaFilter,
  ReplicaRoleName,
  SenderKindName,
} from '../src/types';

/**
 * Drives library/tests/fixtures/channel_filter.json against
 * `channelFilterMatches`.
 *
 * A channel store may push the filter into its query rather than returning
 * every row. That is an optimization and it is the store's to verify: the core
 * re-applies the filter to whatever a listing returns, which drops rows the
 * filter excludes but cannot recover a row that was never returned. An
 * over-selecting pushdown costs bandwidth; an under-selecting one is
 * undetectable at runtime.
 *
 * TypeScript is where this matters most. A function of fewer parameters
 * satisfies a signature declaring more, so a store written before the filter
 * parameter existed still compiles clean under `--strict` — the type system
 * cannot see the gap, and this table is the check that can.
 *
 * The same table drives the Rust, Go and .NET suites. When two bindings
 * disagree, the fixture says which is wrong.
 */

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

const fixture = JSON.parse(
  readFileSync(
    join(__dirname, '..', '..', '..', 'library', 'tests', 'fixtures', 'channel_filter.json'),
    'utf8',
  ),
) as { helpers: Section; replicas: Section };

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

describe.each([
  ['helpers', fixture.helpers],
  ['replicas', fixture.replicas],
] as const)('%s filter conformance', (_name, section) => {
  it.each(section.cases.map((c) => [c.name, c] as const))('%s', (_caseName, c) => {
    expect(survivors(section, c)).toEqual(c.expected);
  });
});
