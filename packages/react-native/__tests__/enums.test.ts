import * as fs from 'node:fs';
import * as path from 'node:path';

import { DEREC_ERROR_CATEGORIES } from '../src/errors';
import { MessageKind } from '../src/messages';
import { ContactMode, FlowKind, SenderKind } from '../src/types';

const fixture = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '../../../library/tests/fixtures/enums.json'),
    'utf8',
  ),
) as {
  enums: Record<
    string,
    { variants: Array<{ name: string; wire: number | string; text?: string }> }
  >;
};

function expectMatches(
  name: string,
  actual: Record<string, unknown>,
): void {
  const variants = fixture.enums[name].variants;
  for (const variant of variants) {
    expect(actual[variant.name]).toBe(variant.wire);
  }
}

describe('enum parity with the shared fixture', () => {
  it('SenderKind matches', () => expectMatches('SenderKind', SenderKind as never));
  it('ContactMode matches', () => expectMatches('ContactMode', ContactMode as never));
  it('FlowKind matches', () => expectMatches('FlowKind', FlowKind as never));

  // `MessageKind` selects which message the JSON codec decodes. A shim value
  // that drifted from the Rust discriminant would decode a message as the
  // wrong type rather than fail, so exact set equality is checked in both
  // directions — not just that every fixture entry is present.
  it('MessageKind matches', () => {
    expectMatches('MessageKind', MessageKind as never);
    const declared = Object.keys(MessageKind).filter((k) => Number.isNaN(Number(k)));
    expect(declared.sort()).toEqual(
      fixture.enums.MessageKind.variants.map((v) => v.name).sort(),
    );
  });

  // `DeRecErrorCategory` is a string union, so the runtime array it is
  // derived from is what can be checked. Exact set equality in both
  // directions: a category Rust can emit but the union omits would make a
  // real error untypeable, and a category the union carries but Rust cannot
  // emit (as `"wasm"` was, inherited from the nodejs SDK) is dead surface
  // that invites callers to handle a case that never arrives.
  it('DeRecErrorCategory covers exactly the categories Rust can emit', () => {
    const expected = fixture.enums.DeRecErrorCategory.variants.map((v) => v.text);
    expect(expected.every((text) => typeof text === 'string')).toBe(true);
    expect([...DEREC_ERROR_CATEGORIES].sort()).toEqual(
      [...(expected as string[])].sort(),
    );
  });
});
