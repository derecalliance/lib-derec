import * as fs from 'node:fs';
import * as path from 'node:path';

import { DEREC_ERROR_CATEGORIES, DEREC_ERROR_CODES } from '../src/errors';
import { MessageKind } from '../src/messages';
import {
  ContactMode,
  FlowKind,
  SenderKind,
  StatusEnum,
  type ChannelStatusName,
  type CorruptionReason,
  type DeRecEvent,
  type IgnoreReason,
  type NotRestoredReason,
  type PendingActionKind,
  type ReplicaRoleName,
  type SecretStore,
  type SenderKindName,
  type StateStore,
  type VerifyFailureReason,
} from '../src/types';

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

// The enums below are type-only unions in this SDK, so each is listed once as
// the keys of a `Record` over the union: a variant missing from the list, or
// one the union does not declare, fails `tsc --noEmit`, and the test then holds
// the list to the fixture.
const NAME_UNIONS: Record<string, Record<string, true>> = {
  ChannelStatus: { Pending: true, Paired: true, Unpairing: true } satisfies Record<ChannelStatusName, true>,
  ReplicaRole: { Source: true, Destination: true } satisfies Record<ReplicaRoleName, true>,
  PendingActionKind: {
    Pairing: true,
    PrePair: true,
    StoreShare: true,
    VerifyShare: true,
    Discovery: true,
    GetShare: true,
    Unpair: true,
    UpdateChannelInfo: true,
    Failed: true,
  } satisfies Record<PendingActionKind, true>,
  IgnoreReason: {
    PendingVerification: true,
    Expired: true,
    TimestampMismatch: true,
    StaleResponse: true,
  } satisfies Record<IgnoreReason, true>,
  NotRestoredReason: { NoTransports: true } satisfies Record<NotRestoredReason, true>,
  VerifyFailureReason: { NoSharedKey: true, NoProof: true, DispatchFailed: true } satisfies Record<
    VerifyFailureReason,
    true
  >,
  CorruptionReason: { Malformed: true, InvalidProof: true, Inconsistent: true } satisfies Record<
    CorruptionReason,
    true
  >,
  DeRecEvent: {
    PairingCompleted: true,
    ReplicaPaired: true,
    ReplicaSecretReceived: true,
    ReplicaSecretInstalled: true,
    ReplicaVersionConflict: true,
    ReplicaSecretRefused: true,
    ReplicaSecretAcked: true,
    ReplicaSyncRejected: true,
    ReplicaSyncFailed: true,
    ReplicaRemoved: true,
    ReplicaSourceChanged: true,
    SelfRemovedFromGroup: true,
    ReplicaDiscoveryComplete: true,
    ReplicaSyncComplete: true,
    ShareStored: true,
    ShareRefused: true,
    ShareConfirmed: true,
    ShareRejected: true,
    SharingComplete: true,
    ShareVerified: true,
    ShareVerifyInvalid: true,
    ShareVerifyRejected: true,
    SecretsDiscovered: true,
    RecoveryShareReceived: true,
    RecoveryShareError: true,
    RecoveryShareRefused: true,
    RecoveryShareCorrupted: true,
    SecretRecovered: true,
    Unpaired: true,
    UnpairRejected: true,
    PrePairRejected: true,
    ChannelInfoUpdated: true,
    ChannelInfoUpdateRejected: true,
    ActionRequired: true,
    AutoAccepted: true,
    RequestFailed: true,
    ErrorResponseReceived: true,
    PairingRefused: true,
    NoOp: true,
    MessageIgnored: true,
    PeerNotRestored: true,
    PairingStarted: true,
    DiscoveryStarted: true,
    DiscoveryFailed: true,
    ProtectSecretStarted: true,
    ProtectSecretFailed: true,
    VerifySharesStarted: true,
    VerifySharesFailed: true,
    RecoverSecretStarted: true,
    RecoverSecretFailed: true,
    UnpairFailed: true,
    UnpairStarted: true,
    UpdateChannelInfoStarted: true,
    UpdateChannelInfoFailed: true,
  } satisfies Record<DeRecEvent['type'], true>,
};

// `SecretKind` and `StateKind` reach this SDK only as the numeric `kind`
// argument of the store callbacks, typed as a literal union of the values.
const NUMBER_UNIONS: Record<string, Record<number, true>> = {
  SecretKind: { 0: true, 1: true, 2: true } satisfies Record<Parameters<SecretStore['load']>[2], true>,
  StateKind: { 0: true, 1: true, 2: true, 3: true, 4: true } satisfies Record<
    Parameters<StateStore['loadAll']>[1],
    true
  >,
};

describe('enum parity with the shared fixture', () => {
  it.each(Object.keys(NAME_UNIONS))('%s declares exactly the fixture names', (name) => {
    const variants = fixture.enums[name].variants;
    expect(variants.every((v) => v.wire === v.name)).toBe(true);
    expect(Object.keys(NAME_UNIONS[name]).sort()).toEqual(variants.map((v) => v.wire as string).sort());
  });

  it.each(Object.keys(NUMBER_UNIONS))('%s declares exactly the fixture values', (name) => {
    expect(Object.keys(NUMBER_UNIONS[name]).map(Number).sort()).toEqual(
      fixture.enums[name].variants.map((v) => v.wire as number).sort(),
    );
  });

  it('SenderKindName covers exactly the SenderKind names', () => {
    const names = { Owner: true, Helper: true, ReplicaSource: true, ReplicaDestination: true } satisfies Record<
      SenderKindName,
      true
    >;
    expect(Object.keys(names).sort()).toEqual(fixture.enums.SenderKind.variants.map((v) => v.name).sort());
  });

  // Every enum the fixture lists is checked by one of the tests in this file.
  it('covers every fixture enum', () => {
    const covered = [
      ...Object.keys(NAME_UNIONS),
      ...Object.keys(NUMBER_UNIONS),
      'SenderKind',
      'ContactMode',
      'FlowKind',
      'StatusEnum',
      'MessageKind',
      'DeRecErrorCategory',
      'DeRecErrorCode',
    ];
    expect(covered.sort()).toEqual(Object.keys(fixture.enums).sort());
  });

  it('SenderKind matches', () => expectMatches('SenderKind', SenderKind as never));
  it('ContactMode matches', () => expectMatches('ContactMode', ContactMode as never));
  it('FlowKind matches', () => expectMatches('FlowKind', FlowKind as never));
  it('StatusEnum matches', () => expectMatches('StatusEnum', StatusEnum as never));

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

  // Error categories and codes reach this SDK already named: the C++ layer
  // turns each number into its name (`errorName` in `cpp/Convert.cpp`), and
  // `cpp/tests/ConvertTest.cpp` holds every fixture number to its name there.
  //
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

  // The C ABI emits exactly `library/src/interop/error_codes.rs`'s `Code`
  // table, the same table the fixture mirrors — unlike the WASM bindings,
  // this SDK has no marshalling-level codes of its own, so no extra entries
  // belong here.
  it('DeRecErrorCode covers exactly the codes the C ABI can emit', () => {
    const expected = fixture.enums.DeRecErrorCode.variants.map((v) => v.text);
    expect(expected.every((text) => typeof text === 'string')).toBe(true);
    expect([...DEREC_ERROR_CODES].sort()).toEqual([...(expected as string[])].sort());
  });
});
